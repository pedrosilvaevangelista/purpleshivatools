#!/usr/bin/env python3
# Morse Encrypt / Decrypt

import unicodedata
import os
import datetime
import argparse
import sys

GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"

dictMorse = {
    'A': '.-',     'B': '-...',   'C': '-.-.',   'D': '-..',    'E': '.',      'F': '..-.',   
    'G': '--.',     'H': '....',   'I': '..',     'J': '.---',   'K': '-.-',    'L': '.-..',   
    'M': '--',      'N': '-.',     'O': '---',    'P': '.--.',   'Q': '--.-',   'R': '.-.',    
    'S': '...',    'T': '-',      'U': '..-',    'V': '...-',  'W': '.--',    'X': '-..-',   
    'Y': '-.--',    'Z': '--..',   

    '1': '.----',   '2': '..---',  '3': '...--',  '4': '....-', '5': '.....', 
    '6': '-....',   '7': '--...',  '8': '---..',  '9': '----.', '0': '-----', 

    '.': '.-.-.-',  ',': '--..--',  '?': '..--..',  "'": '.----.', '!': '-.-.--',  
    '/': '-..-.',   '(': '-.--.',   ')': '-.--.-',  '&': '.-...',  ':': '---...',  
    ';': '-.-.-.',  '=': '-...-',  '+': '.-.-.',   '-': '-....-', '_': '..--.-',  
    '"': '.-..-.',  '$': '...-..-', '@': '.--.-.', " ": "/"  
}
def normalizeText(text):
    return unicodedata.normalize('NFD', text).encode('ascii', 'ignore').decode('ascii')

def morseEncode(text):
    morse_code = ' '.join(dictMorse.get(char.upper(), '/') for char in text)
    return morse_code

def morseDecode(text):
    dictAscii = {value: key for key, value in dictMorse.items()}
    text = str(text).split(" ")
    text = ''.join(dictAscii.get(string, '#') for string in text)
    return text.lower()

def exportFile(text, type):
    current_dir = os.getcwd()
    currentDate = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if type == 0:
        file_path = os.path.join(current_dir, f'encrypted-morse_{currentDate}.txt')
    else:
        file_path = os.path.join(current_dir, f'decrypted-morse_{currentDate}.txt')
    with open(file_path, "w") as file:
        file.write(text)
    print(f"\nFile saved at: {file_path}")

def terminalLogic():
    parser = argparse.ArgumentParser(description="Morse Code Encryption")
    parser.add_argument("-s", "--sourcefile", nargs="?", const="", help="Source file")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", nargs="?", const="", help="Text to encrypt")
    group.add_argument("-d", "--decrypt", nargs="?", const="", help="Text to decrypt")
    parser.add_argument("-x", "--export", help="Path to export the output")

    args = parser.parse_args()

    if args.sourcefile:
        with open(args.sourcefile, "r") as file:
            inputText = file.read()
    else:
        inputText = args.encrypt if args.encrypt is not None else args.decrypt

    if args.encrypt is not None:
        outputText = morseEncode(inputText)
    elif args.decrypt is not None:
        outputText = morseDecode(inputText)
    else:
        parser.error("You must specify either --encrypt or --decrypt.")

    if args.export:
        with open(args.export, "w") as f:
            f.write(outputText)
    else:
        if args.encrypt is not None:
            print(f"Encrypted text: {outputText}")
        else:
            print(f"Decrypted text: {outputText}")

def main():
    if len(sys.argv) > 1:
        terminalLogic()
    else:
        mainMenu()

def mainMenu():
    while True:
        option = input(f"\nDo you want to {GREEN}[E]ncrypt {RESET}or {GREEN}[D]ecrypt?{RESET} ")
        if option.lower() == "e":
            text = input("\nEnter the text to be encrypted: ")
            text = normalizeText(text)
            result = morseEncode(text)
            print(f"Encrypted text: {result}")
            export = input("Want to export the result to a .txt file? [Y]es: ")
            if export.lower() == "y":
                exportFile(result, 0)
            break
        elif option.lower() == "d":
            text = input("\nEnter the text to be decrypted: ")
            text = normalizeText(text)
            result = morseDecode(text)
            print(f"Decrypted text: {result}")
            export = input("Want to export the result to a .txt file? [Y]es: ")
            if export.lower() == "y":
                exportFile(result, 1)
            break
        else:
            print("\nInvalid.")

if __name__ == "__main__":
    main()