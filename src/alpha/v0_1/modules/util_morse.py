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

# function used to normalize the text and change special characters
def normalizeText(text):
    return unicodedata.normalize('NFD', text).encode('ascii', 'ignore').decode('ascii')

# function used to encrypt the text
def morseEncode(text):
    morse_code = ' '.join(dictMorse.get(char.upper(), '/') for char in text)
    return morse_code

# function used to decrypt the text
def morseDecode(text):
    dictAscii = {value: key for key, value in dictMorse.items()}
    text = str(text).split(" ")
    text = ''.join(dictAscii.get(string, '#') for string in text)
    return text.lower()

# function used to export the file to the current directory and it is only used in menu() 
def exportFile(text, type):
    currentDir = os.getcwd()
    currentDate = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if type == 0:
        filePath = os.path.join(currentDir, f'encrypted-morse_{currentDate}.txt')
    else:
        filePath = os.path.join(currentDir, f'decrypted-morse_{currentDate}.txt')
    with open(filePath, "w") as file:
        file.write(text)
    print(f"\nFile saved at: {filePath}")

# terminal() is used if the user is coming from a linux terminal
def terminal():
    parser = argparse.ArgumentParser(description="Morse Code Encryption", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-s", "--sourcefile", nargs="?", const="", help="Source file that contains the text.\n""Usage: purplest-morse -d -s encrypted.txt")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", nargs="?", const="", help="Text to encrypt.\n""Usage: purplest-morse -e \"string\"")
    group.add_argument("-d", "--decrypt", nargs="?", const="", help="Text to decrypt.\n""Usage: purplest-morse -d \"string\"")
    parser.add_argument("-x", "--export", help="Path to export the output.\n""Usage: purplest -e \"string\" -x /path/output.txt")

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

# main() is used to verify if the user is executing the program as a linux terminal command or if it is being called from the main menu
def main():
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

# menu() is used if the user is coming from the main menu 
def menu():
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

# Calls the main function when executed from the main menu (main.py)
if __name__ == "__main__":
    main()