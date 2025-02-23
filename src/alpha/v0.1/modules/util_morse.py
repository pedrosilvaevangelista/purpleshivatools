# Morse Encrypt / Decrypt

import unicodedata
import os
import datetime

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
    print(f"\nEncrypted text: {morse_code}\n")
    return morse_code

def morseDecode(text):
    dictAscii = {value: key for key, value in dictMorse.items()}
    text = str(text).split(" ")
    text = ''.join(dictAscii.get(string, '#') for string in text)
    print(f"\nDecrypted text: {text.lower()}\n")
    return text.lower()

def exportFile(text, type):
    exports_dir = os.path.join(os.path.dirname(__file__), 'exports')
    currentDate = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    if type == 0:
        file_path = os.path.join(exports_dir, f'encrypted-morse{currentDate}.txt')
    else:
        file_path = os.path.join(exports_dir, f'decrypted-morse{currentDate}.txt')
    with open(file_path, "w") as file:
        file.write(text)
    print(f"\nFile saved at: {file_path}")


while True:
    option = input(f"\nDo you want to {GREEN}[E]ncrypt {RESET}or {GREEN}[D]ecrypt?{RESET} ")
    if option.lower() == "e":
         text = input("\nEnter the text to be encrypted: ")
         text = normalizeText(text)
         result = morseEncode(text)
         export = input("Want to export the result to a .txt file? [Y]es: ")
         if export.lower() == "y":
             exportFile(result, 0)
         break
    elif option.lower() == "d":
         text = input("\nEnter the text to be decrypted: ")
         text = normalizeText(text)
         result = morseDecode(text)
         export = input("Want to export the result to a .txt file? [Y]es: ")
         if export.lower() == "y":
             exportFile(result, 1)
         break
    else:
        print("\nInvalid.")