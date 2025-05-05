# Cryptography Tool

A Python GUI application that implements various classical ciphers including Caesar, Affine, and Vigenère ciphers.

## Features

- Caesar Cipher: Simple substitution cipher that shifts letters by a fixed number
- Affine Cipher: Substitution cipher that uses a mathematical function to encrypt letters
- Vigenère Cipher: Method of encrypting alphabetic text using a simple form of polyalphabetic substitution

## Requirements

- Python 3.x
- tkinter (usually comes with Python installation)

## Installation

1. Clone this repository
2. Install the requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. Select a cipher from the dropdown menu
3. Enter the required key(s):
   - For Caesar Cipher: Enter a shift value (integer)
   - For Affine Cipher: Enter values for 'a' and 'b' (integers)
   - For Vigenère Cipher: Enter a keyword (text)
4. Enter your text in the input area
5. Click "Encrypt" or "Decrypt" to process the text
6. The result will appear in the output area

## Notes

- For the Affine Cipher, 'a' must be coprime with 26
- The application preserves case and non-alphabetic characters
- All ciphers work with both uppercase and lowercase letters 