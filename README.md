# Cryptography Tool

A Python GUI application that implements various classical and modern ciphers including Caesar, Affine, Vigenère, Rail Fence, Columnar Transposition, and Salsa20 ciphers.

## Features

### Classical Ciphers
- **Caesar Cipher:** Simple substitution cipher that shifts letters by a fixed number
- **Affine Cipher:** Substitution cipher that uses a mathematical function to encrypt letters
- **Vigenère Cipher:** Method of encrypting alphabetic text using a simple form of polyalphabetic substitution
- **Rail Fence Cipher:** Transposition cipher that arranges text in a zigzag pattern
- **Columnar Transposition:** Cipher that rearranges text using columns ordered by a keyword

### Modern Ciphers
- **Salsa20:** Stream cipher using 256-bit key and 64-bit nonce for secure encryption

## Requirements

- Python 3.x
- tkinter (usually comes with Python installation)
- os module (for secure random number generation)

## Installation

1. Clone this repository
2. No additional requirements needed as all libraries used are part of Python's standard library

## Usage

1. Run the application:
   ```bash
   python main.py
   ```

2. Select a cipher from the dropdown menu
3. Enter the required key(s):
   - **Caesar Cipher:** Enter a shift value (integer)
   - **Affine Cipher:** Enter values for 'a' and 'b' (integers)
   - **Vigenère Cipher:** Enter a keyword (text)
   - **Rail Fence:** Enter number of rails (integer)
   - **Columnar Transposition:** Enter a keyword (text)
   - **Salsa20:** Use the "Generate Random Key/Nonce" button or enter:
     - 32-byte key (hexadecimal)
     - 8-byte nonce (hexadecimal)
4. Enter your text in the input area
5. Click "Encrypt" or "Decrypt" to process the text
6. The result will appear in the output area

## Cipher Details

### Classical Ciphers
- **Caesar Cipher:**
  - Shifts each letter by a fixed number of positions
  - Preserves case and non-alphabetic characters
  - Shift value can be any integer

- **Affine Cipher:**
  - Uses formula E(x) = (ax + b) mod 26
  - 'a' must be coprime with 26
  - Preserves case and non-alphabetic characters

- **Vigenère Cipher:**
  - Uses a keyword for polyalphabetic substitution
  - More secure than Caesar cipher
  - Preserves case and non-alphabetic characters

- **Rail Fence Cipher:**
  - Writes text in zigzag pattern on specified number of rails
  - Geometric transposition cipher
  - Preserves all characters

- **Columnar Transposition:**
  - Uses keyword to determine column order
  - Automatically pads incomplete blocks with underscores
  - Preserves all characters

### Modern Ciphers
- **Salsa20:**
  - Uses 256-bit (32-byte) key for security
  - Requires 64-bit (8-byte) nonce
  - Outputs ciphertext in hexadecimal format
  - Includes secure random key/nonce generation
  - Full support for UTF-8 text encoding

## Security Notes

- Classical ciphers (Caesar, Affine, Vigenère, Rail Fence, Columnar) are for educational purposes only
- Salsa20 provides strong cryptographic security suitable for modern use
- Always use the random key/nonce generator for Salsa20 instead of manual entry when possible
- Keep your keys and nonces secure and never reuse them

## Implementation Details

- All ciphers preserve case sensitivity
- Non-alphabetic characters are preserved in all ciphers
- Error handling for invalid inputs
- Modern GUI with dropdown selection
- Real-time key validation
- Secure random number generation for Salsa20
