"""
Ciphers.py - A collection of cryptographic cipher implementations

This module provides various classical and modern encryption/decryption algorithms
including Caesar, Affine, Vigenere, Rail Fence, Columnar Transposition, RSA, 
Rotato, DES, OTP and Monoalphabetic substitution.
"""

import os
import math
import base64
from typing import Union, Tuple, List, Optional
import pyDes


class ClassicalCiphers:
    """Collection of classical encryption algorithms"""
    
    @staticmethod
    def caesar_encrypt(plaintext: str, shift: int) -> str:
        """
        Encrypt text using Caesar cipher with the specified shift.
        
        Args:
            plaintext: Text to encrypt
            shift: Number of positions to shift each character
            
        Returns:
            The encrypted text
        """
        result = ""
        for char in plaintext:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - start + shift) % 26
                result += chr(start + shifted)
            else:
                result += char
        return result

    @staticmethod
    def caesar_decrypt(ciphertext: str, shift: int) -> str:
        """
        Decrypt text using Caesar cipher with the specified shift.
        
        Args:
            ciphertext: Text to decrypt
            shift: Number of positions used in encryption
            
        Returns:
            The decrypted text
        """
        return ClassicalCiphers.caesar_encrypt(ciphertext, -shift)

    @staticmethod
    def affine_encrypt(plaintext: str, a: int, b: int) -> str:
        """
        Encrypt text using Affine cipher with parameters a and b.
        
        The Affine cipher uses the function (ax + b) mod 26 for encryption.
        
        Args:
            plaintext: Text to encrypt
            a: Multiplicative parameter (must be coprime with 26)
            b: Additive parameter
            
        Returns:
            The encrypted text
            
        Raises:
            ValueError: If a is not coprime with 26
        """
        if math.gcd(a, 26) != 1:
            raise ValueError("Parameter 'a' must be coprime with 26")
            
        result = ""
        for char in plaintext:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                pos = ord(char) - start
                encrypted_pos = (a * pos + b) % 26
                result += chr(start + encrypted_pos)
            else:
                result += char
        return result

    @staticmethod
    def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
        """
        Decrypt text using Affine cipher with parameters a and b.
        
        Args:
            ciphertext: Text to decrypt
            a: Multiplicative parameter used in encryption
            b: Additive parameter used in encryption
            
        Returns:
            The decrypted text
            
        Raises:
            ValueError: If a is not coprime with 26
        """
        # Find modular inverse of a
        a_inv = None
        for x in range(1, 26):
            if (a * x) % 26 == 1:
                a_inv = x
                break
        
        if a_inv is None:
            raise ValueError("Parameter 'a' must be coprime with 26")
        
        result = ""
        for char in ciphertext:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                pos = ord(char) - start
                decrypted_pos = (a_inv * (pos - b)) % 26
                result += chr(start + decrypted_pos)
            else:
                result += char
        return result

    @staticmethod
    def vigenere_encrypt(plaintext: str, key: str) -> str:
        """
        Encrypt text using Vigenere cipher with the specified key.
        
        Args:
            plaintext: Text to encrypt
            key: Encryption key (will be repeated as needed)
            
        Returns:
            The encrypted text
        """
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                key_char = key[key_index % len(key)]
                key_shift = ord(key_char) - ord('A')
                shifted = (ord(char) - start + key_shift) % 26
                result += chr(start + shifted)
                key_index += 1
            else:
                result += char
        return result

    @staticmethod
    def vigenere_decrypt(ciphertext: str, key: str) -> str:
        """
        Decrypt text using Vigenere cipher with the specified key.
        
        Args:
            ciphertext: Text to decrypt
            key: Encryption key used
            
        Returns:
            The decrypted text
        """
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                key_char = key[key_index % len(key)]
                key_shift = ord(key_char) - ord('A')
                shifted = (ord(char) - start - key_shift) % 26
                result += chr(start + shifted)
                key_index += 1
            else:
                result += char
        return result

    @staticmethod
    def railfence_encrypt(plaintext: str, rails: int) -> str:
        """
        Encrypt text using the Rail Fence (zigzag) cipher.
        
        Args:
            plaintext: Text to encrypt
            rails: Number of rails (rows) to use
            
        Returns:
            The encrypted text
        """
        if rails <= 1:
            return plaintext
            
        # Create the rail pattern
        pattern = [[] for _ in range(rails)]
        
        # Fill the pattern
        direction = 1
        row = 0
        
        for char in plaintext:
            pattern[row].append(char)
            row += direction
            
            if row == 0 or row == rails - 1:
                direction *= -1
        
        # Read the pattern row by row
        return "".join("".join(row) for row in pattern)

    @staticmethod
    def railfence_decrypt(ciphertext: str, rails: int) -> str:
        """
        Decrypt text using the Rail Fence (zigzag) cipher.
        
        Args:
            ciphertext: Text to decrypt
            rails: Number of rails used in encryption
            
        Returns:
            The decrypted text
        """
        if rails <= 1:
            return ciphertext
            
        # Create the rail pattern with positions
        pattern = [[] for _ in range(rails)]
        
        # Calculate the positions for each character
        direction = 1
        row = 0
        positions = []
        
        for i in range(len(ciphertext)):
            positions.append(row)
            row += direction
            if row == 0 or row == rails - 1:
                direction *= -1
        
        # Fill the pattern with the correct characters
        text_index = 0
        for row in range(rails):
            for i in range(len(ciphertext)):
                if positions[i] == row:
                    pattern[row].append(ciphertext[text_index])
                    text_index += 1
        
        # Read the pattern in the original order
        result = ""
        direction = 1
        row = 0
        
        for _ in range(len(ciphertext)):
            result += pattern[row].pop(0)
            row += direction
            if row == 0 or row == rails - 1:
                direction *= -1
        
        return result

    @staticmethod
    def columnar_encrypt(plaintext: str, key: str) -> str:
        """
        Encrypt text using Columnar Transposition cipher.
        
        Args:
            plaintext: Text to encrypt
            key: String key that determines column order
            
        Returns:
            The encrypted text
        """
        key_len = len(key)
        text_len = len(plaintext)
        num_rows = math.ceil(text_len / key_len)
        
        # Pad the text if needed
        padded_len = num_rows * key_len
        padded_text = plaintext + '_' * (padded_len - text_len)  # Using '_' as padding
        
        # Create the matrix
        matrix = []
        for i in range(0, padded_len, key_len):
            matrix.append(padded_text[i:i+key_len])
            
        # Determine column order based on key
        key_order = sorted([(key[i], i) for i in range(key_len)])
        
        # Read columns based on key order
        result = ""
        for _, col_index in key_order:
            for row in matrix:
                if col_index < len(row):  # Safety check
                    result += row[col_index]
                    
        return result

    @staticmethod
    def columnar_decrypt(ciphertext: str, key: str) -> str:
        """
        Decrypt text using Columnar Transposition cipher.
        
        Args:
            ciphertext: Text to decrypt
            key: String key used in encryption
            
        Returns:
            The decrypted text
        """
        key_len = len(key)
        text_len = len(ciphertext)
        num_rows = math.ceil(text_len / key_len)
        
        # Determine column order based on key
        key_order = sorted([(key[i], i) for i in range(key_len)])
        sorted_indices = [idx for _, idx in key_order]
        
        # Calculate column lengths
        col_lengths = []
        full_cols = text_len % key_len
        if full_cols == 0:
            full_cols = key_len  # All columns are full
            
        for i in range(key_len):
            col_lengths.append(num_rows if i < full_cols else num_rows - 1)
            
        # Reorder column lengths based on original key index
        ordered_col_lengths = [0] * key_len
        for i in range(key_len):
            ordered_col_lengths[sorted_indices[i]] = col_lengths[i]

        # Create the matrix to reconstruct
        matrix = [[''] * key_len for _ in range(num_rows)]
        
        # Fill the matrix column by column based on key order
        ciphertext_idx = 0
        for _, col_index in key_order:
            col_len = ordered_col_lengths[col_index]
            for row_index in range(col_len):
                if ciphertext_idx < len(ciphertext):
                    matrix[row_index][col_index] = ciphertext[ciphertext_idx]
                    ciphertext_idx += 1
            
        # Read the matrix row by row to get the plaintext
        result = ""
        for row in matrix:
            result += ''.join(row)
            
        # Remove padding
        return result.rstrip('_')

    @staticmethod
    def monoalphabet_encrypt(plaintext: str, key: str) -> str:
        """
        Encrypt text using Monoalphabetic Substitution cipher.
        
        Args:
            plaintext: Text to encrypt
            key: A string of 26 unique letters representing the substitution alphabet
            
        Returns:
            The encrypted text
            
        Raises:
            ValueError: If key is not exactly 26 unique letters
        """
        # Validate key
        if len(key) != 26 or len(set(key.lower())) != 26:
            raise ValueError("Key must be exactly 26 unique letters")
        
        # Create encryption mapping
        key = key.upper()
        mapping = {chr(i + ord('A')): key[i] for i in range(26)}
        
        result = ""
        for char in plaintext:
            if char.isalpha():
                # Preserve case
                is_upper = char.isupper()
                mapped_char = mapping[char.upper()]
                result += mapped_char if is_upper else mapped_char.lower()
            else:
                result += char
        return result

    @staticmethod
    def monoalphabet_decrypt(ciphertext: str, key: str) -> str:
        """
        Decrypt text using Monoalphabetic Substitution cipher.
        
        Args:
            ciphertext: Text to decrypt
            key: The same substitution alphabet used for encryption
            
        Returns:
            The decrypted text
            
        Raises:
            ValueError: If key is not exactly 26 unique letters
        """
        # Validate key
        if len(key) != 26 or len(set(key.lower())) != 26:
            raise ValueError("Key must be exactly 26 unique letters")
        
        # Create decryption mapping
        key = key.upper()
        mapping = {key[i]: chr(i + ord('A')) for i in range(26)}
        
        result = ""
        for char in ciphertext:
            if char.isalpha():
                # Preserve case
                is_upper = char.isupper()
                mapped_char = mapping[char.upper()]
                result += mapped_char if is_upper else mapped_char.lower()
            else:
                result += char
        return result


class ModernCiphers:
    """Collection of modern encryption algorithms"""
    
    @staticmethod
    def generate_rsa_keys(e: Optional[int] = None) -> Tuple[int, int, int]:
        """
        Generate RSA keys using sample prime numbers.
        
        Note: This is for educational purposes only. In production,
        use cryptographically secure libraries with much larger primes.
        
        Args:
            e: Optional public exponent (default: will be computed)
            
        Returns:
            Tuple of (e, d, n) where e is public exponent,
            d is private exponent, and n is the modulus
            
        Raises:
            ValueError: If e is invalid
        """
        p = 7919  # Example prime
        q = 1009  # Example prime

        n = p * q
        phi = (p - 1) * (q - 1)

        # Find or validate public exponent e
        if e is None:
            # Find a suitable e (coprime with phi)
            for e_val in range(3, phi, 2):  # Start with odd numbers for efficiency
                if math.gcd(e_val, phi) == 1:
                    e = e_val
                    break
        else:
            # Verify provided e
            if e <= 1 or e >= phi:
                raise ValueError("e must be greater than 1 and less than phi(n)")
            if math.gcd(e, phi) != 1:
                raise ValueError("e must be coprime with phi(n)")

        # Compute private exponent d
        d = ModernCiphers._mod_inverse(e, phi)
        if d == -1:
            raise ValueError("Could not find modular inverse for the given e")

        return e, d, n

    @staticmethod
    def rsa_encrypt(plaintext: str, e: int, n: int) -> str:
        """
        Encrypt text using RSA algorithm.
        
        Args:
            plaintext: Text to encrypt
            e: Public exponent
            n: Modulus
            
        Returns:
            Space-separated string of encrypted numbers
            
        Raises:
            ValueError: If text contains characters too large for the modulus
        """
        # Convert text to numbers (using ASCII values)
        numbers = [ord(char) for char in plaintext]
        
        # Check if any number is too large for the modulus
        if max(numbers) >= n:
            raise ValueError(
                f"Text contains characters too large for modulus (n={n}). "
                "Use larger prime numbers."
            )
        
        # Encrypt each number
        encrypted = [pow(num, e, n) for num in numbers]
        
        # Convert to string representation
        return ' '.join(map(str, encrypted))

    @staticmethod
    def rsa_decrypt(ciphertext: str, d: int, n: int) -> str:
        """
        Decrypt text using RSA algorithm.
        
        Args:
            ciphertext: Space-separated string of encrypted numbers
            d: Private exponent
            n: Modulus
            
        Returns:
            The decrypted text
            
        Raises:
            ValueError: If ciphertext format is invalid
        """
        try:
            # Split the ciphertext into numbers
            numbers = [int(num) for num in ciphertext.split()]
            
            # Decrypt each number
            decrypted = [pow(num, d, n) for num in numbers]
            
            # Convert back to text
            return ''.join(chr(num) for num in decrypted)
        except ValueError:
            raise ValueError("Invalid ciphertext format: must be space-separated integers")

    @staticmethod
    def rotato_encrypt(plaintext: str, key: Union[int, str]) -> str:
        """
        Encrypt text using rotato cipher:
        1. Convert to base64
        2. Convert to hex
        3. Right rotate by key amount 4 times
        
        Args:
            plaintext: Text to encrypt
            key: Rotation amount (will be converted to int)
            
        Returns:
            The encrypted text
        """
        try:
            # Convert key to int if it's a string
            key = int(key)
            
            # Convert to base64
            base64_bytes = base64.b64encode(plaintext.encode())
            base64_str = base64_bytes.decode()
            
            # Convert to hex
            hex_str = base64_str.encode().hex()
            
            # Perform right rotation 4 times
            rotated = hex_str
            for _ in range(4):
                # Right rotate by key amount
                k = key % len(rotated)  # Ensure key is within valid range
                rotated = rotated[-k:] + rotated[:-k]
            
            return rotated
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

    @staticmethod
    def rotato_decrypt(ciphertext: str, key: Union[int, str]) -> str:
        """
        Decrypt text using rotato cipher:
        1. Left rotate by key amount 4 times
        2. Convert from hex
        3. Convert from base64
        
        Args:
            ciphertext: Text to decrypt
            key: Rotation amount (will be converted to int)
            
        Returns:
            The decrypted text
        """
        try:
            # Convert key to int if it's a string
            key = int(key)
            
            # Perform left rotation 4 times
            rotated = ciphertext
            for _ in range(4):
                # Left rotate by key amount
                k = key % len(rotated)  # Ensure key is within valid range
                rotated = rotated[k:] + rotated[:k]
            
            # Convert from hex
            hex_bytes = bytes.fromhex(rotated)
            base64_str = hex_bytes.decode()
            
            # Convert from base64
            text_bytes = base64.b64decode(base64_str)
            return text_bytes.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    @staticmethod
    def des_encrypt(plaintext: Union[str, bytes], key: Union[str, bytes]) -> bytes:
        """
        Encrypt text or bytes using DES cipher.
        
        Args:
            plaintext: Text or bytes to encrypt
            key: Encryption key (must be 8 bytes)
            
        Returns:
            The encrypted bytes
        """
        # Convert string inputs to bytes if needed
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        if isinstance(key, str):
            key = key.encode()
            
        # Ensure key is exactly 8 bytes
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes long")
        
        # Create DES object
        des_obj = pyDes.des(
            key, 
            pyDes.CBC, 
            b"\0\0\0\0\0\0\0\0",  # IV (initialization vector)
            pad=None, 
            padmode=pyDes.PAD_PKCS5
        )
        
        # Encrypt the data
        return des_obj.encrypt(plaintext)

    @staticmethod
    def des_decrypt(ciphertext: bytes, key: Union[str, bytes]) -> bytes:
        """
        Decrypt bytes using DES cipher.
        
        Args:
            ciphertext: Bytes to decrypt
            key: Encryption key used (must be 8 bytes)
            
        Returns:
            The decrypted bytes
        """
        # Convert string key to bytes if needed
        if isinstance(key, str):
            key = key.encode()
            
        # Ensure key is exactly 8 bytes
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes long")
        
        # Create DES object
        des_obj = pyDes.des(
            key, 
            pyDes.CBC, 
            b"\0\0\0\0\0\0\0\0",  # IV (initialization vector)
            pad=None, 
            padmode=pyDes.PAD_PKCS5
        )
        
        # Decrypt the data
        return des_obj.decrypt(ciphertext)

    @staticmethod
    def otp_encrypt(plaintext: Union[str, bytes], key: Union[str, bytes]) -> str:
        """
        Encrypt text using One-Time Pad (OTP) cipher.
        
        Args:
            plaintext: Text or bytes to encrypt
            key: The one-time pad (must be at least as long as plaintext)
            
        Returns:
            The encrypted text as a hexadecimal string
            
        Raises:
            ValueError: If key is shorter than plaintext
        """
        # Convert to bytes if input is string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        if isinstance(key, str):
            key = key.encode()
        
        # Validate key length
        if len(key) < len(plaintext):
            raise ValueError("Key must be at least as long as the plaintext")
        
        # Perform XOR operation between text and key
        encrypted = bytes(a ^ b for a, b in zip(plaintext, key))
        
        # Convert to hexadecimal string
        return encrypted.hex()

    @staticmethod
    def otp_decrypt(ciphertext: str, key: Union[str, bytes]) -> str:
        """
        Decrypt text using One-Time Pad (OTP) cipher.
        
        Args:
            ciphertext: Hexadecimal string to decrypt
            key: The one-time pad used for encryption
            
        Returns:
            The decrypted text
            
        Raises:
            ValueError: If key is shorter than ciphertext or ciphertext is not valid hex
        """
        # Convert ciphertext from hex to bytes
        try:
            encrypted = bytes.fromhex(ciphertext)
        except ValueError:
            raise ValueError("Invalid hexadecimal ciphertext")
        
        # Convert key to bytes if it's a string
        if isinstance(key, str):
            key = key.encode()
        
        # Validate key length
        if len(key) < len(encrypted):
            raise ValueError("Key must be at least as long as the ciphertext")
        
        # Perform XOR operation between ciphertext and key
        decrypted = bytes(a ^ b for a, b in zip(encrypted, key))
        
        # Convert back to string
        return decrypted.decode()

    @staticmethod
    def _mod_inverse(e: int, phi: int) -> int:
        """
        Calculate the modular inverse of e mod phi.
        
        Args:
            e: The value to find inverse for
            phi: The modulus
            
        Returns:
            The modular inverse or -1 if it doesn't exist
        """
        # Extended Euclidean Algorithm
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            else:
                gcd, x, y = extended_gcd(b % a, a)
                return gcd, y - (b // a) * x, x
        
        gcd, x, _ = extended_gcd(e, phi)
        
        if gcd != 1:
            return -1  # Modular inverse doesn't exist
        else:
            return x % phi


# For backwards compatibility
def caesar_encrypt(text, shift):
    return ClassicalCiphers.caesar_encrypt(text, shift)

def caesar_decrypt(text, shift):
    return ClassicalCiphers.caesar_decrypt(text, shift)

def affine_encrypt(text, a, b):
    return ClassicalCiphers.affine_encrypt(text, a, b)

def affine_decrypt(text, a, b):
    return ClassicalCiphers.affine_decrypt(text, a, b)

def vigenere_encrypt(text, key):
    return ClassicalCiphers.vigenere_encrypt(text, key)

def vigenere_decrypt(text, key):
    return ClassicalCiphers.vigenere_decrypt(text, key)

def railfence_encrypt(text, rails):
    return ClassicalCiphers.railfence_encrypt(text, rails)

def railfence_decrypt(text, rails):
    return ClassicalCiphers.railfence_decrypt(text, rails)

def columnar_transposition_encrypt(text, key):
    return ClassicalCiphers.columnar_encrypt(text, key)

def columnar_transposition_decrypt(text, key):
    return ClassicalCiphers.columnar_decrypt(text, key)

def monoalphabet_encrypt(text, key):
    return ClassicalCiphers.monoalphabet_encrypt(text, key)

def monoalphabet_decrypt(text, key):
    return ClassicalCiphers.monoalphabet_decrypt(text, key)

def generate_rsa_keys(e=None):
    return ModernCiphers.generate_rsa_keys(e)

def rsa_encrypt(text, e, n):
    return ModernCiphers.rsa_encrypt(text, e, n)

def rsa_decrypt(ciphertext, d, n):
    return ModernCiphers.rsa_decrypt(ciphertext, d, n)

def rotato_encrypt(text, key):
    return ModernCiphers.rotato_encrypt(text, key)

def rotato_decrypt(ciphertext, key):
    return ModernCiphers.rotato_decrypt(ciphertext, key)

def des_encrypt(text, key):
    return ModernCiphers.des_encrypt(text, key)

def des_decrypt(encrypted_data, key):
    return ModernCiphers.des_decrypt(encrypted_data, key)

def otp_encrypt(text, key):
    return ModernCiphers.otp_encrypt(text, key)

def otp_decrypt(ciphertext, key):
    return ModernCiphers.otp_decrypt(ciphertext, key)