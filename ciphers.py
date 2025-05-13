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


class Ciphers:
    """Collection of encryption algorithms"""
    
    @staticmethod
    def caesar(text: str, shift: int, encrypt: bool = True) -> str:
        """Caesar cipher encryption/decryption"""
        result = ""
        for char in text:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                shifted = (ord(char) - start + (shift if encrypt else -shift)) % 26
                result += chr(start + shifted)
            else:
                result += char
        return result

    @staticmethod
    def affine(text: str, a: int, b: int, encrypt: bool = True) -> str:
        """Affine cipher encryption/decryption"""
        if math.gcd(a, 26) != 1:
            raise ValueError("Parameter 'a' must be coprime with 26")
            
        if not encrypt:
            # Find modular inverse of a for decryption
            a_inv = next((x for x in range(1, 26) if (a * x) % 26 == 1), None)
            if a_inv is None:
                raise ValueError("Parameter 'a' must be coprime with 26")
            a, b = a_inv, (-a_inv * b) % 26
            
        result = ""
        for char in text:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                pos = ord(char) - start
                new_pos = (a * pos + b) % 26
                result += chr(start + new_pos)
            else:
                result += char
        return result

    @staticmethod
    def vigenere(text: str, key: str, encrypt: bool = True) -> str:
        """Vigenere cipher encryption/decryption"""
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                key_char = key[key_index % len(key)]
                key_shift = ord(key_char) - ord('A')
                shifted = (ord(char) - start + (key_shift if encrypt else -key_shift)) % 26
                result += chr(start + shifted)
                key_index += 1
            else:
                result += char
        return result

    @staticmethod
    def railfence(text: str, rails: int, encrypt: bool = True) -> str:
        """Rail Fence cipher encryption/decryption"""
        if rails <= 1:
            return text
            
        if encrypt:
            # Create the rail pattern
            pattern = [[] for _ in range(rails)]
            direction = 1
            row = 0
            
            for char in text:
                pattern[row].append(char)
                row += direction
                if row == 0 or row == rails - 1:
                    direction *= -1
                    
            return "".join("".join(row) for row in pattern)
        else:
            # Decryption
            pattern = [[] for _ in range(rails)]
            positions = []
            direction = 1
            row = 0
            
            for _ in range(len(text)):
                positions.append(row)
                row += direction
                if row == 0 or row == rails - 1:
                    direction *= -1
                    
            # Fill the pattern
            text_index = 0
            for row in range(rails):
                for i in range(len(text)):
                    if positions[i] == row:
                        pattern[row].append(text[text_index])
                        text_index += 1
                        
            # Read the pattern
            result = ""
            direction = 1
            row = 0
            for _ in range(len(text)):
                result += pattern[row].pop(0)
                row += direction
                if row == 0 or row == rails - 1:
                    direction *= -1
            return result

    @staticmethod
    def columnar(text: str, key: str, encrypt: bool = True) -> str:
        """Columnar Transposition cipher encryption/decryption"""
        key_len = len(key)
        text_len = len(text)
        
        if encrypt:
            # Encryption
            num_rows = math.ceil(text_len / key_len)
            padded_text = text + '_' * (num_rows * key_len - text_len)
            matrix = [padded_text[i:i+key_len] for i in range(0, len(padded_text), key_len)]
            
            # Sort columns based on key
            key_order = sorted([(key[i], i) for i in range(key_len)])
            result = ""
            for _, col_index in key_order:
                for row in matrix:
                    if col_index < len(row):
                        result += row[col_index]
            return result
        else:
            # Decryption
            num_rows = math.ceil(text_len / key_len)
            key_order = sorted([(key[i], i) for i in range(key_len)])
            sorted_indices = [idx for _, idx in key_order]
            
            # Calculate column lengths
            full_cols = text_len % key_len
            if full_cols == 0:
                full_cols = key_len
            col_lengths = [num_rows if i < full_cols else num_rows - 1 for i in range(key_len)]
            
            # Create and fill matrix
            matrix = [[''] * key_len for _ in range(num_rows)]
            text_index = 0
            for _, col_index in key_order:
                col_len = col_lengths[sorted_indices.index(col_index)]
                for row in range(col_len):
                    if text_index < len(text):
                        matrix[row][col_index] = text[text_index]
                        text_index += 1
                        
            # Read matrix row by row
            result = "".join("".join(row) for row in matrix)
            return result.rstrip('_')

    @staticmethod
    def monoalphabet(text: str, key: str, encrypt: bool = True) -> str:
        """Monoalphabetic Substitution cipher encryption/decryption"""
        if len(key) != 26 or len(set(key.lower())) != 26:
            raise ValueError("Key must be exactly 26 unique letters")
            
        key = key.upper()
        if encrypt:
            mapping = {chr(i + ord('A')): key[i] for i in range(26)}
        else:
            mapping = {key[i]: chr(i + ord('A')) for i in range(26)}
            
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                mapped_char = mapping[char.upper()]
                result += mapped_char if is_upper else mapped_char.lower()
            else:
                result += char
        return result

    @staticmethod
    def rsa(text: str, key: Tuple[int, int], encrypt: bool = True) -> str:
        """RSA encryption/decryption"""
        e_or_d, n = key
        try:
            if encrypt:
                # Convert text to numbers and encrypt
                numbers = [ord(char) for char in text]
                if max(numbers) >= n:
                    raise ValueError(f"Text contains characters too large for modulus (n={n})")
                encrypted = [pow(num, e_or_d, n) for num in numbers]
                return ' '.join(map(str, encrypted))
            else:
                # Decrypt numbers back to text
                numbers = [int(num) for num in text.split()]
                decrypted = [pow(num, e_or_d, n) for num in numbers]
                return ''.join(chr(num) for num in decrypted)
        except ValueError as e:
            raise ValueError(f"RSA operation failed: {str(e)}")

    @staticmethod
    def rotato(text: str, key: Union[int, str], encrypt: bool = True) -> str:
        """Rotato cipher encryption/decryption"""
        try:
            key = int(key)
            if encrypt:
                # Encrypt: text -> base64 -> hex -> rotate
                base64_str = base64.b64encode(text.encode()).decode()
                hex_str = base64_str.encode().hex()
                rotated = hex_str
                for _ in range(4):
                    k = key % len(rotated)
                    rotated = rotated[-k:] + rotated[:-k]
                return rotated
            else:
                # Decrypt: rotate -> hex -> base64 -> text
                rotated = text
                for _ in range(4):
                    k = key % len(rotated)
                    rotated = rotated[k:] + rotated[:k]
                hex_bytes = bytes.fromhex(rotated)
                base64_str = hex_bytes.decode()
                return base64.b64decode(base64_str).decode()
        except Exception as e:
            raise ValueError(f"Rotato operation failed: {str(e)}")

    @staticmethod
    def des(data: Union[str, bytes], key: Union[str, bytes], encrypt: bool = True) -> bytes:
        """DES encryption/decryption"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
            
        if len(key) != 8:
            raise ValueError("DES key must be exactly 8 bytes long")
            
        des_obj = pyDes.des(
            key, 
            pyDes.CBC, 
            b"\0\0\0\0\0\0\0\0",
            pad=None, 
            padmode=pyDes.PAD_PKCS5
        )
        
        return des_obj.encrypt(data) if encrypt else des_obj.decrypt(data)

    @staticmethod
    def otp(data: Union[str, bytes], key: Union[str, bytes], encrypt: bool = True) -> Union[str, bytes]:
        """One-Time Pad encryption/decryption"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
            
        if len(key) < len(data):
            raise ValueError("Key must be at least as long as the data")
            
        result = bytes(a ^ b for a, b in zip(data, key))
        return result.hex() if encrypt else result.decode()

    @staticmethod
    def generate_rsa_keys(e: Optional[int] = None) -> Tuple[int, int, int]:
        """Generate RSA keys (e, d, n)"""
        p, q = 7919, 1009  # Example primes
        n = p * q
        phi = (p - 1) * (q - 1)
        
        if e is None:
            e = next((x for x in range(3, phi, 2) if math.gcd(x, phi) == 1), 3)
        elif e <= 1 or e >= phi or math.gcd(e, phi) != 1:
            raise ValueError("Invalid public exponent e")
            
        # Find modular inverse of e
        d = next((x for x in range(2, phi) if (e * x) % phi == 1), None)
        if d is None:
            raise ValueError("Could not find modular inverse for e")
            
        return e, d, n


# For backwards compatibility
def caesar_encrypt(text, shift): return Ciphers.caesar(text, shift, True)
def caesar_decrypt(text, shift): return Ciphers.caesar(text, shift, False)
def affine_encrypt(text, a, b): return Ciphers.affine(text, a, b, True)
def affine_decrypt(text, a, b): return Ciphers.affine(text, a, b, False)
def vigenere_encrypt(text, key): return Ciphers.vigenere(text, key, True)
def vigenere_decrypt(text, key): return Ciphers.vigenere(text, key, False)
def railfence_encrypt(text, rails): return Ciphers.railfence(text, rails, True)
def railfence_decrypt(text, rails): return Ciphers.railfence(text, rails, False)
def columnar_transposition_encrypt(text, key): return Ciphers.columnar(text, key, True)
def columnar_transposition_decrypt(text, key): return Ciphers.columnar(text, key, False)
def monoalphabet_encrypt(text, key): return Ciphers.monoalphabet(text, key, True)
def monoalphabet_decrypt(text, key): return Ciphers.monoalphabet(text, key, False)
def rsa_encrypt(text, e, n): return Ciphers.rsa(text, (e, n), True)
def rsa_decrypt(text, d, n): return Ciphers.rsa(text, (d, n), False)
def rotato_encrypt(text, key): return Ciphers.rotato(text, key, True)
def rotato_decrypt(text, key): return Ciphers.rotato(text, key, False)
def des_encrypt(text, key): return Ciphers.des(text, key, True)
def des_decrypt(text, key): return Ciphers.des(text, key, False)
def otp_encrypt(text, key): return Ciphers.otp(text, key, True)
def otp_decrypt(text, key): return Ciphers.otp(text, key, False)
def generate_rsa_keys(e=None): return Ciphers.generate_rsa_keys(e)