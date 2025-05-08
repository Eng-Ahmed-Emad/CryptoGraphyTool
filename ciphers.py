import os
import math
import base64
import pyDes

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - start + shift) % 26
            result += chr(start + shifted)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def affine_encrypt(text, a, b):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            pos = ord(char) - start
            encrypted_pos = (a * pos + b) % 26
            result += chr(start + encrypted_pos)
        else:
            result += char
    return result

def affine_decrypt(text, a, b):
    result = ""
    # Find modular inverse of a
    a_inv = None
    for x in range(1, 26):
        if (a * x) % 26 == 1:
            a_inv = x
            break
    
    if a_inv is None:
        raise ValueError("'a' must be coprime with 26")
    
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            pos = ord(char) - start
            decrypted_pos = (a_inv * (pos - b)) % 26
            result += chr(start + decrypted_pos)
        else:
            result += char
    return result

def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    
    for char in text:
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

def vigenere_decrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    
    for char in text:
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

def railfence_encrypt(text, rails):
    """Encrypt text using the Rail Fence cipher"""
    if rails <= 1:
        return text
        
    # Create the rail pattern
    pattern = []
    for i in range(rails):
        pattern.append([])
    
    # Fill the pattern
    direction = 1
    row = 0
    
    for char in text:
        pattern[row].append(char)
        row += direction
        
        if row == 0 or row == rails - 1:
            direction *= -1
    
    # Read the pattern row by row
    result = ""
    for row in pattern:
        result += "".join(row)
    
    return result

def railfence_decrypt(text, rails):
    """Decrypt text using the Rail Fence cipher"""
    if rails <= 1:
        return text
        
    # Create the rail pattern with positions
    pattern = []
    for i in range(rails):
        pattern.append([])
    
    # Calculate the positions for each character
    direction = 1
    row = 0
    positions = []
    
    for i in range(len(text)):
        positions.append(row)
        row += direction
        if row == 0 or row == rails - 1:
            direction *= -1
    
    # Fill the pattern with the correct characters
    text_index = 0
    for row in range(rails):
        for i in range(len(text)):
            if positions[i] == row:
                pattern[row].append(text[text_index])
                text_index += 1
    
    # Read the pattern in the original order
    result = ""
    direction = 1
    row = 0
    
    for i in range(len(text)):
        if pattern[row]:
            result += pattern[row].pop(0)
        row += direction
        if row == 0 or row == rails - 1:
            direction *= -1
    
    return result

def columnar_transposition_encrypt(text, key):
    """Encrypts text using Columnar Transposition cipher"""
    key_len = len(key)
    text_len = len(text)
    num_rows = math.ceil(text_len / key_len)
    num_cols = key_len
    
    # Pad the text if needed
    padded_len = num_rows * num_cols
    text += '_' * (padded_len - text_len) # Using '_' as padding
    
    # Create the matrix
    matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    k = 0
    for i in range(num_rows):
        for j in range(num_cols):
            matrix[i][j] = text[k]
            k += 1
            
    # Determine column order based on key
    key_order = sorted([(key[i], i) for i in range(key_len)])
    
    # Read columns based on key order
    result = ""
    for _, col_index in key_order:
        for row_index in range(num_rows):
            result += matrix[row_index][col_index]
            
    return result

def columnar_transposition_decrypt(ciphertext, key):
    """Decrypts text using Columnar Transposition cipher"""
    key_len = len(key)
    text_len = len(ciphertext)
    num_rows = math.ceil(text_len / key_len)
    num_cols = key_len
    
    # Determine column order based on key
    key_order = sorted([(key[i], i) for i in range(key_len)])
    
    # Calculate number of full columns and potentially shorter last column
    num_full_cols = text_len % key_len
    if num_full_cols == 0:
        num_full_cols = key_len # All columns are full

    col_lengths = [num_rows] * num_full_cols + [num_rows - 1] * (key_len - num_full_cols)

    # Reorder column lengths based on original key index
    ordered_col_lengths = [0] * key_len
    sorted_indices = [idx for _, idx in key_order]
    for i in range(key_len):
        original_index = sorted_indices[i]
        ordered_col_lengths[original_index] = col_lengths[i]


    # Create the matrix to reconstruct
    matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]
    
    # Fill the matrix column by column based on key order
    ciphertext_idx = 0
    for _, col_index in key_order:
        col_len = ordered_col_lengths[col_index] # Use the reordered lengths
        for row_index in range(col_len):
            matrix[row_index][col_index] = ciphertext[ciphertext_idx]
            ciphertext_idx += 1
            
    # Read the matrix row by row to get the plaintext
    result = ""
    for i in range(num_rows):
        for j in range(num_cols):
            result += matrix[i][j]
            
    # Remove padding (assuming '_' was used) - adjust if needed
    # This simple removal might be incorrect if '_' is part of the original message
    # A more robust method would store the original length or use a non-printable padding char
    # For simplicity, we'll remove trailing underscores for now.
    while result.endswith('_'):
         result = result[:-1]

    return result


def power(base, expo, m):
    return pow(base, expo, m)

def modInverse(e, phi):
    for d in range(2, phi):
        if (e * d) % phi == 1:
            return d
    return -1

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_rsa_keys(e=None):
    """Generate RSA keys using provided public exponent e"""
    p = 7919
    q = 1009

    n = p * q
    phi = (p - 1) * (q - 1)

    # If e is not provided, find a suitable one
    if e is None:
        for e in range(2, phi):
            if gcd(e, phi) == 1:
                break
    else:
        # Verify that the provided e is valid
        if e <= 1 or e >= phi:
            raise ValueError("e must be greater than 1 and less than phi(n)")
        if gcd(e, phi) != 1:
            raise ValueError("e must be coprime with phi(n)")

    # Compute d such that e * d ≡ 1 (mod phi(n))
    d = modInverse(e, phi)
    if d == -1:
        raise ValueError("Could not find modular inverse for the given e")

    return e, d, n

def rsa_encrypt(text, e, n):
    """Encrypt text using RSA"""
    try:
        # Convert text to numbers (using ASCII values)
        numbers = [ord(char) for char in text]
        
        # Check if any number is too large for the modulus
        if max(numbers) >= n:
            raise ValueError(f"Text contains characters that are too large for the current modulus (n={n}). Please use larger prime numbers.")
        
        # Encrypt each number
        encrypted = [power(num, e, n) for num in numbers]
        # Convert to string representation
        return ' '.join(map(str, encrypted))
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def rsa_decrypt(ciphertext, d, n):
    """Decrypt text using RSA"""
    try:
        # Split the ciphertext into numbers
        numbers = [int(num) for num in ciphertext.split()]
        # Decrypt each number
        decrypted = [power(num, d, n) for num in numbers]
        # Convert back to text
        return ''.join(chr(num) for num in decrypted)
    except ValueError as e:
        raise ValueError(f"Invalid ciphertext format: {str(e)}")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def rotato_encrypt(text, key):
    """Encrypt text using rotato cipher:
    1. Convert to base64
    2. Convert to hex
    3. Right rotate by key amount 4 times
    """
    try:
        # Convert to base64
        base64_bytes = base64.b64encode(text.encode())
        base64_str = base64_bytes.decode()
        
        # Convert to hex
        hex_str = base64_str.encode().hex()
        
        # Perform right rotation 4 times
        rotated = hex_str
        key = int(key)
        for _ in range(4):
            # Right rotate by key amount
            k = key % len(rotated)  # Ensure key is within valid range
            rotated = rotated[-k:] + rotated[:-k]
        
        return rotated
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def rotato_decrypt(ciphertext, key):
    """Decrypt text using rotato cipher:
    1. Left rotate by key amount 4 times
    2. Convert from hex
    3. Convert from base64
    """
    try:
        # Perform left rotation 4 times
        rotated = ciphertext
        key = int(key)
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

def des_encrypt(text, key):
    """Encrypt text using DES cipher with custom key"""
    # Make sure the key is properly encoded if it's a string
    if isinstance(key, str):
        key = key.encode()
    
    # Create DES object with parameters as in example
    des_obj = pyDes.des(key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    
    # Encrypt the data
    encrypted = des_obj.encrypt(text)
    
    return encrypted

def des_decrypt(encrypted_data, key):
    """Decrypt text using DES cipher with custom key - always returns result even with wrong key"""
    # Make sure the key is properly encoded if it's a string
    if isinstance(key, str):
        key = key.encode()
    
    # Create DES object with parameters as in example
    des_obj = pyDes.des(key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    
    # Decrypt the data
    decrypted = des_obj.decrypt(encrypted_data)
    
    return decrypted

