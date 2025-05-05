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