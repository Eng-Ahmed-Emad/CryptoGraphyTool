import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ===== Caesar Cipher =====

def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypt text using Caesar cipher."""
    return ''.join(
        chr((ord(c) - ord(base) + shift) % 26 + ord(base)) if c.isalpha() else c
        for c in text
        for base in (ord('A') if c.isupper() else ord('a'),)
    )


def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt Caesar cipher."""
    return caesar_encrypt(text, -shift)


# ===== Affine Cipher =====

def modinv(a: int, m: int) -> int:
    """Return modular inverse of a under modulo m."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"No modular inverse for a={a} under mod {m}")


def affine_encrypt(text: str, a: int, b: int) -> str:
    """Encrypt text using Affine cipher."""
    if modinv(a, 26) is None:
        raise ValueError("Key 'a' must be coprime with 26.")
    
    return ''.join(
        chr((a * (ord(c) - ord(base)) + b) % 26 + ord(base)) if c.isalpha() else c
        for c in text
        for base in (ord('A') if c.isupper() else ord('a'),)
    )


def affine_decrypt(text: str, a: int, b: int) -> str:
    """Decrypt Affine cipher."""
    a_inv = modinv(a, 26)
    return ''.join(
        chr((a_inv * (ord(c) - ord(base) - b)) % 26 + ord(base)) if c.isalpha() else c
        for c in text
        for base in (ord('A') if c.isupper() else ord('a'),)
    )


# ===== Vigenère Cipher =====

def vigenere_encrypt(text: str, key: str) -> str:
    """Encrypt text using Vigenère cipher."""
    result, key = "", key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result


def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt Vigenère cipher."""
    result, key = "", key.upper()
    key_index = 0

    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    return result


# ===== Rail Fence Cipher =====

def railfence_encrypt(text: str, rails: int) -> str:
    """Encrypt text using Rail Fence cipher."""
    if rails <= 1:
        return text

    fence = [[] for _ in range(rails)]
    row, step = 0, 1

    for char in text:
        fence[row].append(char)
        row += step
        if row == 0 or row == rails - 1:
            step *= -1

    return ''.join(''.join(r) for r in fence)


def railfence_decrypt(text: str, rails: int) -> str:
    """Decrypt text using Rail Fence cipher."""
    if rails <= 1:
        return text

    # Determine position pattern
    pattern = []
    row, step = 0, 1
    for _ in text:
        pattern.append(row)
        row += step
        if row == 0 or row == rails - 1:
            step *= -1

    # Fill rails with encrypted characters
    rail_lengths = [pattern.count(r) for r in range(rails)]
    rails_filled = []
    i = 0
    for count in rail_lengths:
        rails_filled.append(list(text[i:i+count]))
        i += count

    # Reconstruct original text
    result = ""
    row = 0
    step = 1
    for r in pattern:
        result += rails_filled[r].pop(0)
        row += step
        if row == 0 or row == rails - 1:
            step *= -1

    return result


# ===== RSA =====

def generate_rsa_keys():
    """Generate RSA public/private key pair in PEM format."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()


def rsa_encrypt(text: str, public_key_pem: str) -> str:
    """Encrypt text with RSA public key."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        encrypted = public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        raise ValueError(f"RSA encryption failed: {str(e)}")


def rsa_decrypt(encrypted_text: str, private_key_pem: str) -> str:
    """Decrypt text with RSA private key."""
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_text),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {str(e)}")
