import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def encrypt_file(input_file, output_file, password):
    # Generate a 16-byte salt
    salt = os.urandom(16)

    # Derive a key and IV from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    iv = os.urandom(16)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the file
    with open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(iv)
        for chunk in iter(lambda: input_file.read(4096), b''):
            f_out.write(encryptor.update(chunk))
        f_out.write(encryptor.finalize())


def decrypt_file(input_file, password):
    # Read salt and IV from the file
    with open(input_file, 'rb') as f_in:
        salt = f_in.read(16)
        iv = f_in.read(16)

    # Derive key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = b''
    # Decrypt the file
    with open(input_file, 'rb') as f_in:
        # Skip salt and IV
        f_in.seek(32)
        for chunk in iter(lambda: f_in.read(4096), b''):
            decrypted_data += decryptor.update(chunk)
        decrypted_data += decryptor.finalize()

    return decrypted_data


def encrypt_bytes(input_bytes, password):
    # Generate a 16-byte salt
    salt = os.urandom(16)

    # Derive a key and IV from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    iv = os.urandom(16)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    encrypted_data = salt + iv + encryptor.update(input_bytes) + encryptor.finalize()

    return encrypted_data


def decrypt_bytes(input_bytes, password):
    # Read salt and IV from the input bytes
    salt = input_bytes[:16]
    iv = input_bytes[16:32]
    ciphertext = input_bytes[32:]

    # Derive key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_data
