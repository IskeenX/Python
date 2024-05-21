import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AESCipher:
    
    # Constructor for AESCipher class
    def __init__(self, key):
        self.key = key # key (bytes)
        
    # Encrypts the plaintext using AES encryption
    def encrypt(self, plaintext):
        iv = os.urandom(16) # Generate a random initialization vector (IV)
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(algorithms.AES.block_size).padder() # Add PKCS7 padding
        
        padded_data = padder.update(plaintext.encode()) + padder.finalize() # Pad the plaintext
        ciphertext = encryptor.update(padded_data) + encryptor.finalize() # Encrypt the padded plaintext
        
        return iv + ciphertext
    
    # Decrypts the ciphertext using AES decryption
    def decrypt(self, ciphertext):
        iv = ciphertext[:16] # Extract the initialization vector from the ciphertext
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize() # Decrypt the ciphertext
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder() # Remove PKCS7 padding
        plaintext = unpadder.update(padded_data) + unpadder.finalize() # Unpad the decrypted data
        
        return plaintext.decode() # Convert decrypted bytes to string
    