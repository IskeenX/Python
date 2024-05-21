import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

class DiffieHellman:
    _parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    # Generates private and public keys for Diffie-Hellman key exchange
    def __init__(self):
        self.private_key = DiffieHellman._parameters.generate_private_key()
        self.public_key = self.private_key.public_key()

    # Generates a shared secret key using Diffie-Hellman key exchange
    def generate_shared_key(self, peer_public_key):
        shared_key = self.private_key.exchange(peer_public_key)
        
        # The derived shared secret key
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(shared_key)
        return derived_key

    # Gets the public key bytes of the current instance
    def get_public_key_bytes(self):
        # The public key bytes in PEM format
        return self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Loads a public key from its bytes representation
    @staticmethod
    def load_public_key(public_key_bytes):
        return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
    