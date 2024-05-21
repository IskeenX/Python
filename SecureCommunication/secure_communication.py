from diffie_hellman import DiffieHellman
from aes_cipher import AESCipher

def simulate_communication():
    
    # Alice and Bob generate their Diffie-Hellman key pairs
    alice_dh = DiffieHellman()
    bob_dh = DiffieHellman()
    
    # Exchange public keys
    alice_public_key_bytes = alice_dh.get_public_key_bytes()
    bob_public_key_bytes = bob_dh.get_public_key_bytes()
    
    # Load public keys
    alice_public_key = DiffieHellman.load_public_key(alice_public_key_bytes)
    bob_public_key = DiffieHellman.load_public_key(bob_public_key_bytes)
    
    # Print public keys to verify they are correctly loaded
    print("Alice's public key:", alice_public_key_bytes.decode())
    print("Bob's public key:", bob_public_key_bytes.decode())
    
    # Generate shared keys
    alice_shared_key = alice_dh.generate_shared_key(bob_public_key)
    bob_shared_key = bob_dh.generate_shared_key(alice_public_key)
    
    # Ensure both keys are identical
    assert alice_shared_key == bob_shared_key, "Shared keys do not match"
    
    # Encrypt and decrypt a message using the shared key
    message = "Hello, Bob! This is Alice."
    aes_cipher = AESCipher(alice_shared_key)
    
    # Alice encrypts the message
    encrypted_message = aes_cipher.encrypt(message)
    print("Encrypted message:", encrypted_message)
    
    # Bob decrypts the message
    decrypted_message = aes_cipher.decrypt(encrypted_message)
    print("Decrypted message:", decrypted_message)
    
simulate_communication()
