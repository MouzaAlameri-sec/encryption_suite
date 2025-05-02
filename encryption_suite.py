__Author__="Mouza Alameri"
__Date__="02/05/2025"
__Github__= "https://github.com/MouzaAlameri-sec"


import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def printmsg(): 
    print("Welcome to the encryption suit \n")
    print("This will take your password and form a key and it will encrypt your message \n")
    print("make sure you enter short passwords and messages for efficiency")

def display(label, output):
    if isinstance(output, bytes):
        print(f"{label}: {output.hex()}")
    else:
        print(f"{label}: {output}")

def encrypt_key(passw):
    salt = os.urandom(32)
    strecher = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return strecher.derive(passw.encode()), salt

def cha_encrypt(data, key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    return nonce + cipher.encryptor().update(data.encode())

def rsa_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private, private.public_key()

def rsa_encrypt(data, public_key):
    return public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def sha256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode())
    return digest.finalize()

def main():
    printmsg()
    msg = input(" Enter a message :  ")
    passw = input("Enter a password:  ")
    
    key, salt = encrypt_key(passw)
    encrypted_msg = cha_encrypt(msg, key)
    
    print("\nResults:")
    display("Salt", salt)
    display("Encryption Key", key)
    display("Encrypted Message", encrypted_msg)

if __name__ == "__main__":
    main()