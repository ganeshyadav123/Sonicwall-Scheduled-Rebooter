import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_aes_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode('utf-8'))

def encrypt_csv_text(csv_text: str, passphrase: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_aes_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, csv_text.encode('utf-8'), None)
    payload = {
        "v": 1,
        "algo": "AES-256-GCM",
        "kdf": "PBKDF2-SHA256",
        "iterations": 100000,
        "salt": salt.hex(),
        "iv": iv.hex(),
        "data": ciphertext.hex()
    }
    return json.dumps(payload)

def decrypt_csv_text(payload_json: str, passphrase: str) -> str:
    payload = json.loads(payload_json)
    salt = bytes.fromhex(payload["salt"])
    iv = bytes.fromhex(payload["iv"])
    ciphertext = bytes.fromhex(payload["data"])
    iterations = payload.get("iterations", 100000)
    
    key = derive_aes_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
    return decrypted_bytes.decode('utf-8')

sample_csv = "Name,IP,Port,Username,Password,Site\nSonicWall-HQ,192.168.1.1,22,admin,MySecretPass,Headquarters"
passphrase = "EnterpriseSecretPass123!"

print("Original CSV:\n", sample_csv)
enc = encrypt_csv_text(sample_csv, passphrase)
print("\nAES-256-GCM Encrypted JSON Payload:\n", enc)

dec = decrypt_csv_text(enc, passphrase)
print("\nDecrypted CSV:\n", dec)

assert sample_csv == dec, "Mismatch error!"
print("\n✅ Python PyCA Cryptography AES-256-GCM TEST PASSED 100%")
