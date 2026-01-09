import Crypto.Cipher.AES as AES
from Crypto.Util.Padding import pad, unpad

"""
    def _encrypt(self, plaintext: bytes) -> bytes:
        cipher = AES.new(self._key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return tag + nonce + ciphertext

    def _decrypt(self, ciphertext: bytes) -> bytes:
        tag = bytes(ciphertext[0:16])
        nonce = bytes(ciphertext[16:32])
        ciphertext = bytes(ciphertext[32:])
        cipher = AES.new(self._key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        cipher.verify(tag)
        return plaintext

"""


def encrypt(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)

    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return tag + nonce + ciphertext


def decrypt(key: bytes, cypher_mess: bytes) -> bytes:
    tag = bytes(cypher_mess[0:16])
    nonce = bytes(cypher_mess[16:32])
    ciphertext = bytes(cypher_mess[32:])
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)
    return plaintext


data = b"a cow jumps over the moon."

key = b"Sixteen byte keySixteen byte key"

ciphertext = encrypt(key, data)
print()
data2 = decrypt(key, ciphertext)

print(data)
print(ciphertext)
print(data2)
"""

data = b"a cow jumps over the moon."

key = b"Sixteen byte keySixteen byte key"

cipher = AES.new(key, AES.MODE_EAX)

nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data)

print(data)
print(ciphertext)

cypher_mess = tag + nonce + ciphertext

tag, nonce, cyphertext = cypher_mess[0:16], cypher_mess[16:32], cypher_mess[32:]
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
cipher.verify(tag)

print(plaintext)
"""
