from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket as skt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

"""
key = RSA.generate(2048)
# Save the private key for the client
with open("client_private.pem", "wb") as private_file:
    private_file.write(key.export_key())

# Save the public key for the server
with open("server_public.pem", "wb") as public_file:
    public_file.write(key.publickey().export_key())
"""


class BlkSocket:
    def __init__(self, socket: skt.socket, max_len=8):
        self._socket = socket
        self._max_len = max_len

    def b_recv(self) -> bytes:
        size = self._socket.recv(self._max_len)
        while len(size) != self._max_len:
            size += self._socket.recv(self._max_len - len(size))

        size = int.from_bytes(size)
        data = bytes()
        while len(data) < size:
            data += self._socket.recv(size - len(data))

        return data

    def b_sendall(self, data: bytes):
        self._socket.sendall(len(data).to_bytes(self._max_len) + data)

    def get_sock(self):
        return self._socket

    _socket: skt.socket
    _max_len: int


class PEMsocket:
    def __init__(
        self,
        socket: BlkSocket,
    ):
        if socket is not BlkSocket:
            self._socket = BlkSocket(socket)
        else:
            self._socket = socket

            self._priv = None
            self._pub = None

    def set_pub_key(self, public_key_file: str):
        with open(public_key_file, "rb") as key_file:
            self._pub = key_file.read()

    def set_priv_key(self, private_key_file: str):
        with open(private_key_file, "rb") as key_file:
            self._priv = key_file.read()

    def s_recv(self) -> bytes:
        return self.decrypt(self._socket.b_recv())

    def s_sendall(self, message: bytes):
        self._socket.b_sendall(self.encrypt(message))

    def encrypt(self, message):
        server_public_key = RSA.import_key(self._pub)
        cipher = PKCS1_OAEP.new(server_public_key)
        return cipher.encrypt(message)

    # Decrypts the message using the private key of the client
    def decrypt(self, encrypted_message):
        client_private_key = RSA.import_key(self._priv)
        cipher = PKCS1_OAEP.new(client_private_key)
        return cipher.decrypt(encrypted_message)

    def get_sock(self) -> BlkSocket:
        return self._socket

    _socket: BlkSocket
    _pub: str
    _priv: str


class AESsocket:
    def __init__(self, socket, key=None):
        if socket is not BlkSocket:
            self._socket = BlkSocket(socket)
        else:
            self._socket = socket

        if key is None:
            self._key = get_random_bytes(32)
        else:
            self._key = key
        self._cipher = AES.new(self._key, AES.MODE_ECB)

    def get_key(self) -> bytes:
        return bytes(self._key)

    def s_recv(self) -> bytes:
        return self.decrypt(self._socket.b_recv())

    def s_sendall(self, data: bytes):
        self._socket.b_sendall(self.encrypt(data))

    _socket: BlkSocket
    _key: bytes

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = self._cipher.encrypt(pad(plaintext, 16))
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = unpad(self._cipher.decrypt(ciphertext), 16)
        return plaintext

    def get_sock(self) -> BlkSocket:
        return self._socket
