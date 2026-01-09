import socket as skt
import datetime as dt
import os
import json as js

"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class BlkSocket:
    def __init__(self, socket: skt.socket, max_len=8):
        self._socket
        self._max_len = max_len

    def b_recv(self) -> bytes:
        size = self._socket.recv(max_len)
        while len(size) != max_len:
            size += self._socket.recv(max_len - len(size))

        size = int.from_bytes(size)
        data = bytes()
        while len(data) < size:
            data += self._socket.recv(size - len(data))

        return data

    def b_sendall(self, data: bytes):
        self._socket.sendall(len(data).to_bytes(max_len) + data)

    self._socket: skt.socket


class PEMsocket:
    def __init__(self, pub: str, priv: str, socket: BlkSocket):
        if socket is not BlkSocket:
            self._socket = BlkSocket(socket)
        else:
            self._socket = socket

        self._pub = pub
        self._priv = priv

    def s_recv(self) -> bytes:
        return


class AESsocket:
    def __init__(self, socket, key=None):
        if key is None:
            self._key = get_random_bytes(32)
        else:
            self._key = key
        self._cipher = AES.new(self._key, AES.MODE_ECB)
        self._socket = socket

    def get_key(self) -> bytes:
        return bytes(self._key)

    def s_recv(self) -> bytes:
        size = self._socket.recv(8)
        while len(size) != 8:
            size += self._socket.recv(8 - len(size))

        size = int.from_bytes(size)
        ciphertext = bytes()
        while len(ciphertext) < size:
            ciphertext += self._socket.recv(size - len(ciphertext))

        return self._decrypt(ciphertext)

    def s_sendall(self, data: bytes):
        ciphertext = self._encrypt(data)
        self._socket.sendall(len(ciphertext).to_bytes(8) + ciphertext)

    _socket: skt.socket
    _key: bytes

    def _encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = self._cipher.encrypt(pad(plaintext, 16))
        return ciphertext

    def _decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = unpad(self._cipher.decrypt(ciphertext), 16)
        return plaintext
"""


class Email:
    def __init__(self, sender: str):
        self._sender = sender
        self._recievers = None
        self._title = None
        self._content = None
        self._timestamp = None

    def clear(self):
        clear(self._recievers)
        clear(self._title)
        clear(self._timestamp)
        clear(self._content)

    def add_recievers(self, recievers: str):
        self._recievers = recievers.strip()

    def add_title(self, title: str):
        if len(title) > 100:
            raise RuntimeError("title can't be more than 100 characters.")
        self._title = title.strip()

    def add_content(self, content: str):
        content = content.strip()
        if len(content) > 100000:
            raise RuntimeError("content length too long (max 1000000.")
        self._content = content

    def __str__(self):
        pass

    def timestamp(self, date):
        self._timestamp = dt.datetime.now()

    def create_message(self) -> str:
        if self._recievers is None:
            raise RuntimeError("missing recieved field")
        if self._title is None:
            raise RuntimeError("missing title field")
        if self._content is None:
            raise RuntimeError("missing content field")

        output = "From: " + self._sender + "\nTo: " + self._recievers
        if self._timestamp is not None:
            output += "\nTime and Date: " + str(self._timestamp)

        output += (
            "\nTitle: "
            + self._title
            + "\nContent Length: "
            + str(len(self._content))
            + "\nContent: \n"
            + self._content
        )

        return output

    _sender: str

    def get_sender(self):
        return self._sender

    _recievers: str

    def get_recievers(self):
        return self._recievers

    _title: str

    def get_title(self):
        return self._title

    _content: str

    def get_content(self):
        return self._content

    _timestamp: dt.datetime

    def get_timestamp(self):
        return self._self

    def save_to_file(self):
        for recipient in self._recievers.split(";"):
            folder_name = recipient
            os.makedirs(
                folder_name, exist_ok=True
            )  # Create the folder if it doesn't exist

            # Looks for next index from index_map.json: "1": "file name"
            index_file = os.path.join(folder_name, "index_map.json")

            # Create index_map.json if it doesn't exist
            if not os.path.exists(index_file):
                with open(index_file, "w") as f:
                    js.dump({}, f)

            # Load the index map from the JSON file
            with open(index_file, "r") as f:
                try:
                    index_map = js.load(f)
                except js.JSONDecodeError:
                    index_map = {}  # If the file is corrupted, reset to an empty dictionary

            # Find the next index
            next_index = 1
            if index_map:
                last_index = max(map(int, index_map.keys()))
                next_index = last_index + 1

            # Save the email file [source client username]_[email title].txt
            file_name = f"{self._sender}_{self._title}.txt"
            file_path = os.path.join(folder_name, file_name)

            with open(file_path, "w") as f:
                f.write(self.create_message())  # Write the email content

            # Update the index_map.json with index: stored email
            index_map[str(next_index)] = {
                "file_name": file_name,
                "timestamp": str(self._timestamp),
            }
            with open(index_file, "w") as f:
                js.dump(index_map, f, indent=4)


def Email_from_message(message: str) -> Email:
    lines = message.splitlines()
    mail = Email(_SMTP__check_string(lines[0], b"From: "))
    mail.add_recievers(_SMTP__check_string(lines[1], b"To: "))
    mail.add_title(_SMTP__check_string(lines[2], b"Title: "))
    content_length = int(_SMTP__check_string(lines[3], b"Content Length: ").strip())
    _SMTP__check_string(lines[4], b"Content: ")
    content = b"".join(lines[5:])
    if len(content) != content_length:
        raise RuntimeError(
            "content length is not the same as in the header"
            + f"\n\theader content length: {content_length}"
            + f"\n\tactual content length: {len(content)}"
        )
    mail.add_content(content.decode("ascii"))
    return mail


class SMTP:
    def __init__(self, socket):
        self._socket = socket

    def send(self, email: Email):
        email = email.create_message()
        self._socket.sendall(email.encode("ascii"))
        recieved = self._socket.recv(2)
        if recieved != b"OK":
            raise RuntimeError(
                "expected 'OK' from server recieved: " + recieved.decode("ascii")
            )

    def recv(self, first_recv=1024) -> Email:
        recieved_data = self._socket.recv(first_recv)
        data_length = len(recieved_data)
        lines = recieved_data.splitlines()
        recieved_mail = Email(__check_string(lines[0], b"From: "))
        recieved_mail.add_recievers(__check_string(lines[1], b"To: "))
        recieved_mail.add_title(__check_string(lines[2], b"Title: "))
        content_length = int(__check_string(lines[3], b"Content Length: ").strip())
        __check_string(lines[4], b"Content: ")

        message_len = len(b"".join(lines[0:5])) + content_length
        if message_len > first_recv:
            read_len = len(recieved_data)
            while read_len < content_length:
                recieved_data = self._socket.recv(content_length)
                lines.extend(recieved_data.splitlines())
                read_len += len(recieved_data)

        content = b"".join(lines[5:])[0:content_length]
        recieved_mail.add_content(content.decode("ascii"))
        self._socket.send(b"OK")
        return recieved_mail

    _socket: skt.socket


def _SMTP__check_string(
    line: bytes,
    header: bytes,
) -> str:
    if line.startswith(header):
        line = line.decode("ascii")
        if len(header) == len(line):
            return ""
        return line[len(header) :]
    else:
        raise RuntimeError(f"invalid field {line}")
