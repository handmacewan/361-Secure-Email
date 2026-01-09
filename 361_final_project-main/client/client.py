import socket as skt  # Importing socket module for network communication
import sys  # Importing sys module for system-specific parameters and functions
import json as js  # Importing JSON module for handling JSON data
import os  # Importing OS module for interacting with the operating system
import glob as gb  # Importing glob module for file pattern matching
import datetime as dt  # Importing datetime module for handling date and time
from Crypto.PublicKey import RSA  # Importing RSA for public/private key handling
from Crypto.Cipher import AES, PKCS1_OAEP  # Importing AES and PKCS1_OAEP for encryption
from Crypto.Util.Padding import pad, unpad  # Importing padding utilities for encryption
from Crypto.Random import get_random_bytes  # Importing random byte generator for cryptography

# const global vars. SHOULD NOT BE CHANGED
SERVER_PORT = 13001  # Port Number client will use
SERVER_HOST = input("Enter the server IP or name: ")  # Prompt user for server IP or hostname

class BlkSocket:
    def __init__(self, socket: skt.socket, max_len=8):
        self._socket = socket
        self._max_len = max_len

    def b_recv(self) -> bytes:
        size = self._socket.recv(self._max_len)
        while len(size) != self._max_len:
            size += self._socket.recv(self._max_len - len(size))

        size = int.from_bytes(size, byteorder="big")
        data = bytes()
        while len(data) < size:
            data += self._socket.recv(size - len(data))

        return data

    def b_sendall(self, data: bytes):
        self._socket.sendall(len(data).to_bytes(self._max_len, byteorder='big') + data)

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
# Email class to represent an email object
class Email:
    def __init__(self, sender: str):
        self._sender = sender  # Sender's email address
        self._recievers = None  # Recipients of the email
        self._title = None  # Title of the email
        self._content = None  # Content of the email
        self._timestamp = None  # Timestamp of the email

    def clear(self):
        # Clear all email fields
        clear(self._recievers)
        clear(self._title)
        clear(self._timestamp)
        clear(self._content)

    def add_recievers(self, recievers: str):
        # Add recipients to the email
        self._recievers = recievers.strip()

    def add_title(self, title: str):
        # Add a title to the email, with a length check
        if len(title) > 100:
            raise RuntimeError("title can't be more than 100 characters.")
        self._title = title.strip()

    def add_content(self, content: str):
        # Add content to the email, with a length check
        content = content.strip()
        if len(content) > 100000:
            raise RuntimeError("content length too long (max 1000000.")
        self._content = content

    def __str__(self):
        # Placeholder for string representation of the email
        pass

    def timestamp(self, date):
        # Set the timestamp to the current date and time
        self._timestamp = dt.datetime.now()

    def create_message(self) -> str:
        # Create the email message string
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

    # Getter methods for email fields
    def get_sender(self):
        return self._sender

    def get_recievers(self):
        return self._recievers

    def get_title(self):
        return self._title

    def get_content(self):
        return self._content

    def get_timestamp(self):
        return self._self

    def save_to_file(self):
        # Save the email to a file for each recipient
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


# Function to create an Email object from a message string
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


# Helper function to validate and extract string fields
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


# Function to get email content from the user
def get_content() -> str:
    while True:
        match (
            input("Would you like to load contents from a file? (Y/N): ")
            .strip()
            .upper()
        ):
            case "Y":
                try:
                    file = open(input("enter filename: ").strip())
                except FileNotFoundError:
                    print("file does not exist")
                    continue
                file_contents = file.read().strip()
                file.close()
                return file_contents
            case "N":
                return input("enter content: ").strip()
            case _:
                print("invalid input\n\n")


# Function to create and send an email
def create_and_send_Email(client_socket: AESsocket, username):
    key = client_socket.s_recv()  # Receive the server's response
    mail = Email(username)
    # Step 1: Enter recipients
    mail.add_recievers(input("Enter destinations (separated by ;):").strip())

    # Step 2: Enter title and content
    while True:
        try:
            mail.add_title(input("Enter title:").strip())
            mail.add_content(get_content())
        except RuntimeError as e:
            print("invalid input: \n\t", e)
            continue
        break

    print("the message is sent to the server", end="...")
    client_socket.s_sendall(mail.create_message().encode())
    print("done")


# Function to retrieve and display the inbox
def get_inbox(client_socket):
    data = client_socket.s_recv()

    sys.stdout.write(data.decode())  # Display the inbox list


# Function to display the content of an email
def display_content(client_socket):
    data = client_socket.s_recv().decode()
    sys.stdout.write(data)  # Display response
    sys.stdout.flush()
    if "Enter the email index" in data:
        email_index = sys.stdin.readline().strip()
        client_socket.s_sendall(
            email_index.encode()
        )  # Send the email index to the server
        # Send the email index to the server
        # Keep receiving data 1024 byte chunks
        chunk = client_socket.s_recv().decode()
        # if not chunk:
        #    break  # Exit loop if no more data is received

        sys.stdout.write(chunk.replace("<END>", ""))  # Remove <END>
        sys.stdout.flush()


# Main function to handle client operations
def main():
    # Create a socket using IPv4 and TCP
    with skt.socket(skt.AF_INET, skt.SOCK_STREAM) as client_socket:
        client_socket.connect(
            (SERVER_HOST, SERVER_PORT)
        )  # Connect to the above's server name and port
        s_client_socket = PEMsocket(client_socket)

        s_client_socket.set_pub_key("server_public.pem")
        s_client_socket.set_priv_key("client_private.pem")

        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()
        s_client_socket.s_sendall(username.encode())
        s_client_socket.s_sendall(password.encode())
        response = s_client_socket.get_sock().b_recv()

        if b"Invalid username or password." in response:
            print(response)
            return

        s_client_socket = AESsocket(client_socket, s_client_socket.decrypt(response))

        while True:
            user_input = input(s_client_socket.s_recv().decode()).strip()
            if user_input == "1":  # Option 1: Create and send an email
                s_client_socket.s_sendall(b"1")
                create_and_send_Email(s_client_socket, username)
                continue

            elif user_input == "2":  # Option 2: Display the inbox list
                s_client_socket.s_sendall(b"2")
                get_inbox(s_client_socket)

                continue

            elif user_input == "3":  # Option 3: Display the email contents
                s_client_socket.s_sendall(b"3")
                display_content(s_client_socket)

                continue

            elif user_input == "4":  # Option 4: Terminate connection
                s_client_socket.s_sendall(b"4")
                response = s_client_socket.get_sock().b_recv()
                sys.stdout.write(response.decode())
                sys.stdout.flush()
                client_socket.close()
                break
            else:
                s_client_socket.s_sendall(b"4")
                response = s_client_socket.get_sock().b_recv()
                sys.stdout.write(response.decode())
                sys.stdout.flush()
                client_socket.close()
                break


# Entry point of the script
if __name__ == "__main__":
    main()
