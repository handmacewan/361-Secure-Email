import socket as skt  # Importing socket module for network communication
import sys  # Importing sys module for system-specific parameters and functions
import os  # Importing OS module for interacting with the operating system
import datetime as dt  # Importing datetime module for handling date and time
import json as js  # Importing JSON module for handling JSON data
import glob as gb  # Importing glob module for file pattern matching
from Crypto.PublicKey import RSA  # Importing RSA for public/private key handling
from Crypto.Cipher import AES, PKCS1_OAEP  # Importing AES and PKCS1_OAEP for encryption
from Crypto.Util.Padding import pad, unpad  # Importing padding utilities for encryption
from Crypto.Random import get_random_bytes  # Importing random byte generator for cryptography
# any module from the crypto lib:


# const global vars. SHOULD NOT BE CHANGED
HOST = ""  # Server will listen on all available interfaces
PORT = 13001  # Port number for the server to listen on
DATABASE_FILE = "Database.json"  # File to store email data
USER_PASS_FILE = "user_pass.json"  # File to store user credentials

# Check if the Database.json file exists
# Uncomment the following lines if you want to initialize the database file
if not os.path.exists(DATABASE_FILE):
  with open(DATABASE_FILE, "w") as db:
       js.dump({}, db)

# Class to handle socket communication with a fixed-length header
class BlkSocket:
    def __init__(self, socket: skt.socket, max_len=8):
        self._socket = socket  # Underlying socket object
        self._max_len = max_len  # Maximum length of the header

    def b_recv(self) -> bytes:
        # Receive the size of the incoming message
        size = self._socket.recv(self._max_len)
        while len(size) != self._max_len:
            size += self._socket.recv(self._max_len - len(size))

        size = int.from_bytes(size, byteorder ='big')  # Convert size to an integer
        data = bytes()
        # Receive the actual message data
        while len(data) < size:
            data += self._socket.recv(size - len(data))

        return data

    def b_sendall(self, data: bytes):
        # Send the size of the message followed by the actual data
        self._socket.sendall(len(data).to_bytes(self._max_len, byteorder ='big') + data)

    def get_sock(self):
        # Return the underlying socket object
        return self._socket

    _socket: skt.socket  # Underlying socket object
    _max_len: int  # Maximum length of the header


# Class to handle PEM-based encryption and decryption
class PEMsocket:
    def __init__(
        self,
        socket: BlkSocket,
    ):
        if socket is not BlkSocket:
            self._socket = BlkSocket(socket)  # Wrap the socket in a BlkSocket
        else:
            self._socket = socket

        self._priv = None  # Private key
        self._pub = None  # Public key

    def set_pub_key(self, public_key_file: str):
        # Load the public key from a file
        with open(public_key_file, "rb") as key_file:
            self._pub = key_file.read()

    def set_priv_key(self, private_key_file: str):
        # Load the private key from a file
        with open(private_key_file, "rb") as key_file:
            self._priv = key_file.read()

    def s_recv(self) -> bytes:
        # Receive and decrypt data
        return self.decrypt(self._socket.b_recv())

    def s_sendall(self, message: bytes):
        # Encrypt and send data
        self._socket.b_sendall(self.encrypt(message))

    def encrypt(self, message):
        # Encrypt the message using the public key
        server_public_key = RSA.import_key(self._pub)
        cipher = PKCS1_OAEP.new(server_public_key)
        return cipher.encrypt(message)

    def decrypt(self, encrypted_message):
        # Decrypt the message using the private key
        client_private_key = RSA.import_key(self._priv)
        cipher = PKCS1_OAEP.new(client_private_key)
        return cipher.decrypt(encrypted_message)

    def get_sock(self) -> BlkSocket:
        # Return the underlying BlkSocket
        return self._socket

    _socket: BlkSocket  # Underlying BlkSocket
    _pub: str  # Public key
    _priv: str  # Private key


# Class to handle AES-based encryption and decryption
class AESsocket:
    def __init__(self, socket, key=None):
        if socket is not BlkSocket:
            self._socket = BlkSocket(socket)  # Wrap the socket in a BlkSocket
        else:
            self._socket = socket

        if key is None:
            self._key = get_random_bytes(32)  # Generate a random 256-bit key
        else:
            self._key = key
        self._cipher = AES.new(self._key, AES.MODE_ECB)  # Initialize AES cipher in ECB mode

    def get_key(self) -> bytes:
        # Return the AES key
        return bytes(self._key)

    def s_recv(self) -> bytes:
        # Receive and decrypt data
        return self.decrypt(self._socket.b_recv())

    def s_sendall(self, data: bytes):
        # Encrypt and send data
        self._socket.b_sendall(self.encrypt(data))

    def encrypt(self, plaintext: bytes) -> bytes:
        # Encrypt the plaintext using AES
        ciphertext = self._cipher.encrypt(pad(plaintext, 16))
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        # Decrypt the ciphertext using AES
        plaintext = unpad(self._cipher.decrypt(ciphertext), 16)
        return plaintext

    def get_sock(self) -> BlkSocket:
        # Return the underlying BlkSocket
        return self._socket

    _socket: BlkSocket  # Underlying BlkSocket
    _key: bytes  # AES key


# Class to represent an email
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

# Load user_pass.json
def load_user_pass():
    if not os.path.exists(USER_PASS_FILE):
        sys.exit(1)  # Closes if no user_pass.json
    with open(USER_PASS_FILE, "r") as up_file:
        user_pass = js.load(up_file)
    return {
        username.encode(): password.encode() for username, password in user_pass.items()
    }


# Function to create a folder for the client if it doesn't exist
def create_client_directory(username):
    client_folder = username
    if not os.path.exists(client_folder):
        os.makedirs(client_folder)  # Create the folder if it doesn't exist
        print(f"Created directory for {username}")


# Option 1: Create and Send Email Function
def create_and_send_Email(client_socket: AESsocket, sender):
    client_socket.s_sendall(b"Send the email using " + client_socket.get_key())
    client_mail = Email_from_message(client_socket.s_recv())
    client_mail.timestamp(dt.datetime.today())
    print(
        f"An email from {client_mail.get_sender()}"
        + f" is sent to {client_mail.get_recievers()}"
        + f" has a content length of {len(client_mail.get_content())}"
    )
    client_mail.save_to_file()


# Option 2: Get Inbox List Function
def get_inbox_list(client_socket, username):
    inbox_folder = username.decode()  # Folder is the username of the logged-in person

    index_file = os.path.join(inbox_folder, "index_map.json")

    return_string = b""

    # Check if the index_map.json file exists and not empty
    if os.path.exists(index_file) and os.stat(index_file).st_size > 0:
        with open(index_file, "r", encoding="utf-8") as f:
            index_map = js.load(f)
    else:
        # if nothing in index_map, respond to the client empty or missing
        client_socket.s_sendall(f"No emails found for {inbox_folder}.\n".encode())
        return

    # Display email list header: "Index    From      DateTime        Title"
    return_string += b"\nIndex  From        DateTime                Title\n"

    # Iterate through the index_map to display the emails
    for email_index, email_info in index_map.items():
        # Get file_name and timestamp from index_map
        file_name = email_info["file_name"]
        timestamp = email_info["timestamp"]

        # Split "From" and "Title" from the file_name
        try:
            from_user, title_with_extension = file_name.rsplit("_", 1)
            title = title_with_extension.rsplit(".", 1)[0]
        except ValueError:
            # error fallback if file_name is unexpected
            from_user = "Unknown"
            title = "No Title"

        # Format the email information to display
        email_info_display = (
            f"{email_index:<6} {from_user:<10} {timestamp:<25} {title:<100}\n"
        )
        return_string += email_info_display.encode()

    client_socket.s_sendall(return_string + b"\n")


# Option 3: Display Email Contents
def display_email_content(client_socket: AESsocket, username):
    inbox_folder = username.decode()  # Folder is the username of the logged-in person

    index_file = os.path.join(inbox_folder, "index_map.json")

    # Load index_map.json
    if os.path.exists(index_file) and os.stat(index_file).st_size > 0:
        with open(index_file, "r", encoding="utf-8") as f:
            index_map = js.load(f)
    else:
        client_socket.s_sendall(f"No emails found for {inbox_folder}.\n".encode())
        return

    # Ask for the index
    client_socket.s_sendall(b"Enter the email index you wish to view: ")
    selected_index = client_socket.s_recv().decode().strip()

    # Get the email entry (dictionary) from index_map.json
    email_entry = index_map.get(selected_index)

    if not email_entry:
        client_socket.s_sendall(b"Invalid email index.\n")
        return

    # get only file_name
    file_name = email_entry["file_name"]
    file_path = os.path.join(inbox_folder, file_name)

    # Check if this file exists in the folder
    if not os.path.exists(file_path):
        client_socket.s_sendall(b"Email file not found.\n")
        return

    # Displays the email contents
    with open(file_path, "r", encoding="utf-8") as f:
        email_content = f.read()

    # Process email content
    lines = email_content.splitlines()

    from_user = next(
        (line.split(":", 1)[1].strip() for line in lines if line.startswith("From:")),
        "Unknown",
    )
    to_users = next(
        (line.split(":", 1)[1].strip() for line in lines if line.startswith("To:")),
        "Unknown",
    )
    datetime_str = next(
        (
            line.split(":", 1)[1].strip()
            for line in lines
            if line.startswith("Time and Date:")
        ),
        "Unknown",
    )
    title = next(
        (line.split(":", 1)[1].strip() for line in lines if line.startswith("Title:")),
        "No Title",
    )

    # Extract message content after "Content:"
    content_index = next(
        (i for i, line in enumerate(lines) if line.strip().startswith("Content:")), None
    )
    if content_index is not None:
        message_content = (
            lines[content_index].split(":", 1)[1].strip()
        )  # Strip "Content:"
        message_content += (
            "\n" + "\n".join(lines[content_index + 1 :]).strip()
        )  # Append the lines

    # Get content length
    content_length = len(message_content)

    # Format and send email details
    email_details = (
        f"\nFrom: {from_user}\n"
        f"To: {to_users}\n"
        f"Time and Date: {datetime_str}\n"
        f"Title: {title}\n"
        f"Content Length: {content_length}\n"
        f"Content:{message_content}\n"
        "<END>"
    )

    client_socket.s_sendall(email_details.encode())


# Ensure index_map.json exists, if not create it
def ensure_index_map(inbox_folder):
    index_file = os.path.join(inbox_folder, "index_map.json")

    # If index_map.json exists and is not empty, load and return it
    if os.path.exists(index_file) and os.stat(index_file).st_size > 0:
        with open(index_file, "r") as f:
            return js.load(f)

    # If index_map.json does not exist, create it with available .txt files
    email_files = [f for f in os.listdir(inbox_folder) if f.endswith(".txt")]
    index_map = {str(i + 1): email_files[i] for i in range(len(email_files))}

    # Save the new index map to JSON
    with open(index_file, "w") as f:
        js.dump(index_map, f, indent=4)

    return index_map


# Function to help communicate with the client
def handle_client(client_socket: PEMsocket):
    client_socket.set_priv_key("server_private.pem")
    users = load_user_pass()  # Loads user and passwords

    username = client_socket.s_recv()
    password = client_socket.s_recv()

    # Check if the user exists
    if username not in users or password != users[username]:
        client_socket.get_sock().b_sendall(b"Invalid username or password.\n")
        return

    client_socket.set_pub_key(f"{username.decode()}_public.pem")

    temp = AESsocket(client_socket.get_sock().get_sock())
    client_socket.s_sendall(temp.get_key())
    client_socket = temp

    # creates the client's folder if doesn't exist
    create_client_directory(username)

    while True:
        menu = (
            b"\nSelect the operation:\n"
            + b"1) Create and send an email \n"
            + b"2) Display the inbox list \n"
            + b"3) Display the email contents \n"
            + b"4) Terminate the connection\n"
            + b"Choice: "
        )
        client_socket.s_sendall(menu)  # Sends the above menu text to client

        choice = client_socket.s_recv()  # Receives the client's selection

        if choice == b"1":  # Option 1 Create and send an email
            create_and_send_Email(client_socket, username)

        elif choice == b"2":  # Option 2 Display the inbox list
            get_inbox_list(client_socket, username)

        elif choice == b"3":  # Option 3 Display the email contents
            display_email_content(client_socket, username)

        elif choice == b"4":  # Option 4 Terminate the connection
            client_socket.get_sock().b_sendall(
                b"The connection is terminated with the server.\n"
            )
            client_socket.get_sock().get_sock().close()
            break


# os.fork(): For UNIX: Comment out for Windows testing.
def _forking_operations(server, client_socket):
    pid = os.fork()
    if pid == 0:
        server.close()
        handle_client(PEMsocket(client_socket))
        client_socket.close()
        os._exit(0)
    else:
        client_socket.close()


def main():
    server = skt.socket(skt.AF_INET, skt.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Server listening on port {PORT}...")

    while True:
        client_socket, addr = server.accept()
        _forking_operations(server, client_socket)


if __name__ == "__main__":
    main()
