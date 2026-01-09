import smtp
import socket as skt

with skt.socket(skt.AF_INET, skt.SOCK_STREAM) as server_socket:
    server_socket.bind(("", 13000))
    server_socket.listen(5)

    client_socket, addr = server_socket.accept()
    key = client_socket.recv(32)
    ssocket = smtp.AESsocket(client_socket, key)

    email = ssocket.s_recv()
    email = smtp.Email_from_message(email)
    print(email.create_message())
    test = email._content
    print(len(test))
