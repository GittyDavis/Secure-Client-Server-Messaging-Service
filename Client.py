import linecache
import os
import secrets
import socket
import struct
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from AnswersFunc import receive_answer, continue_operation


def read_port():
    try:
        with open("srv.info", "r") as file:
            auth_server_ip, auth_server_port = file.readline().strip().split(':')
            msg_server_ip, msg_server_port = file.readline().strip().split(':')
    except FileNotFoundError:
        print("The file 'srv.info' not found.")
    return auth_server_ip, int(auth_server_port), msg_server_ip, int(msg_server_port)


def connect_to_sever(server_ip, server_port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    return client


def registrate_client(client_sock):
    name = input("\033[96mPlease enter your name: \033[0m")
    password = input("\033[96mPlease enter your password: \033[0m")
    if len(name) > 255 or len(password) > 32:
        print("\033[91mIncorrect input.\033[0m")
    if os.path.exists("me.info"):
        name_from_file = linecache.getline('me.info', 1).strip()
        if name != name_from_file:
            print("\033[91mIncorrect name, Try again.\033[0m")
            exit(0)
        else:
            print("\033[96mYou reconnect to the authentication server successfully.\n"
                  "The next action is to ask for an AES key to connect with messaging server.")
            continue_operation()
    else:
        payload = struct.pack("255s255s", name.encode('utf-8'), password.encode('utf-8'))
        send_request(client_sock, "".encode('utf-8'), 1024, payload)
        receive_answer(client_sock, name)
    return password


def aes_key_request(client_socket, password):
    client_id = linecache.getline('me.info', 2).strip()
    nonce = secrets.randbits(64)
    send_request(client_socket, client_id.encode('utf-8'), 1027, struct.pack("<Q", nonce))
    details = struct.pack("<255sQ", password.encode('utf-8'), nonce)
    return receive_answer(client_socket, details)


def send_aes_key(client_socket, aes_key, ticket):
    header_ticket = ticket[:33]
    version, client_id, server_id = struct.unpack("<B16s16s", header_ticket)
    creation_time = datetime.now().timestamp()
    data = header_ticket + struct.pack("<d", creation_time)
    padded_data = pad(data, AES.block_size)
    authenticator_iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, authenticator_iv)
    authenticator = struct.pack("16s48s", authenticator_iv, cipher.encrypt(padded_data))
    send_request(client_socket, client_id, 1028, authenticator + ticket)
    receive_answer(client_socket)


def send_msg_to_print(client_socket, aes_key):
    print("\033[96mYou can now send messages to print.")
    client_id = linecache.getline('me.info', 2).strip()
    while True:
        msg = input("Your message - (type 'quit' to exit): ")
        if msg.lower() == 'quit':
            print("You chose to exit,\nGoodBye.\033[0m")
            break
        padded_msg = pad(msg.encode('utf-8'), AES.block_size)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_msg)
        payload = struct.pack("<i16s", len(ciphertext), iv) + ciphertext
        send_request(client_socket, client_id.encode('utf-8'), 1029, payload)
        receive_answer(client_socket)


def send_request(client_socket, client_id, code, payload):
    header = struct.pack("<16sBHI", client_id, 24, code, len(payload))
    # print(code)
    # print(header + payload)
    client_socket.sendall(header + payload)


if __name__ == '__main__':
    auth_srv_ip, auth_srv_port, msg_srv_ip, msg_srv_port = read_port()
    client_and_auth_server_socket = connect_to_sever(auth_srv_ip, auth_srv_port)
    client_password = registrate_client(client_and_auth_server_socket)
    client_server_key, ticket_to_msg_server = aes_key_request(client_and_auth_server_socket, client_password)
    client_and_auth_server_socket.close()
    client_and_msg_server_socket = connect_to_sever(msg_srv_ip, msg_srv_port)
    send_aes_key(client_and_msg_server_socket, client_server_key, ticket_to_msg_server)
    send_msg_to_print(client_and_msg_server_socket, client_server_key)
    client_and_msg_server_socket.close()
    print("Connection to server closed")
