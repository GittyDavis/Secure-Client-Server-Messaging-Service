import socket
import threading

from ASRequestsFunc import handle_request, Client

SERVER_HOST = '127.0.0.1'
clients_dict = {}


def read_port():
    port = 1256
    try:
        with open("port.info", "r") as port_file:
            port = int(port_file.read())
    except FileNotFoundError:
        print("Warning: File 'port.info' not exist. Working on default port - 1256.")
    return port


def read_msg_server_details():
    try:
        with open("msg.info", "r") as msg_server_file:
            msg_server_file.readline()
            msg_server_file.readline()
            server_id = msg_server_file.readline().strip()
            aes_key = msg_server_file.readline().strip()
            return server_id, aes_key
    except FileNotFoundError:
        print("Warning: File 'msg.info' not exist.")


def load_clients():
    try:
        with open("clients.txt", "r") as file:
            lines = file.readlines()
            for line in lines:
                line = line.strip()
                client_id, name, password_hash, last_seen = line.split(':', 3)
                clients_dict[client_id] = Client(client_id, name, password_hash, last_seen)
    except FileNotFoundError:
        file = open("clients.txt", "w+")
        file.close()


def create_server_socket(port):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind((SERVER_HOST, port))
        server_sock.listen(5)
        print("Server listening on", SERVER_HOST, "port", port)
        return server_sock
    except Exception as e:
        print(f"Error: {e}")


def handle_client(client_sock):
    while True:
        connected = handle_request(client_sock, clients_dict)
        if not connected:
            break
    client_sock.close()
    print("Server finished handling client.")


if __name__ == '__main__':
    port_num = read_port()
    read_msg_server_details()
    load_clients()
    server_socket = create_server_socket(port_num)
    while True:
        client_socket, client_address = server_socket.accept()
        print("Server accepted connection from", client_address)
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()
