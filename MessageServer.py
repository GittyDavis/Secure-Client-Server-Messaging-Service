import socket
import threading

from MSGRequestsFunc import handle_request


def read_port():
    with open("msg.info", "r") as file:
        ip, port = file.readline().split(":")
    return ip, int(port)


def create_server_socket(ip, port_num):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind((ip, port_num))
        server_sock.listen(5)
        print("Server listening on", ip, "port", port_num)
        return server_sock
    except Exception as e:
        print(f"Error: {e}")


def handle_client(client_sock):
    while True:
        connected = handle_request(client_sock)
        if not connected:
            break
    client_sock.close()
    print("Server finished handling client")


if __name__ == '__main__':
    server_ip, server_port = read_port()
    server_socket = create_server_socket(server_ip, server_port)
    while True:
        client_socket, client_address = server_socket.accept()
        print("Server accepted connection from", client_address)
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()
