import hashlib
import struct
import uuid
from datetime import datetime

from functions import add_client_to_db, create_encrypted_key, create_ticket

values = {'registering client request': 1024, 'symmetric key request': 1027,
          'error answer code': 1609, 'registering succeeded': 1600, 'registering failed': 1601,
          'sending key answer': 1603, 'version': 24, 'header size': 23}


class Client:
    def __init__(self, client_id, name, password_hash, last_seen):
        self.client_id = client_id[:16]
        self.name = name[:]
        self.password_hash = password_hash[:]
        self.last_seen = last_seen


def request1024(client_id, payload, clients_dict):
    payload = payload.decode()
    name = payload[:payload.find('\0')]
    payload = payload[255:]
    password = payload[:payload.find('\0')]
    for client in clients_dict.values():
        if client.name == name:
            return values['registering failed'], None
    client_uuid = uuid.uuid1().hex.encode()
    hashed_password = hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]
    new_client = Client(str(client_uuid.decode('utf-8')), name, hashed_password, datetime.now())
    add_client_to_db(new_client, clients_dict)
    return values['registering succeeded'], struct.pack("<16s", client_uuid)


def request1027(client_id, payload, clients_dict):
    encrypted_key, aes_key = create_encrypted_key(client_id.decode('utf-8'), payload, clients_dict)
    ticket = create_ticket(client_id, aes_key)
    return values['sending key answer'], struct.pack("16s64s105s", client_id, encrypted_key, ticket)


def send_answer(client_sock, answer_code, payload):
    if payload:
        header = struct.pack("<BHI", values['version'], answer_code, len(payload))
        # print(header + payload)
        client_sock.sendall(header + payload)
    else:
        header = struct.pack("<BHI", values['version'], answer_code, 0)
        client_sock.send(header)


def handle_request(client_socket, clients_dict):
    try:
        header = client_socket.recv(values['header size'])
        if not header:
            return False
        client_id, version, code, payload_size = struct.unpack("<16sBHI", header)
        payload = client_socket.recv(payload_size)
        print(f"Received request:\nClient id: {client_id}\n"
                   f"Code: {code}\nPayload: {payload}")
        requests_func = {values['registering client request']: request1024,
                         values['symmetric key request']: request1027}
        answer_code, payload = requests_func[code](client_id, payload, clients_dict)
        send_answer(client_socket, answer_code, payload)
        return True
    except Exception as e:
        send_answer(client_socket, values['error answer code'], None)
        print(f"Error while handling client:\n{e}")
        return False
