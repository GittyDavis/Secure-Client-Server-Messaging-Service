import linecache
import struct
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

clients_dict = {}
values = {'sending an aes key request': 1028, 'sending messages to print request': 1029,
          'error answer code': 1609, 'got key answer code': 1604, 'print msg answer code': 1605}


def data_from_authenticator(msg_server_key, authenticator):
    try:
        authenticator_iv, encrypted_authenticator_data = struct.unpack("16s48s", authenticator)
        cipher_authenticator = AES.new(msg_server_key, AES.MODE_CBC, authenticator_iv)
        decrypted_authenticator = cipher_authenticator.decrypt(encrypted_authenticator_data)
        original_data = unpad(decrypted_authenticator, AES.block_size)
        version, c_id, server_id, creation_time = struct.unpack("<B16s16sd", original_data)
        return creation_time
    except Exception as e:
        print(f"Error: {e}")


def data_from_ticket(msg_server_key, ticket):
    version, c_id, server_id, creation_time, ticket_iv, encrypted_key \
        = struct.unpack("<B16s16sd16s48s", ticket)
    cipher_ticket = AES.new(msg_server_key, AES.MODE_CBC, ticket_iv)
    decrypted_ticket = cipher_ticket.decrypt(encrypted_key)
    original_ticket = unpad(decrypted_ticket, AES.block_size)
    return struct.unpack("<32sd", original_ticket)


def check_validation(ticket_expiration_time, authenticator_creation_time):
    now = datetime.now().timestamp()
    if ticket_expiration_time < now or authenticator_creation_time > ticket_expiration_time:
        return values['error answer code']
    return values['got key answer code']


def request1028(client_id, payload):
    authenticator, ticket = struct.unpack("<64s105s", payload)
    msg_server_key = linecache.getline('msg.info', 4).strip()
    msg_server_key = bytes(msg_server_key, 'utf-8')
    aes_key, ticket_expiration_time = data_from_ticket(msg_server_key, ticket)
    clients_dict[client_id] = aes_key
    authenticator_creation_time = data_from_authenticator(aes_key, authenticator)
    code = check_validation(ticket_expiration_time, authenticator_creation_time)
    return code


def request1029(client_id, payload):
    msg_size, msg_iv = struct.unpack("<i16s", payload[:20])
    aes_key = clients_dict.get(client_id)
    ciphertext = payload[20:]
    cipher = AES.new(aes_key, AES.MODE_CBC, msg_iv)
    decrypted_msg = cipher.decrypt(ciphertext)
    original_msg = unpad(decrypted_msg, AES.block_size)
    original_msg = original_msg.decode('utf-8')
    print("\033[95m", original_msg, "\033[0m", sep="")
    return values['print msg answer code']


def send_answer(client_sock, answer_code):
    header = struct.pack("<BHI", 24, answer_code, 0)
    client_sock.send(header)


def handle_request(client_socket):
    try:
        header = client_socket.recv(23)
        if not header:
            return False
        client_id, version, code, payload_size = struct.unpack("<16sBHI", header)
        payload = client_socket.recv(payload_size)
        print(f"Received request:\nClient id: {client_id}\n"
                   f"Code: {code}\nPayload: {payload}")
        requests_func = {values['sending an aes key request']: request1028,
                         values['sending messages to print request']: request1029}
        answer_code = requests_func[code](client_id, payload)
        send_answer(client_socket, answer_code)
        return True
    except Exception:
        send_answer(client_socket, 1609)
        return False
