import linecache
import secrets
import struct
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def add_client_to_db(client, clients_dict):
    clients_dict[client.client_id] = client
    with open("clients.txt", "a") as file:
        file.write(client.client_id + ":" + client.name + ':' +
                   client.password_hash + ':' + str(client.last_seen) + '\n')


def create_encrypted_key(client_id, payload, clients_dict):
    iv = secrets.token_bytes(AES.block_size)
    client_key = clients_dict[client_id].password_hash
    client_key = bytes(client_key.encode('utf-8'))
    aes_key = get_random_bytes(32)
    nonce = struct.unpack("<Q", payload)[0]
    data = nonce.to_bytes(length=8, byteorder="little") + aes_key
    padded_data = pad(data, AES.block_size)
    cipher = AES.new(client_key, AES.MODE_CBC, iv)
    return struct.pack("16s48s", iv, cipher.encrypt(padded_data)), aes_key


def convert_hex_to_bytes(hex_val):
    bytes_val = []
    while hex_val:
        bytes_val.append(int(hex_val[:2], 16))
        hex_val = hex_val[2:]
    return bytearray(bytes_val)


def create_ticket(client_id, aes_key):
    version = 24
    server_id = linecache.getline('msg.info', 3).strip()
    msg_server_key = linecache.getline('msg.info', 4).strip()
    msg_server_key = bytes(msg_server_key, 'utf-8')
    creation_time = datetime.now().timestamp()
    iv = secrets.token_bytes(AES.block_size)
    server_id = convert_hex_to_bytes(server_id)
    header_ticket = struct.pack("<B16s16sd16s", version, client_id, server_id, creation_time, iv)
    expiration_time = (datetime.now() + timedelta(hours=9)).timestamp()
    data = aes_key + struct.pack('<d', expiration_time)
    padded_data = pad(data, AES.block_size)
    cipher = AES.new(msg_server_key, AES.MODE_CBC, iv)
    return header_ticket + cipher.encrypt(padded_data)
