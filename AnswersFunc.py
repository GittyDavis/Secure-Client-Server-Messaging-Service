import hashlib
import struct

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def answer1600(payload, name):
    with open("me.info", "w+") as my_info:
        my_info.write(name + "\n")
        my_info.write(str(payload.decode('utf-8')))
    print("\033[96mRegistered to authentication server succeeded.\n"
          "The next action is to ask for an AES key to connect with messaging server.")
    continue_operation()


def answer1601(payload, details):
    print("Client name exist. try again with another name")
    exit(0)


def answer1603(payload, details):
    password, nonce_from_request = struct.unpack("<255sQ", details)
    password = password.decode()
    password = password[:password.find('\0')]
    client_id, encrypted_key, ticket = struct.unpack("16s64s105s", payload)
    encrypted_key_iv, encrypted_data = struct.unpack("16s48s", encrypted_key)
    hashed_password = hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]
    client_key = bytes(hashed_password.encode('utf-8'))
    cipher = AES.new(client_key, AES.MODE_CBC, encrypted_key_iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    original_data = unpad(decrypted_data, AES.block_size)
    nonce_from_answer, aes_key = struct.unpack('<Q32s', original_data)
    if nonce_from_answer != nonce_from_request:
        print("\033[91mServer responded with an error.\033[0m\nExiting")
        exit(-1)
    print("\033[96mGot an aes key from authentication server successfully."
          "\nThe next action is to send the AES key to the message server.")
    continue_operation()
    return aes_key, ticket


def answer1604(payload, details):
    print("\033[96mMessage server received the aes key successfully"
          "\nThe next action is to send messages to print.")
    continue_operation()


def answer1605(payload, details):
    print("\033[96mGot the message. Printed. Thank you!")


def answer1609(payload, details):
    print("\033[91mServer responded with an error.\033[0m\nExiting")
    exit(-1)


def continue_operation():
    choice = input("Enter 1 to continue or 0 to exit: \033[96m\n")
    if choice == "0":
        print("You chose to exit. \nGoodBye.")
        exit(0)


def receive_answer(client_sock, details=""):
    try:
        header = client_sock.recv(7)
        version, code, payload_size = struct.unpack("<BHI", header)
        payload = client_sock.recv(payload_size)
        answers_func = {1600: answer1600, 1601: answer1601, 1603: answer1603,
                        1604: answer1604, 1605: answer1605, 1609: answer1609}
        return answers_func[code](payload, details)
    except Exception as e:
        print(f"\033[91mError: {e}")
