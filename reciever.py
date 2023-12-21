import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

encryption_key_file = "./.config/SecureDrop/key.json"

def read_sender_info(file_path):
    try:
        with open(file_path, 'r') as sender_info_file:
            sender_info = json.load(sender_info_file)
            return sender_info["iv_from_sender"], sender_info["encrypted_data_from_sender"]
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading sender_info.json: {e}")
        return None, None

def simulate_receiver(file_message, contact_encryption_key):
    iv = base64.b64decode(file_message["iv"])
    encrypted_file_data = base64.b64decode(file_message["data"])
    decrypted_file_data = decrypt_file(iv, encrypted_file_data, contact_encryption_key)

    with open("received_file.txt", 'wb') as file:
        file.write(decrypted_file_data)

def decrypt_file(iv, encrypted_data, key):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data
    except ValueError as e:
        print(f"Error decrypting file: {e}")
        return None

def get_aes_encryption_key():
    encryption_key = json.load(open(encryption_key_file, "r"))["key"]
    return base64.b64decode(encryption_key)

sender_info_path = "sender_info.json"
iv_from_sender, encrypted_data_from_sender = read_sender_info(sender_info_path)

if iv_from_sender is not None and encrypted_data_from_sender is not None:
    contact_encryption_key = get_aes_encryption_key()
    simulate_receiver({"iv": iv_from_sender, "data": encrypted_data_from_sender}, contact_encryption_key)
else:
    print("Error reading sender_info.json. Make sure the file exists and contains valid JSON.")
