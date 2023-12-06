import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

encryption_key_file = "./.config/SecureDrop/key.json"

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

iv_from_sender = "M/LXAOjXmzVb10+RalFTRA=="
encrypted_data_from_sender = "gnbCX/aJ/lm0PrPJKKVJy1FS6Ms6OAiRb+YkQsJqNznlM98H+xIlArFIM2ErEiVI"

file_message = {
    "iv": iv_from_sender,
    "data": encrypted_data_from_sender
}

contact_encryption_key = get_aes_encryption_key()
simulate_receiver(file_message, contact_encryption_key)
