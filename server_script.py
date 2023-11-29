import socket
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def load_network_key(file_path):
    with open(file_path, 'r') as file:
        key_data = json.load(file)
        return base64.b64decode(key_data["key"])

network_decryption_key = load_network_key("./.config/SecureDrop/key.json")

def decrypt_network_data(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    ct = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def test_server():
    host = 'localhost'
    port = 2022

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()
        print(f"Test server listening on {port}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                encrypted_data = conn.recv(1024)
                if encrypted_data:
                    email = decrypt_network_data(encrypted_data, network_decryption_key)
                    print(f"Received query for: {email}")
                    response = "online" if email == "jpope@gmail.com" else "offline"
                    conn.sendall(response.encode())

if __name__ == '__main__':
    test_server()
