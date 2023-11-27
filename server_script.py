import socket

def test_server():
    # Local testing here (as stated in PDF)
    host = 'localhost'
    port = 2022

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Test server listening on {port}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024).decode()
                if data:
                    print(f"Received query for: {data}")
                    # Mock response if user exists
                    response = "online" if data == "jpope@gmail.com" else "offline"
                    conn.sendall(response.encode())

if __name__ == '__main__':
    test_server()