import socket

HOST = '0.0.0.0'
PORT = 65435

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        for _ in range(10):
            data = conn.recv(1024)
            data = data.decode('utf8').replace('i', 'o')
            conn.send(data.encode('utf8'))
