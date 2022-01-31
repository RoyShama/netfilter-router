from __future__ import annotations

import socket


class Connection:
    """
    generate a connection
    """
    ENCODING = 'utf8'

    def __init__(self,
                 destination_ip: str,
                 destination_port: int):
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.socket: socket.socket = None

    def send(self, data: str):
        self.socket.send(data.encode(self.ENCODING))

    def receive(self, size: int) -> str:
        return self.socket.recv(size).decode(self.ENCODING)

    def __enter__(self) -> Connection:
        raise NotImplementedError()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()


class TCPConnection(Connection):
    def __enter__(self) -> TCPConnection:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.destination_ip, self.destination_port))
        self.socket.settimeout(1)
        return self
