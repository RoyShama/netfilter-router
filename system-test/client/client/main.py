from __future__ import annotations

import socket
from datetime import datetime
from time import sleep


class Connection:
    """
    generate a connection
    """
    ENCODING = 'utf8'

    def __init__(self,
                 source_port: int,
                 destination_ip: str,
                 destination_port: int):
        self.source_port = source_port
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
        self.socket.bind(('0.0.0.0', self.source_port))
        self.socket.connect((self.destination_ip, self.destination_port))
        self.socket.settimeout(1)
        return self


def test_communication_tcp(source_port: int, ip: str, port: int) -> bool:
    try:
        with TCPConnection(source_port, ip, port) as connection:
            for _ in range(10):
                current_time = datetime.now()
                message = f'ping{current_time}'
                expected_response = f'pong{current_time}'
                connection.send(message)
                response = connection.receive(len(message))
                assert response == expected_response
        return True
    except Exception as e:
        return False

sleep(5)

print(test_communication_tcp(5000, '100.0.0.2', 65435))
