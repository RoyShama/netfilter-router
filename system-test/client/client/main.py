import socket
from datetime import datetime

from client.utils import TCPConnection


def test_communication_tcp(ip: str, port: int) -> bool:
    try:
        with TCPConnection(ip, port) as connection:
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


print(test_communication_tcp('127.0.0.1', 65435))
