"""
Starts the HTTP server and performs scripted interactions to check
that the HTTP semantics are correct.
"""

import time
import socket
import subprocess
import sys
from datetime import datetime
from dataclasses import dataclass

HTTP_PORT = 8080
HTTPS_PORT = 8081
CONNECTION_TIMEOUT_SEC = 60
CLOSING_TIMEOUT_SEC = 1
REQUEST_TIMEOUT_SEC = 5

@dataclass
class Delay:
    """
    Represents a delay in a scripted interaction
    """
    sec: float

@dataclass
class Send:
    """
    Represents output bytes in a scripted interaction
    """
    def __init__(self, args):
        self.data = bytes("\r\n".join(args), "utf-8")

@dataclass
class Recv:
    """
    Represents input bytes in a scripted interaction
    """
    def __init__(self, args):
        self.data = bytes("\r\n".join(args), "utf-8")

@dataclass
class Close:
    """
    Represents the connection termination in a scripted interaction
    """

class TestFailure(Exception):
    """
    Class representing the failure of a test
    """

def print_bytes(prefix, data):
    """
    Print a sequence of bytes over multiple lines adding a prefix
    before each line
    """
    print(prefix, f"\\r\\n\n{prefix}".join(data.decode("utf-8").split("\r\n")), sep="")

def run_test(test, addr, port):
    """
    Evaluates the scripted interaction "test" making sure the server
    listening at addr:port behaves as expected
    """

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    conn.connect((addr, port))

    for step in test:
        match step:

            case Delay(amount_ms):
                time.sleep(amount_ms/1000)

            case Send(data=data):
                sent = 0
                while sent < len(data):
                    just_sent = conn.send(data[sent:])
                    if just_sent == 0:
                        break
                    print_bytes("< ", data[sent:sent+just_sent])
                    sent += just_sent

            case Recv(data=data):
                chunks = []
                count = 0
                while count < len(data):
                    chunk = conn.recv(len(data) - count)
                    if chunk == b"":
                        break
                    print_bytes("> ", chunk)
                    chunks.append(chunk)
                    count += len(chunk)
                received = b''.join(chunks)
                if data != received:
                    raise TestFailure(f"Wrong data. Received:\n\t{received}\nExpected:\n\t{data}")

            case Close():
                chunk = conn.recv(1)
                if chunk != b"":
                    raise TestFailure("expected close got some data")

            case _:
                pass


tests = [
    [
        # Test "Connection: Close"
        Send([
            "GET / HTTP/1.1",
            "Connection: Close",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 404 Not Found",
            "Connection: Close",
            "Content-Length: 15       ",
            "",
            "Nothing here :|",
        ]),
        Close(),
    ],
    [
        # Test "Connection: Keep-Alive"
        Send([
            "GET / HTTP/1.1",
            "Connection: Keep-Alive",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 404 Not Found",
            "Connection: Keep-Alive",
            "Content-Length: 15       ",
            "",
            "Nothing here :|",
        ]),
        Send([
            "GET / HTTP/1.1",
            "Connection: Close",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 404 Not Found",
            "Connection: Close",
            "Content-Length: 15       ",
            "",
            "Nothing here :|",
        ]),
        Close(),
    ],
    [
        # Test that the connection header is insensitive to case and whitespace
        Send([
            "GET / HTTP/1.1",
            "Connection:   keEp-ALiVE   ",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 404 Not Found",
            "Connection: Keep-Alive",
            "Content-Length: 15       ",
            "",
            "Nothing here :|",
        ]),
        Send([
            "GET / HTTP/1.1",
            "Connection: closE",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 404 Not Found",
            "Connection: Close",
            "Content-Length: 15       ",
            "",
            "Nothing here :|",
        ]),
        Close(),
    ],
    [
        Send([
            "XXX",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 400 Bad Request",
            "Connection: Close",
            "",
            "",
        ]),
    ],
    [
        Send([
            "GET /hello HTTP/1.1",
            "Connection: Keep-Alive",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 200 OK",
            "Connection: Keep-Alive",
            "Content-Length: 13       ",
            "",
            "Hello, world!",
        ]),
    ],
    [
        # Test request timeout
        Send([
            "GET /hel"
        ]),
        Delay(6),
        Recv([
            "HTTP/1.1 408 Request Timeout",
            "Connection: Close",
            "",
            "",
        ]),
        Close()
    ],
    [
        # Test idle connection timeout
        Delay(6),
        Close()
    ],
    [
        # Test invalid protocol version
        Send([
            "GET /hello HTTP/2",
            "Connection: Keep-Alive",
            "",
            ""
        ]),
        Recv([
            "HTTP/1.1 505 HTTP Version Not Supported",
            "Connection: Keep-Alive",
            "Content-Length: 0        ",
            "",
            "",
        ]),
    ],
    [
        # Send request in pieces
        Send([
            "GET /hello HT",
        ]),
        Delay(1),
        Send([
            "TP/1.1",
            "Connection: Ke",
        ]),
        Delay(1),
        Send([
            "ep-Alive",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 200 OK",
            "Connection: Keep-Alive",
            "Content-Length: 13       ",
            "",
            "Hello, world!",
        ]),
    ],
    [
        # Test pipelining
        Send([
            "GET /hello HTTP/1.1",
            "Connection: Keep-Alive",
            "",
            "GET /hello HTTP/1.1",
            "Connection: Keep-Alive",
            "",
            "",
        ]),
        Recv([
            "HTTP/1.1 200 OK",
            "Connection: Keep-Alive",
            "Content-Length: 13       ",
            "",
            "Hello, world!",
        ]),
        Recv([
            "HTTP/1.1 200 OK",
            "Connection: Keep-Alive",
            "Content-Length: 13       ",
            "",
            "Hello, world!",
        ]),
    ],
]

def main():
    """
    Entry point
    """

    config_file = "test_config.txt"
    with open(config_file, "w", encoding="utf-8") as file:
        file.write(f"""
        log_buff_size_b 1048576 # 1MB
        log_file_limit_b 16777216 # 16MB
        log_dir_limit_mb 25600 # 25GB
        log_dir_path logs
        log_flush_timeout_sec 3
        max_connections 1022
        keep_alive_max_requests 1000
        connection_timeout_sec {CONNECTION_TIMEOUT_SEC}
        closing_timeout_sec {CLOSING_TIMEOUT_SEC}
        request_timeout_sec {REQUEST_TIMEOUT_SEC}
        access_log no
        show_io no
        show_requests no
        http_addr "127.0.0.1"
        http_port {HTTP_PORT}
        https_addr "127.0.0.1"
        https_port {HTTPS_PORT}
        cert_file "cert.pem"
        privkey_file "key.pem"
        """)

    total = 0
    passed = 0

    with subprocess.Popen(['../serve', config_file], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as server_process:
        timeout_sec = 10

        online = False
        start_time = datetime.now()
        while not online:

            elapsed_sec = (datetime.now() - start_time).total_seconds()
            if elapsed_sec >= timeout_sec:
                print("Couldn't connect to server")
                server_process.terminate()
                return 1

            time.sleep(0.5)

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                    conn.connect(("127.0.0.1", HTTP_PORT))
                    online = True
            except ConnectionRefusedError:
                pass
        print("Connected")

        for i, current_test in enumerate(tests):
            try:
                run_test(current_test, "127.0.0.1", HTTP_PORT)
                print("Test", i, "passed\n")
                passed += 1
            except TestFailure as exception:
                print("Test", i, "failed:", exception.with_traceback(None), "\n")
            total += 1
        print("passed: ", passed, "/", total, sep="")
        server_process.terminate()
        server_process.wait()

    if passed < total:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
