import time
import socket
import subprocess
import sys
from typing import Optional
from dataclasses import dataclass

@dataclass
class Delay:
    sec: float

class Send:
    def __init__(self, args):
        self.data = bytes("\r\n".join(args), "utf-8")

class Recv:
    def __init__(self, args):
        self.data = bytes("\r\n".join(args), "utf-8")

class Close:
    pass

def print_bytes(prefix, data):
    print(prefix, f"\\r\\n\n{prefix}".join(data.decode("utf-8").split("\r\n")), sep="")

def run_test(test, addr, port):

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    conn.connect((addr, port))

    for step in test:
        match step:

            case Delay(ms):
                time.sleep(ms/1000)

            case Send(data=data):
                sent = 0
                while sent < len(data):
                    n = conn.send(data[sent:])
                    if n == 0:
                        break
                    print_bytes("< ", data[sent:sent+n])
                    sent += n

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
                    raise RuntimeError(f"Wrong data. Received:\n\t{received}\nExpected:\n\t{data}")

            case Close():
                chunk = conn.recv(1)
                if chunk != b"":
                    raise RuntimeError("expected close got some data")

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

p = subprocess.Popen(['../serve_cov'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

time.sleep(0.5)

total = 0
passed = 0
for i, test in enumerate(tests):
    try:
        run_test(test, "127.0.0.1", 8080)
        print("Test", i, "passed\n")
        passed += 1
    except Exception as e:
        print("Test", i, "failed:", e.with_traceback(None), "\n")
    total += 1
print("passed: ", passed, "/", total, sep="")
p.terminate()
p.wait()

if passed < total:
    sys.exit(1)
