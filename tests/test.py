import time
import socket
import subprocess
from typing import Optional
from dataclasses import dataclass

@dataclass
class Delay:
	ms: float

@dataclass
class Send:
	data: bytes
	timeout: Optional[float] = None

@dataclass
class Recv:
	data: bytes
	timeout: Optional[float] = None

@dataclass
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

			case Send(data, timeout):
				sent = 0
				while sent < len(data):
					n = conn.send(data[sent:])
					if n == 0:
						break
					print_bytes("< ", data[sent:sent+n])
					sent += n

			case Recv(data, timeout):
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
		Send(b"GET / HTTP/1.1\r\nConnection: Close\r\n\r\n"),
		Recv(b"HTTP/1.1 404 Not Found\r\nConnection: Close\r\nContent-Length: 15       \r\n\r\nNothing here :|"),
		Close(),
	],
	[
		# Test "Connection: Keep-Alive"
		Send(b"GET / HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n"),
		Recv(b"HTTP/1.1 404 Not Found\r\nConnection: Keep-Alive\r\nContent-Length: 15       \r\n\r\nNothing here :|"),
		Send(b"GET / HTTP/1.1\r\nConnection: Close\r\n\r\n"),
		Recv(b"HTTP/1.1 404 Not Found\r\nConnection: Close\r\nContent-Length: 15       \r\n\r\nNothing here :|"),
		Close(),
	],
	[
		Send(b"XXX\r\n\r\n"),
		Recv(b"HTTP/1.1 400 Bad Request\r\nConnection: Close\r\n\r\n"),
	],
	[
		Send(b"GET /hello HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n"),
		Recv(b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 13       \r\n\r\nHello, world!"),
	],
	[
		# Test request timeout
		Send(b"GET /hel"),
		Delay(6),
		Recv(b"HTTP/1.1 408 Request Timeout\r\nConnection: Close\r\n\r\n"),
		Close()
	],
	[
		# Test idle connection timeout
		Delay(6),
		Close()
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
