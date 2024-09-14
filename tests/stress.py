import time
import asyncio
import random
import inspect

HOST = "127.0.0.1"
PORT = 8080
NCLIENTS = 100

def print_bytes(prefix, data):
	print(prefix, f"\\r\\n\n{prefix}".join(data.decode("utf-8").split("\r\n")), sep="")

async def start_sending_request_then_close(client_id, reader, writer):

	print(client_id, inspect.currentframe().f_code.co_name)

	writer.write(b"GET /hello HT")
	await writer.drain()

	writer.close()


async def close_while_waiting_response(client_id, reader, writer):

	print(client_id, inspect.currentframe().f_code.co_name)

	writer.write(b"GET /hello HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n")
	await writer.drain()

	writer.close()

async def send_simple_request(client_id, reader, writer):

	print(client_id, inspect.currentframe().f_code.co_name)

	writer.write(b"GET /hello HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n")
	await writer.drain()

	expect = [
		b"HTTP/1.1 200 OK\r\nConnection: Close\r\nContent-Length: 13       \r\n\r\nHello, world!",
		b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 13       \r\n\r\nHello, world!",
	]
	expect.sort(key=lambda e: len(e))

	unexpected = True
	accum = b''
	for res in expect:

		if len(res) > len(accum):
			data = await reader.read(len(res) - len(accum))
			if len(data) == 0:
				return # We were disconnected
			#print_bytes("> ", data)
			accum = accum + data

		if accum == res:
			unexpected = False
			break
	
	if unexpected:
		raise RuntimeError("Unexpected response")


async def send_request_pipeline(client_id, reader, writer):

	print(client_id, inspect.currentframe().f_code.co_name)

	base = b"GET /hello HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n"
	pipeline = base * 300
	print(len(pipeline))

	writer.write(pipeline)
	await writer.drain()

	asyncio.sleep(1)

	writer.close()
	await writer.wait_closed()

actions = [
	send_request_pipeline,
	start_sending_request_then_close,
	close_while_waiting_response,
#	send_simple_request,
]

async def client(client_id):

	reader = None

	while True:
		if reader is None or reader.at_eof():
			#print('Connecting')
			reader, writer = await asyncio.open_connection(HOST, PORT)
		try:
			await asyncio.sleep(0.1)
			await actions[random.randint(0, len(actions)-1)](client_id, reader, writer)
		except ConnectionResetError as e:
			print(e)
	print('Close the connection')
	writer.close()
	await writer.wait_closed()

async def main():
	tasks = []
	for i in range(NCLIENTS):
		tasks.append(asyncio.create_task(client(i)))
	await asyncio.gather(*tasks)

asyncio.run(main())