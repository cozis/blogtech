# My Blog Technology
This is a minimal web server designed to serve my blog. I'm writing it to be robust enough to face the public internet. You can see it in action at http://playin.coz.is/index.html (It's running the dev branch).

I asked [Reddit](https://www.reddit.com/r/C_Programming/comments/1falo3b/using_my_c_web_server_to_host_a_blog_you_cant/) to [hack](https://www.reddit.com/r/hacking/comments/1fcc5hd/im_using_my_custom_c_webserver_to_host_my_blog_no/) me, which resulted in gigabytes and gigabytes of very funny and malicious request logs. I copied a couple into `attempts.txt`. Maybe one day I'll go over the logs to get some new ones :^)

# Specs
- Only Linux is supported
- Implements HTTP/1.1, pipelining, and keep-alive connections
- HTTPS (up to TLS 1.2 using BearSSL)
- Minimal dependencies (libc and BearSSL when using HTTPS)
- Configurable timeouts
- Access log, crash log, log file rotation, hard disk usage limits
- No `Transfer-Encoding: Chunked` (when receiving a chunked request the server responds with `411 Length Required`, prompting the client to try again with the `Content-Length` header)
- Single core (This will probably change when I get a better VPS)
- No static file caching (yet)

# Benchmarks
The focus of the server is robustness, but it's definitely not slow. Here's a quick compatison agains nginx (static endpoint, both single-threaded, 1K connection limit)
```
(blogtech)
$ wrk -c 500 -d 5s http://127.0.0.1:80/hello
Running 5s test @ http://127.0.0.1:80/hello
  2 threads and 500 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     6.66ms    3.71ms  48.87ms   92.30%
    Req/Sec    39.59k     6.43k   50.60k    67.35%
  385975 requests in 5.01s, 30.55MB read
Requests/sec:  76974.24
Transfer/sec:      6.09MB

(nginx)
$ wrk -c 500 -d 5s http://127.0.0.1:8080/hello
Running 5s test @ http://127.0.0.1:8080/hello
  2 threads and 500 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   149.11ms  243.02ms 934.12ms   81.80%
    Req/Sec    24.97k    16.87k   57.73k    61.11%
  224790 requests in 5.08s, 42.01MB read
Requests/sec:  44227.78
Transfer/sec:      8.27MB
```

Nginx uses this configuration:
```
worker_processes 1;

events {
	worker_connections 1024;
}

http {
	server {
		listen 8080;
		location /hello {
			add_header Content-Type text/plain;
			return 200 "Hello, world!";
		}
	}
}
```

# Build and run
By default the server build is HTTP-only:
```
$ make
```
this will generate the executables `serve` (release build), `serve_cov` (coverage build), and `serve_debug` (debug build).

To enable HTTPS, you'll need to clone BearSSL and build it. You can do so by running these commands from the root folder of this repository:
```
$ mkdir 3p
$ cd 3p
$ git clone https://www.bearssl.org/git/BearSSL
$ cd BearSSL
$ make -j
$ cd ../../
$ make -B HTTPS=1
```
which will produce the usual executables with HTTPS enabled. The HTTPS server will continue serving HTTP content on port 80.

The Certificate "cert.pem" and private key "key.pem" need to be placed in the same directory as the executable. You can change their default name and/or location by modifying the symbols
```
#define HTTPS_KEY_FILE  "key.pem"
#define HTTPS_CERT_FILE "cert.pem"
```
If you just want to test the HTTPS server locally, you can use a self-signed certificate. First, generate a private key:
```
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
```
then the certificate:
```
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```
when sending requests with curl or similar tools you'll need to allow self-signed certificated.

# Testing
I routinely run the server under valgrind or sanitizers (address, undefined) and target it using `wrk`. I'm also adding automatized tests to `tests/test.py` to check compliance with the HTTP/1.1 spec.

# Known Issues
- Server replies to HTTP/1.0 clients as HTTP/1.1
