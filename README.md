# My Blog Technology
This is a minimal web server designed to host my blog. It's built from scratch to be robust enough to face the public internet. No reverse proxies required! You can see it in action at http://playin.coz.is/index.html.

I asked [Reddit](https://www.reddit.com/r/C_Programming/comments/1falo3b/using_my_c_web_server_to_host_a_blog_you_cant/) to [hack](https://www.reddit.com/r/hacking/comments/1fcc5hd/im_using_my_custom_c_webserver_to_host_my_blog_no/) me, which resulted in gigabytes of hilarious and malicious request logs. I saved some in `attempts.txt`, and may dig out a few more for fun someday :^)

There is also a discussion on [Hacker News](https://news.ycombinator.com/item?id=41642151)

Feel free to help! At this time the main focus is on semantic correctess of HTTP and testing. I try to keep the main branch stable so remember to target the dev branch with PRs. Changes to README are fine to do on main though.

# But.. Why?
I enjoy making my own tools and I'm a bit tired of hearing that everything needs to be "battle-tested." So what it will crash? Bugs can be fixed :^)

# Specs
- Linux only
- Implements HTTP/1.1, pipelining, and keep-alive connections
- HTTPS support (up to TLS 1.2 using BearSSL)
- Minimal dependencies (libc and BearSSL when using HTTPS)
- Configurable timeouts
- Access logs, crash logs, log rotation, disk usage limits
- No `Transfer-Encoding: Chunked` (responds with `411 Length Required`, prompting the client to resend with `Content-Length`)
- Single core (This will probably change when I get a better VPS)
- No static file caching (yet)

# Benchmarks
The focus of the project is robustness, but it's definitely not slow. Here's a quick comparison agains nginx (static endpoint, both single-threaded, 1K connection limit)
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

# Build & Run
By default the server build is HTTP-only:
```
$ make
```
this generates the executables: `serve` (release build), `serve_cov` (coverage build), and `serve_debug` (debug build). Release builds listen on port 80; debug builds on port 8080.

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
The same executables will be generated, but with secure connections on port 443 (release) or 8081 (debug).

Place your `cert.pem` and `key.pem` files in the same directory as the executable. You can customiza names and locations by changing:
```c
#define HTTPS_KEY_FILE  "key.pem"
#define HTTPS_CERT_FILE "cert.pem"
```

For testing locally with HTTPS, generate a self-signed certificate (and private key):
```
openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365
```

# Usage
The server serves static content from the `docroot/` folder. You can change this by modifying the `respond` function:
```c
typedef struct {
	Method method;
	string path;
	int    major;
	int    minor;
	int    nheaders;
	Header headers[MAX_HEADERS];
	string content;
} Request;

void respond(Request request, ResponseBuilder *b)
{
	if (request.major != 1 || request.minor > 1) {
		status_line(b, 505); // HTTP Version Not Supported
		return;
	}

	if (request.method != M_GET) {
		status_line(b, 405); // Method Not Allowed
		return;
	}

	if (string_match_case_insensitive(request.path, LIT("/hello"))) {
		status_line(b, 200);
		append_content_s(b, LIT("Hello, world!"));
		return;
	}

	if (serve_file_or_dir(b, LIT("/"), LIT("docroot/"), request.path, NULLSTR, false))
		return;

	status_line(b, 404);
	append_content_s(b, LIT("Nothing here :|"));
}
```
you can add your endpoints here by switching on the `request.path` field. Note that the path is just a slice into the request buffer. URIs are not parsed.

# Testing
I routinely run the server under valgrind and sanitizers (address, undefined) and target it using `wrk`. I'm also adding automatized tests to `tests/test.py` to check compliance with the HTTP/1.1 spec. I also use it to host my website and post it here and there to keep it under stress.Turns out, all of those bots scanning he internet for vulnerable websites make great fuzzers!

# Known Issues
- Server replies to HTTP/1.0 clients as HTTP/1.1
- Server rejects HEAD requests
