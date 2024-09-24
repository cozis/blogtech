# My Blog Technology
This is a minimal web server designed to serve my blog. I'm writing it to be robust enough to face the public internet. You can see it in action at http://playin.coz.is/index.html (It's running the dev branch).

I asked [Reddit](https://www.reddit.com/r/C_Programming/comments/1falo3b/using_my_c_web_server_to_host_a_blog_you_cant/) to [hack](https://www.reddit.com/r/hacking/comments/1fcc5hd/im_using_my_custom_c_webserver_to_host_my_blog_no/) me, which resulted in gigabytes and gigabytes of very funny and malicious request logs. I copied a couple into `attempts.txt`. Maybe one day I'll go over the logs to get some new ones :^)

# Specs
- Only runs on Linux
- HTTP/1.1 support with pipelining and keep-alive
* HTTPS (TLS 1.2 using BearSSL)
- Uses request and connection timeouts
- Access log, log file rotation, hard disk usage limits
- No `Transfer-Encoding: Chunked` (when receiving a chunked request the server responds with `411 Length Required`, prompting the client to try again with the `Content-Length` header)
- Static file serving utilities
- Single core (This will probably change when I get a better VPS)

# Building
By default the server is built without HTTPS and you can do so by doing:
```
$ make
```
this will generate `serve`, `serve_cov`, and `serve_debug`. These are respectively release, coverage, and debug build. Unless you're modifying the source you need to use `serve`.

If you want to enable HTTPS, you'll need to create a `3p` directory (in the same folder as this README) and clone BearSSL in it. Then you'll need to build it.
```
$ mkdir 3p
$ cd 3p
$ git clone https://www.bearssl.org/git/BearSSL
$ cd BearSSL
$ make -j
$ cd ../../
$ make -B HTTPS=1
```
which will produce the same executables but with HTTPS enabled. Your private key `key.pem` and certificate `cert.pem` will need to be stored in the same folder as the executable.

NOTE: If you already built the files and want to build them again with a different HTTPS setting, you'll need to force the build with the `-B` option

# Testing
I routinely run the server under valgrind or sanitizers (address, undefined) and target it using `wrk`. I'm also adding automatized tests to `tests/test.py` to check compliance with the HTTP/1.1 spec.

# Known Issues
- Server replies to HTTP/1.0 clients as HTTP/1.1
