# My Blog Technology
This is a minimal web server designed to serve my blog. I'm writing it to be robust enough to face the public internet. You can see it in action at http://playin.coz.is/index.html. You probably can't get it to crash, but feel free to try! And if you manage to do it, send me an email to show off! I'll leave the coolest attempts in `attempts.txt`.

# Specs
- Only runs on Linux
- HTTP/1.1 support with pipelining and keep-alive
* HTTPS (TLS 1.2 using BearSSL)
- Uses request and connection timeouts
- IP blacklist
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

If you want to enable HTTPS, you'll need to create a `3p` directory (in the same folder as this README) and clone BearSSL in it
```
$ mkdir 3p
$ cd 3p
$ git clone https://www.bearssl.org/git/BearSSL
$ cd ..
$ make -B HTTPS=1
```
which will produce the same executables but with HTTPS enabled. Your private key `key.pem` and certificate `cert.pem` will need to be stored in the same folder as the executable.

NOTE: If you already built the files and want to build them again with a different HTTPS setting, you'll need to force the build with the `-B` option

# Testing
I routinely run the server under valgrind or sanitizers (address, undefined) and target it using `wrk`. I'm also adding automatized tests to `tests/test.py` to check compliance with the HTTP/1.1 spec.

# Blocking IPs
To block any number of IP addresses you need to create a `blacklist.txt` file and insert the IPs. You can also add comments:
```
# I'm a comment
10.0.0.1
127.0.0.1 # I'm a comment too
```
Blocked addresses will be rejected after being accepted. This is just a best effort solution as you should block connections using iptables or nftables.

# Known Issues
- Server replies to HTTP/1.0 clients as HTTP/1.1
