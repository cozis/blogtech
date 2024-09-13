# My Blog Technology
This is a minimal web server designed to serve my blog. I'm writing it to be robust enough to face the public internet. You can see it in action at http://playin.coz.is/index.html. You probably can't get it to crash, but feel free to try! And if you manage to do it, send me an email to show off! I'll leave the coolest attempts in `attempts.txt`.

# Specs
- Linux only
- HTTP/1.1 + pipelining + keep-alive
- Request and connection deadlines
- No `Transfer-Encoding: Chunked` (when receiving a chunked request the server responds with `411 Length Required`, prompting the client to try again with the `Content-Length` header)
- Static file serving utilities
- Single core (This will probably change when I get a better VPS)

# How I test it
I'm still testing manually. I usually stress test the server locally using `wrk` and see if it breaks. I also test it under `valgrind` and sanitizers.

# Known issues:
- When idle connections timeout, the server sends 411
- Server tries to keep connections alive even when peer sends `Connection: Close`
- Server replies to HTTP/1.0 clients as HTTP/1.1
- Since poll is edge triggered, when the server is full and can't accept all new connections the remaining ones are left waiting until some other event wakes up poll()