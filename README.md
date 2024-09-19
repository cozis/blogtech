# My Blog Technology
This is a minimal web server designed to serve my blog. I'm writing it to be robust enough to face the public internet. You can see it in action at http://playin.coz.is/index.html (It's running the dev branch).

I asked [Reddit](https://www.reddit.com/r/C_Programming/comments/1falo3b/using_my_c_web_server_to_host_a_blog_you_cant/) to [hack](https://www.reddit.com/r/hacking/comments/1fcc5hd/im_using_my_custom_c_webserver_to_host_my_blog_no/) me, which resulted in gigabytes and gigabytes of very funny and malicious request logs. I copied a couple into `attempts.txt`. Maybe one day I'll go over the logs to get some new ones :^)

# Specs
- Only runs on Linux
- HTTP/1.1 support with pipelining and keep-alive
- Uses request and connection timeouts
- IP blacklist
- Access log, log file rotation, hard disk usage limits
- No `Transfer-Encoding: Chunked` (when receiving a chunked request the server responds with `411 Length Required`, prompting the client to try again with the `Content-Length` header)
- Static file serving utilities
- Single core (This will probably change when I get a better VPS)

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
