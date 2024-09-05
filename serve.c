#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) < (Y) ? (X) : (Y))
#define SIZEOF(X) ((ssize_t) sizeof(X))
#define COUNTOF(X) (SIZEOF(X) / SIZEOF((X)[0]))

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

typedef struct {
	char  *data;
	size_t size;
} Slice;

enum {
    P_OK,
    P_INCOMPLETE,
    P_BADMETHOD,
    P_BADVERSION,
    P_BADHEADER,
};

enum {
    T_CHUNKED  = 1 << 0,
    T_COMPRESS = 1 << 1,
    T_DEFLATE  = 1 << 2,
    T_GZIP     = 1 << 3,
};

typedef enum {
    M_GET,
    M_POST,
    M_HEAD,
    M_PUT,
    M_DELETE,
    M_CONNECT,
    M_OPTIONS,
    M_TRACE,
    M_PATCH,
} Method;

#define MAX_HEADERS 32

typedef struct {
    Slice name;
    Slice value;
} Header;

typedef struct {
    Method method;
    Slice  path;
    int    major;
    int    minor;
    int    nheaders;
    Header headers[MAX_HEADERS];
    Slice  content;
} Request;

bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

int parse_request_head(char *src, size_t len, Request *request)
{
    size_t cur;
    if (len > 2
        && src[0] == 'G'
        && src[1] == 'E'
        && src[2] == 'T') {
        request->method = M_GET;
        cur = 3;
    } else if (len > 3
        && src[0] == 'H'
        && src[1] == 'E'
        && src[2] == 'A'
        && src[3] == 'D') {
        request->method = M_HEAD;
        cur = 4;
    } else if (len > 3
        && src[0] == 'P'
        && src[1] == 'O'
        && src[2] == 'S'
        && src[3] == 'T') {
        request->method = M_POST;
        cur = 4;
    } else if (len > 2
        && src[0] == 'P'
        && src[1] == 'U'
        && src[2] == 'T') {
        request->method = M_PUT;
        cur = 3;
    } else if (len > 5
        && src[0] == 'D'
        && src[1] == 'E'
        && src[2] == 'L'
        && src[3] == 'E'
        && src[4] == 'T'
        && src[5] == 'E') {
        request->method = M_DELETE;
        cur = 6;
    } else if (len > 6
        && src[0] == 'C'
        && src[1] == 'O'
        && src[2] == 'N'
        && src[3] == 'N'
        && src[4] == 'E'
        && src[5] == 'C'
        && src[6] == 'T') {
        request->method = M_CONNECT;
        cur = 7;
    } else if (len > 6
        && src[0] == 'O'
        && src[1] == 'P'
        && src[2] == 'T'
        && src[3] == 'I'
        && src[4] == 'O'
        && src[5] == 'N'
        && src[6] == 'S') {
        request->method = M_OPTIONS;
        cur = 7;
    } else if (len > 4
        && src[0] == 'T'
        && src[1] == 'R'
        && src[2] == 'A'
        && src[3] == 'C'
        && src[4] == 'E') {
        request->method = M_TRACE;
        cur = 5;
    } else if (len > 4
        && src[0] == 'P'
        && src[1] == 'A'
        && src[2] == 'T'
        && src[3] == 'C'
        && src[4] == 'H') {
        request->method = M_PATCH;
        cur = 5;
    } else {
        return P_BADMETHOD;
    }

    if (cur == len || src[cur] != ' ')
        return P_INCOMPLETE;
    cur++;

    // TODO: Make this more robust
    {
        size_t start = cur;
        while (cur < len && src[cur] != ' ')
            cur++;
        request->path.data = src + start;
        request->path.size = cur - start;
    }

    if (cur == len || src[cur] != ' ')
        return P_INCOMPLETE;
    cur++;

    if (cur+4 >= len
        || src[cur+0] != 'H'
        || src[cur+1] != 'T'
        || src[cur+2] != 'T'
        || src[cur+3] != 'P'
        || src[cur+4] != '/'
        || !is_digit(src[cur+5]))
        return P_BADVERSION;
    cur += 5;
    request->major = src[cur] - '0';
    cur++;
    
    if (cur < len && src[cur] == '.') {
        cur++;
        if (cur == len || !is_digit(src[cur]))
            return P_BADVERSION;
        request->minor = src[cur] - '0';
        cur++;
    } else {
        request->minor = 0;
    }

    if (cur+1 >= len
        || src[cur+0] != '\r'
        || src[cur+1] != '\n')
        return P_INCOMPLETE;
    cur += 2;

    request->nheaders = 0;
    while (cur+1 >= len
        || src[cur+0] != '\r'
        || src[cur+1] != '\n') {
        
        Slice name;
        Slice value;

        size_t start = cur;

        // TODO: More robust
        while (cur < len && src[cur] != ':')
            cur++;
        
        name.data = src + start;
        name.size = cur - start;

        if (cur == len)
            return P_BADHEADER;
        cur++; // :

        // TODO: More robust
        start = cur;
        while (cur < len && src[cur] != '\r')
            cur++;
        value.data = src + start;
        value.size = cur - start;

        cur++; // \r
        if (cur == len || src[cur] != '\n')
            return P_BADHEADER;
        cur++; // \n

        if (request->nheaders < MAX_HEADERS) {
            request->headers[request->nheaders].name = name;
            request->headers[request->nheaders].value = value;
            request->nheaders++;
        }
    }
    cur += 2; // \r\n
    return P_OK;
}

char to_lower(char c)
{
    if (c >= 'A' || c <= 'Z')
        return c - 'A' + 'a';
    else
        return c;
}

bool string_match_case_insensitive(Slice x, Slice y)
{
    if (x.size != y.size)
        return false;
    for (size_t i = 0; i < x.size; i++)
        if (to_lower(x.data[i]) != to_lower(y.data[i]))
            return false;
    return true;
}

Slice str_to_slice(char *str)
{
    return (Slice) {.data=str, .size=strlen(str)};
}

bool match_header_name(Slice s1, char *s2)
{
    return string_match_case_insensitive(s1, str_to_slice(s2));
}

Slice trim(Slice s)
{
    size_t cur = 0;
    while (cur < s.size && is_space(s.data[cur]))
        cur++;
    
    if (cur == s.size) {
        s.data = "";
        s.size = 0;
    } else {
        while (is_space(s.data[s.size-1]))
            s.size--;
    }
    return s;
}

bool match_header_value(Slice s1, char *s2)
{
    Slice x = trim(s1);
    Slice y = trim(str_to_slice(s2));
    return string_match_case_insensitive(x, y);
}

bool find_header(Request *request, char *name, Slice *value)
{
    for (int i = 0; i < request->nheaders; i++)
        if (match_header_name(request->headers[i].name, name)) {
            *value = request->headers[i].value;
            return true;
        }
    return false;
}

const char *get_status_string(int status)
{
	switch(status)
	{
		case 100: return "Continue";
		case 101: return "Switching Protocols";
		case 102: return "Processing";

		case 200: return "OK";
		case 201: return "Created";
		case 202: return "Accepted";
		case 203: return "Non-Authoritative Information";
		case 204: return "No Content";
		case 205: return "Reset Content";
		case 206: return "Partial Content";
		case 207: return "Multi-Status";
		case 208: return "Already Reported";

		case 300: return "Multiple Choices";
		case 301: return "Moved Permanently";
		case 302: return "Found";
		case 303: return "See Other";
		case 304: return "Not Modified";
		case 305: return "Use Proxy";
		case 306: return "Switch Proxy";
		case 307: return "Temporary Redirect";
		case 308: return "Permanent Redirect";

		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 402: return "Payment Required";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 406: return "Not Acceptable";
		case 407: return "Proxy Authentication Required";
		case 408: return "Request Timeout";
		case 409: return "Conflict";
		case 410: return "Gone";
		case 411: return "Length Required";
		case 412: return "Precondition Failed";
		case 413: return "Request Entity Too Large";
		case 414: return "Request-URI Too Long";
		case 415: return "Unsupported Media Type";
		case 416: return "Requested Range Not Satisfiable";
		case 417: return "Expectation Failed";
		case 418: return "I'm a teapot";
		case 420: return "Enhance your calm";
		case 422: return "Unprocessable Entity";
		case 426: return "Upgrade Required";
		case 429: return "Too many requests";
		case 431: return "Request Header Fields Too Large";
		case 449: return "Retry With";
		case 451: return "Unavailable For Legal Reasons";

		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		case 504: return "Gateway Timeout";
		case 505: return "HTTP Version Not Supported";
		case 509: return "Bandwidth Limit Exceeded";
	}
	return "???";
}

size_t parse_content_length(Slice s)
{
    char  *src = s.data;
    size_t len = s.size;

    size_t cur = 0;
    while (cur < len && is_space(src[cur]))
        cur++;
    
    if (cur == len || !is_digit(src[cur]))
        return -1;

    size_t x = 0;
    do {
        int d = src[cur] - '0';
        if (x > (SIZE_MAX - d) / 10)
            return -1;
        x = x * 10 + d;
        cur++;
    } while (cur < len && is_digit(src[cur]));

    while (cur < len && is_space(src[cur]))
        cur++;
    
    if (cur != len)
        return -1;
    
    return x;
}

int find_and_parse_transfer_encoding(Request *request)
{
    Slice value;
    if (!find_header(request, "Transfer-Encoding", &value))
        return 0;
    
    int res = 0;
    char  *src = value.data;
    size_t len = value.size;
    size_t cur = 0;
    for (;;) {
        
        while (cur < len && (is_space(src[cur]) || src[cur] == ','))
            cur++;
        
        if (cur+6 < len
            && src[cur+0] == 'c'
            && src[cur+1] == 'h'
            && src[cur+2] == 'u'
            && src[cur+3] == 'n'
            && src[cur+4] == 'k'
            && src[cur+5] == 'e'
            && src[cur+6] == 'd') {
            cur += 7;
            res |= T_CHUNKED;
        } else if (cur+7 < len
            && src[cur+0] == 'c'
            && src[cur+1] == 'o'
            && src[cur+2] == 'm'
            && src[cur+3] == 'p'
            && src[cur+4] == 'r'
            && src[cur+5] == 'e'
            && src[cur+6] == 's'
            && src[cur+7] == 's') {
            cur += 8;
            res |= T_COMPRESS;
        } else if (cur+6 < len
            && src[cur+0] == 'd'
            && src[cur+1] == 'e'
            && src[cur+2] == 'f'
            && src[cur+3] == 'l'
            && src[cur+4] == 'a'
            && src[cur+5] == 't'
            && src[cur+6] == 'e') {
            cur += 7;
            res |= T_DEFLATE;
        } else if (cur+3 < len
            && src[cur+0] == 'g'
            && src[cur+1] == 'z'
            && src[cur+2] == 'i'
            && src[cur+3] == 'p') {
            cur += 4;
            res |= T_GZIP;
        } else {
            return -1;
        }
    }
    return res;
}

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

typedef struct {
    char  *data;
    size_t head;
    size_t size;
    size_t capacity;
} ByteQueue;

typedef struct Connection Connection;
struct Connection {
	ByteQueue input;
	ByteQueue output;
};

#define MAX_CONNECTIONS 1024
struct pollfd pollarray[MAX_CONNECTIONS+1];
Connection conns[MAX_CONNECTIONS];

void init_globals(void)
{
	for (int i = 0; i < MAX_CONNECTIONS; i++) {
		pollarray[i].fd = -1;
		pollarray[i].events = 0;
		pollarray[i].revents = 0;
	}
}

void byte_queue_init(ByteQueue *q)
{
    q->data = NULL;
    q->head = 0;
    q->size = 0;
    q->capacity = 0;
}

void byte_queue_free(ByteQueue *q)
{
    free(q->data);
}

size_t byte_queue_used_space(ByteQueue *q)
{
    return q->size;
}

size_t byte_queue_free_space(ByteQueue *q)
{
    return q->capacity - q->size - q->head;
}

bool byte_queue_ensure_min_free_space(ByteQueue *q, size_t num)
{
    size_t total_free_space = q->capacity - q->size;
    size_t free_space_after_data = q->capacity - q->size - q->head;

    if (free_space_after_data < num) {
        if (total_free_space < num) {
            // Resize required

            size_t capacity = 2 * q->capacity;
            if (capacity - q->size < num) capacity = q->size + num;

            char *data = malloc(capacity);
            if (!data) return false;

            if (q->size > 0)
                memcpy(data, q->data + q->head, q->size);

            free(q->data);
            q->data = data;
            q->capacity = capacity;

        } else {
            // Move required
            memmove(q->data, q->data + q->head, q->size);
            q->head = 0;
        }
    }

    return true;
}

char *byte_queue_start_write(ByteQueue *q)
{
    return q->data + q->head + q->size;
}

void byte_queue_end_write(ByteQueue *q, size_t num)
{
    q->size += num;
}

char *byte_queue_start_read(ByteQueue *q)
{
    return q->data + q->head;
}

void byte_queue_end_read(ByteQueue *q, size_t num)
{
    q->head += num;
    q->size -= num;
}

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

static bool set_blocking(int fd, bool blocking)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags == -1)
		return false;

	if (blocking) flags &= ~O_NONBLOCK;
	else          flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags))
		return false;

	return true;
}

void print_bytes(const char *prefix, const char *str, size_t len)
{
	FILE *stream = stdout;

	bool line_start = true;

	size_t i = 0;
	while (i < len) {

		size_t substr_offset = i;
		while (i < len && str[i] != '\r' && str[i] != '\n')
			i++;
		size_t substr_length = i - substr_offset;

		if (line_start) {
			fprintf(stream, "%s", prefix);
			line_start = false;
		}

		fwrite(str + substr_offset, 1, substr_length, stream);

		if (i < len) {
			if (str[i] == '\r')
				fprintf(stream, "\\r");
			else {
				fprintf(stream, "\\n\n");
				line_start = true;
			}
			i++;
		}
	}
}

void respond(Request request, ByteQueue *output);

int main(int argc, char **argv)
{
	init_globals();

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		return -1;
	}

	if (!set_blocking(listen_fd, false)) {
		perror("fcntl");
		return -1;
	}

	int one = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*) &one, sizeof(one));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8080);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr))) {
		perror("bind");
		return -1;
	}

	if (listen(listen_fd, 32)) {
		perror("listen");
		return -1;
	}

	pollarray[0].fd = listen_fd;
	pollarray[0].events = POLLIN;

	while (1) {
		int ret = poll(pollarray, MAX_CONNECTIONS, -1);
		if (ret < 0) {
			if (errno == EINTR)
				break;
			perror("poll");
			return -1;
		}

		if (pollarray[0].revents) {
			for (;;) {

				// Look for a connection structure
				int free_index = 0;
				while (free_index < MAX_CONNECTIONS && pollarray[free_index].fd != -1)
					free_index++;
				if (free_index == MAX_CONNECTIONS) {
					pollarray[0].events &= ~POLLIN; // Stop listening for incoming connections
					break;
				}

				int accepted_fd = accept(listen_fd, NULL, NULL);
				if (accepted_fd < 0) {
					if (errno == EINTR)
						continue;
					if (errno == EAGAIN || errno == EWOULDBLOCK)
						break;
					perror("accept");
					return -1;
				}
				if (!set_blocking(accepted_fd, false)) {
					perror("fcntl");
					return -1;
				}

				pollarray[free_index].fd = accepted_fd;
				pollarray[free_index].events = POLLIN;
				pollarray[free_index].revents = 0;
				byte_queue_init(&conns[free_index-1].input);
				byte_queue_init(&conns[free_index-1].output);
			}
		}

		for (int i = 1; i-1 < MAX_CONNECTIONS; i++) {

			if (pollarray[i].fd == -1)
				continue;

			Connection *conn = &conns[i-1];
			bool remove = false;

			if (pollarray[i].revents & POLLIN) {

				for (;;) {

					if (!byte_queue_ensure_min_free_space(&conn->input, 512)) {
						printf("Out of memory\n");
						abort();
					}

					char  *dst = byte_queue_start_write(&conn->input);
					size_t max = byte_queue_free_space(&conn->input);

					int num = recv(pollarray[i].fd, dst, max, 0);
					if (num < 0) {
						if (errno == EINTR)
							continue;
						if (errno == EAGAIN || errno == EWOULDBLOCK)
							break;
						remove = true;
						break;
					}
					if (num == 0) {
						remove = true;
						break;
					}

					//print_bytes("> ", dst, num);

					byte_queue_end_write(&conn->input, (size_t) num);
				}
				
				if (!remove) {

					for (;;) { /* Respond loop start */

						char  *src = byte_queue_start_read(&conn->input);
						size_t len = byte_queue_used_space(&conn->input);

						// Look for the \r\n\r\n
						size_t j = 0;
						while (j+3 < len && (src[j] != '\r' || src[j+1] != '\n' || src[j+2] != '\r' || src[j+3] != '\n'))
							j++;
						if (j+3 >= len)
							break;
						size_t head_length = j+4;

						//print_bytes("REQUEST | ", src, head_length);

						// Found! We got the request head
						Request request;
						int res = parse_request_head(src, head_length, &request);
						if (res != P_OK) {
							// TODO
							printf("Couldn't parse request\n");
							abort();
						}

						Slice content_length_header;
						size_t content_length;
						if (!find_header(&request, "Content-Length", &content_length_header)) {
							content_length = 0;
						} else {
							content_length = parse_content_length(content_length_header);
						}

						if (content_length == (size_t) -1) {
							// TODO
							printf("Invalid Content-Length\n");
							abort();
						} else {
							size_t request_length = head_length + content_length;
							if (len >= request_length) {
								// Respond
								respond(request, &conn->output);
								byte_queue_end_read(&conn->input, request_length);
								if (byte_queue_used_space(&conn->output) > 0) {
									pollarray[i].events |= POLLOUT;
								}
							}
						}
					} /* Respond loop end */
				}
			}

			if (!remove && (pollarray[i].revents & POLLOUT)) {
				for (;;) {
					char  *src = byte_queue_start_read(&conn->output);
					size_t len = byte_queue_used_space(&conn->output);

					if (len == 0) {
						pollarray[i].events &= ~POLLOUT;
						break;
					}

					int num = send(pollarray[i].fd, src, len, 0);
					if (num < 0) {
						if (errno == EINTR)
							continue;
						if (errno == EAGAIN || errno == EWOULDBLOCK)
							break;
						perror("send");
						return -1;
					}

					//print_bytes("< ", src, num);

					byte_queue_end_read(&conn->output, (size_t) num);
				}
			}

			pollarray[i].revents = 0;

			if (remove) {
				close(pollarray[i].fd);
				pollarray[i].fd = -1;
				pollarray[i].events = 0;
				byte_queue_free(&conn->input);
				byte_queue_free(&conn->output);
			}
		}
	}

	close(listen_fd);
	return 0;
}

void respond(Request request, ByteQueue *output)
{
	char buffer[1<<10];
	int num = snprintf(buffer, sizeof(buffer), "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello!");
	assert(num > 0);

	if (!byte_queue_ensure_min_free_space(output, num)) {
		printf("Out of memory\n");
		abort();
	}

	char *dst = byte_queue_start_write(output);
	
	memcpy(dst, buffer, num);

	byte_queue_end_write(output, num);
}
