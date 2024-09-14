#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>

#ifdef RELEASE
#define PORT 80
#define LOG_DIRECTORY_SIZE_LIMIT_MB (25 * 1024)
#define MAX_CONNECTIONS 1024
#else
#define PORT 8080
#define LOG_DIRECTORY_SIZE_LIMIT_MB 10
#define MAX_CONNECTIONS 32
#endif

#define SHOW_IO 0
#define SHOW_REQUESTS 0
#define REQUEST_TIMEOUT_SEC 5
#define CLOSING_TIMEOUT_SEC 2
#define CONNECTION_TIMEOUT_SEC 60
#define LOG_BUFFER_SIZE (1<<20)
#define LOG_BUFFER_LIMIT (1<<24)
#define LOG_FLUSH_TIMEOUT_SEC 3
#define INPUT_BUFFER_LIMIT_MB 1

#ifndef NDEBUG
#define DEBUG(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#else
#define DEBUG(...) {}
#endif

static_assert(LOG_BUFFER_SIZE < LOG_BUFFER_LIMIT, "");

typedef struct {
	char  *data;
	size_t size;
} string;

#define LIT(S) (string) {.data=(S), .size=sizeof(S)-1}
#define STR(S) (string) {.data=(S), .size=strlen(S)}
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) < (Y) ? (X) : (Y))
#define SIZEOF(X) ((ssize_t) sizeof(X))
#define COUNTOF(X) (SIZEOF(X) / SIZEOF((X)[0]))
#define NULLSTR (string) {.data=NULL, .size=0}

void log_init(void);
void log_free(void);
void log_data(string str);
void log_fatal(string str);
void log_perror(string str);
void log_format(const char *fmt, ...);
void log_flush(void);
bool log_empty(void);

uint64_t get_current_time_ms(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret) log_fatal(LIT("Couldn't read time\n"));

	if ((uint64_t) ts.tv_sec > UINT64_MAX / 1000)
		log_fatal(LIT("Time overflow\n"));
	uint64_t ms = ts.tv_sec * 1000;

	uint64_t nsec_part = ts.tv_nsec / 1000000;
	if (ms > UINT64_MAX - nsec_part)
		log_fatal(LIT("Time overflow\n"));
	ms += nsec_part;
	return ms;
}

void *mymalloc(size_t num)
{
	return malloc(num);
}

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

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
    string name;
    string value;
} Header;

typedef struct {
    Method method;
    string path;
    int    major;
    int    minor;
    int    nheaders;
    Header headers[MAX_HEADERS];
    string content;
} Request;

bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

bool is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool startswith(string prefix, string str)
{
	if (prefix.size > str.size)
		return false;
	// TODO: What is prefix.data==NULL or str.data==NULL?
	return !memcmp(prefix.data, str.data, prefix.size);
}

bool endswith(string suffix, string name)
{
	char *tail = name.data + (name.size - suffix.size);
	return suffix.size <= name.size && !memcmp(tail, suffix.data, suffix.size);
}

int parse_request_head(string str, Request *request)
{
	char  *src = str.data;
    size_t len = str.size;

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
		
		string name;
		string value;

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
	// cur here points to the \r in \r\n
	return P_OK;
}

char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    else
        return c;
}

bool string_match_case_insensitive(string x, string y)
{
    if (x.size != y.size)
        return false;
    for (size_t i = 0; i < x.size; i++)
        if (to_lower(x.data[i]) != to_lower(y.data[i]))
            return false;
    return true;
}

bool match_header_name(string s1, string s2)
{
    return string_match_case_insensitive(s1, s2);
}

string trim(string s)
{
    size_t cur = 0;
    while (cur < s.size && is_space(s.data[cur]))
        cur++;

    if (cur == s.size) {
        s.data = "";
        s.size = 0;
    } else {
		s.data += cur;
		s.size -= cur;
        while (is_space(s.data[s.size-1]))
            s.size--;
    }
    return s;
}

string substr(string str, size_t start, size_t end)
{
	return (string) {
		.data = str.data + start,
		.size = end - start,
	};
}

bool match_header_value(string s1, string s2)
{
    return string_match_case_insensitive(trim(s1), trim(s2));
}

bool find_header(Request *request, string name, string *value)
{
    for (int i = 0; i < request->nheaders; i++)
        if (match_header_name(request->headers[i].name, name)) {
            *value = request->headers[i].value;
            return true;
        }
    return false;
}

string get_status_string(int status)
{
	switch(status)
	{
		case 100: return LIT("Continue");
		case 101: return LIT("Switching Protocols");
		case 102: return LIT("Processing");

		case 200: return LIT("OK");
		case 201: return LIT("Created");
		case 202: return LIT("Accepted");
		case 203: return LIT("Non-Authoritative Information");
		case 204: return LIT("No Content");
		case 205: return LIT("Reset Content");
		case 206: return LIT("Partial Content");
		case 207: return LIT("Multi-Status");
		case 208: return LIT("Already Reported");

		case 300: return LIT("Multiple Choices");
		case 301: return LIT("Moved Permanently");
		case 302: return LIT("Found");
		case 303: return LIT("See Other");
		case 304: return LIT("Not Modified");
		case 305: return LIT("Use Proxy");
		case 306: return LIT("Switch Proxy");
		case 307: return LIT("Temporary Redirect");
		case 308: return LIT("Permanent Redirect");

		case 400: return LIT("Bad Request");
		case 401: return LIT("Unauthorized");
		case 402: return LIT("Payment Required");
		case 403: return LIT("Forbidden");
		case 404: return LIT("Not Found");
		case 405: return LIT("Method Not Allowed");
		case 406: return LIT("Not Acceptable");
		case 407: return LIT("Proxy Authentication Required");
		case 408: return LIT("Request Timeout");
		case 409: return LIT("Conflict");
		case 410: return LIT("Gone");
		case 411: return LIT("Length Required");
		case 412: return LIT("Precondition Failed");
		case 413: return LIT("Request Entity Too Large");
		case 414: return LIT("Request-URI Too Long");
		case 415: return LIT("Unsupported Media Type");
		case 416: return LIT("Requested Range Not Satisfiable");
		case 417: return LIT("Expectation Failed");
		case 418: return LIT("I'm a teapot");
		case 420: return LIT("Enhance your calm");
		case 422: return LIT("Unprocessable Entity");
		case 426: return LIT("Upgrade Required");
		case 429: return LIT("Too many requests");
		case 431: return LIT("Request Header Fields Too Large");
		case 449: return LIT("Retry With");
		case 451: return LIT("Unavailable For Legal Reasons");

		case 500: return LIT("Internal Server Error");
		case 501: return LIT("Not Implemented");
		case 502: return LIT("Bad Gateway");
		case 503: return LIT("Service Unavailable");
		case 504: return LIT("Gateway Timeout");
		case 505: return LIT("HTTP Version Not Supported");
		case 509: return LIT("Bandwidth Limit Exceeded");
	}
	return LIT("???");
}

size_t parse_content_length(string s)
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
    string value;
    if (!find_header(request, LIT("Transfer-Encoding"), &value))
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
	byte_queue_init(q);
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

            char *data = mymalloc(capacity);
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

string byte_queue_start_write(ByteQueue *q)
{
    return (string) {
		.data = q->data     + q->head + q->size,
		.size = q->capacity - q->head - q->size,
	};
}

void byte_queue_end_write(ByteQueue *q, size_t num)
{
    q->size += num;
}

string byte_queue_start_read(ByteQueue *q)
{
	return (string) {
		.data = q->data + q->head,
		.size = q->size,
	};
}

size_t byte_queue_size(ByteQueue *q)
{
	return q->size;
}

void byte_queue_end_read(ByteQueue *q, size_t num)
{
    q->head += num;
    q->size -= num;
}

bool byte_queue_write(ByteQueue *q, string src)
{
	if (!byte_queue_ensure_min_free_space(q, src.size))
		return false;
	string dst = byte_queue_start_write(q);
	assert(dst.size >= src.size);
	memcpy(dst.data, src.data, src.size);
	byte_queue_end_write(q, src.size);
	return true;
}

void byte_queue_patch(ByteQueue *q, size_t offset, char *src, size_t len)
{
	// TODO: Safety checks
	memcpy(q->data + q->head + offset, src, len);
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

void print_bytes(string prefix, string str)
{
	char  *src = str.data;
	size_t len = str.size;

	bool line_start = true;

	size_t i = 0;
	while (i < len) {

		size_t substr_offset = i;
		while (i < len && src[i] != '\r' && src[i] != '\n')
			i++;
		size_t substr_length = i - substr_offset;

		if (line_start) {
			log_data(prefix);
			line_start = false;
		}

		log_data((string) { src + substr_offset, substr_length });

		if (i < len) {
			if (src[i] == '\r')
				log_data(LIT("\\r"));
			else {
				log_data(LIT("\\n\n"));
				line_start = true;
			}
			i++;
		}
	}

	if (!line_start)
		log_data(LIT("\n"));
}

typedef struct {
	ByteQueue input;
	ByteQueue output;
	int served_count;
	bool closing;
	bool keep_alive;
	uint64_t creation_time;
	uint64_t start_time;
} Connection;

typedef enum {
	R_STATUS,
	R_HEADER,
	R_CONTENT,
	R_COMPLETE,
} ResponseBuilderState;

typedef struct {
	ResponseBuilderState state;
	Connection *conn;
	bool failed;
	bool keep_alive;
	size_t content_length_offset;
	size_t content_offset;
} ResponseBuilder;

void response_builder_init(ResponseBuilder *b, Connection *conn)
{
	b->state = R_STATUS;
	b->conn = conn;
	b->failed = false;
	b->keep_alive = true;
	b->content_length_offset = -1;
	b->content_offset = -1;
}

void status_line(ResponseBuilder *b, int status)
{
	if (b->state != R_STATUS)
		log_fatal(LIT("Appending status line twice\n"));
	if (!b->failed) {
		char buf[1<<10];
		string status_string = get_status_string(status);
		int num = snprintf(buf, sizeof(buf), "HTTP/1.1 %d %.*s\r\n", status, (int) status_string.size, status_string.data);
		assert(num > 0);
		if (!byte_queue_write(&b->conn->output, (string) {buf, num}))
			b->failed = true;
	}
	b->state = R_HEADER;
}

void add_header(ResponseBuilder *b, string header)
{
	if (b->state != R_HEADER) {
		if (b->state == R_STATUS)
			log_fatal(LIT("Didn't write status line before headers\n"));
		else
			log_fatal(LIT("Can't add headers after content\n"));
	}
	if (b->failed)
		return;
	if (!byte_queue_write(&b->conn->output, header) ||
		!byte_queue_write(&b->conn->output, LIT("\r\n"))) {
		b->failed = true;
		return;
	}
}

void add_header_f(ResponseBuilder *b, const char *fmt, ...)
{
	char buffer[1<<10];

	va_list args;
	va_start(args, fmt);
	int num = vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	if (num < 0 || num >= (int) sizeof(buffer)) {
		b->failed = true;
		return;
	}

	buffer[num] = '\0';

	add_header(b, (string) {buffer, num});
}

bool should_keep_alive(Connection *conn);

uint64_t now;

void append_special_headers(ResponseBuilder *b)
{
	if (should_keep_alive(b->conn))
		add_header(b, LIT("Connection: Keep-Alive"));
	else {
		add_header(b, LIT("Connection: Close"));
		b->conn->closing = true;
		b->conn->start_time = now;
		// TODO: Stop monitoring POLLIN
	}

	b->content_length_offset = byte_queue_size(&b->conn->output) + sizeof("Content-Length: ") - 1;
	add_header(b, LIT("Content-Length:          "));
	if (!byte_queue_write(&b->conn->output, LIT("\r\n")))
		b->failed = true;
	b->content_offset = byte_queue_size(&b->conn->output);
}

void append_content_s(ResponseBuilder *b, string str)
{
	if (b->state == R_HEADER) {
		append_special_headers(b);
		b->state = R_CONTENT;
	}
	if (b->state != R_CONTENT)
		log_fatal(LIT("Invalid response builder state\n"));

	if (b->failed)
		return;

	if (!byte_queue_write(&b->conn->output, str)) {
		b->failed = true;
		return;
	}
}

string append_content_start(ResponseBuilder *b, size_t cap)
{
	if (b->state == R_HEADER) {
		append_special_headers(b);
		b->state = R_CONTENT;
	}
	if (b->state != R_CONTENT)
		log_fatal(LIT("Invalid response builder state\n"));

	if (b->failed)
		return NULLSTR;

	if (!byte_queue_ensure_min_free_space(&b->conn->output, cap)) {
		b->failed = true;
		return NULLSTR;
	}
	return byte_queue_start_write(&b->conn->output);
}

void append_content_end(ResponseBuilder *b, size_t num)
{
	byte_queue_end_write(&b->conn->output, num);
}

void append_content_f(ResponseBuilder *b, const char *fmt, ...)
{
	size_t cap = 128;

	for (;;) {

		string dst = append_content_start(b, cap);
		if (dst.size == 0)
			return;

		va_list args;
		va_start(args, fmt);

		int num = vsnprintf(dst.data, dst.size, fmt, args);
		assert(num >= 0);

		va_end(args);

		if ((size_t) num < cap) {
			append_content_end(b, num);
			break;
		}

		cap *= 2;
	}
}

void response_builder_complete(ResponseBuilder *b)
{
	if (b->state == R_COMPLETE)
		return;

	if (b->failed)
		return;

	if (b->state == R_HEADER) {
		append_special_headers(b);
		if (b->failed) return;
	} else {
		if (b->state != R_CONTENT)
			log_fatal(LIT("Invalid response builder state\n"));
	}
	size_t current_offset = byte_queue_size(&b->conn->output);
	size_t content_length = current_offset - b->content_offset;

	if (content_length > 1<<30) {
		// Content larger than 1GB
		b->failed = true;
		return;
	}
	int content_length_int = (int) content_length;

	char content_length_string[128];
	int n = snprintf(content_length_string, sizeof(content_length_string), "%d", content_length_int);
	assert(n >= 1 && n <= 9);

	byte_queue_patch(&b->conn->output, b->content_length_offset, content_length_string, n);

	b->state = R_COMPLETE;
}

void respond(Request request, ResponseBuilder *b);

struct pollfd pollarray[MAX_CONNECTIONS+1];
Connection conns[MAX_CONNECTIONS];
int num_conns = 0;

bool should_keep_alive(Connection *conn)
{
	// Don't keep alive if the peer doesn't want to
	if (conn->keep_alive == false)
		return false;

	// Don't keep alive if the request is too old
	if (now - conn->creation_time > CONNECTION_TIMEOUT_SEC * 1000)
		return false;

	// Don't keep alive if we served a lot of requests to this connection
	if (conn->served_count > 100)
		return false;

	// Don't keep alive if the server is more than 70% full
	if (num_conns > 0.7 * MAX_CONNECTIONS)
		return false;

	return true;
}

uint64_t deadline_of(Connection *conn)
{
	return conn->start_time + (conn->closing ? CLOSING_TIMEOUT_SEC : REQUEST_TIMEOUT_SEC) * 1000;
}

volatile sig_atomic_t stop = 0;

void handle_sigterm(int signum) 
{
	(void) signum;
	stop = 1;
}

bool respond_to_available_requests(struct pollfd *polldata, Connection *conn)
{
	bool remove = false;

	int pipeline_count = 0;
	while (!remove) { /* Respond loop start */

		string src = byte_queue_start_read(&conn->input);

		// Look for the \r\n\r\n
		size_t j = 0;
		while (j+3 < src.size && (src.data[j] != '\r' || src.data[j+1] != '\n' || src.data[j+2] != '\r' || src.data[j+3] != '\n'))
			j++;
		if (j+3 >= src.size)
			break; // No \r\n\r\n

		size_t head_length = j+4;

#if SHOW_REQUESTS
		print_bytes(LIT(""), (string) {src.data, head_length});
		log_data(LIT("\n"));
#endif

		// Found! We got the request head
		Request request;
		int res = parse_request_head((string) {src.data, head_length}, &request);
		if (res != P_OK) {
			// Invalid HTTP request
			byte_queue_write(&conn->output, LIT(
				"HTTP/1.1 400 Bad Request\r\n"
				"Connection: Close\r\n"
				"\r\n"));
			polldata->events &= ~POLLIN;
			polldata->events |= POLLOUT;
			polldata->revents |= POLLOUT;
			conn->closing = true;
			conn->start_time = now;
			break;
		}

		string content_length_header;
		size_t content_length;
		if (!find_header(&request, LIT("Content-Length"), &content_length_header)) {

			if (find_and_parse_transfer_encoding(&request) & T_CHUNKED) {
				// Content-Length missing
				byte_queue_write(&conn->output, LIT(
					"HTTP/1.1 411 Length Required\r\n"
					"Connection: Close\r\n"
					"\r\n"));
				polldata->events &= ~POLLIN;
				polldata->events |= POLLOUT;
				polldata->revents |= POLLOUT;
				conn->closing = true;
				conn->start_time = now;
				log_data(LIT("Content-Length missing\n"));
				break;
			} else
				content_length = 0;

		} else {
			content_length = parse_content_length(content_length_header);
			if (content_length == (size_t) -1) {
				// Invalid Content-Length
				byte_queue_write(&conn->output, LIT(
					"HTTP/1.1 400 Bad Request\r\n"
					"Connection: Close\r\n"
					"\r\n"));
				polldata->events &= ~POLLIN;
				polldata->events |= POLLOUT;
				polldata->revents |= POLLOUT;
				conn->closing = true;
				conn->start_time = now;
				log_data(LIT("Invalid Content-Length\n"));
				break;
			}
		}

		if (content_length > 1<<20) {
			// Request too large
			byte_queue_write(&conn->output, LIT(
				"HTTP/1.1 413 Content Too Large\r\n"
				"Connection: Close\r\n"
				"\r\n"));
			polldata->events &= ~POLLIN;
			polldata->events |= POLLOUT;
			polldata->revents |= POLLOUT;
			conn->closing = true;
			conn->start_time = now;
			log_data(LIT("Request too large\n"));
			break;
		}

		size_t request_length = head_length + content_length;
		if (src.size < request_length)
			break; // Request wasn't completely received yet

		// Reset the request timer
		conn->start_time = now;

		conn->keep_alive = false;
		string keep_alive_header;
		if (find_header(&request, LIT("Connection"), &keep_alive_header)) {
			if (string_match_case_insensitive(trim(keep_alive_header), LIT("Keep-Alive")))
				conn->keep_alive = true;
		}
		// Respond
		ResponseBuilder builder;
		response_builder_init(&builder, conn);
		respond(request, &builder);
		response_builder_complete(&builder);
		if (builder.failed)
			remove = true;
		else {
			conn->served_count++;
			byte_queue_end_read(&conn->input, request_length);
			if (byte_queue_size(&conn->output) > 0) {
				polldata->events |= POLLOUT;
				polldata->revents |= POLLOUT;
			}
			if (!conn->keep_alive) {
				polldata->events &= ~POLLIN;
				conn->closing = true;
				conn->start_time = now;
			}

			pipeline_count++;
			if (pipeline_count == 10) {
				// TODO: We should send a response to the client instead of dropping it
				remove = true;
				break;
			}
		}

	}

	return remove;
}

bool read_from_socket(int fd, ByteQueue *queue)
{
	bool remove = false;

	for (;;) {

		if (!byte_queue_ensure_min_free_space(queue, 512)) {
			remove = true;
			break;
		}

		string dst = byte_queue_start_write(queue);

		int num = recv(fd, dst.data, dst.size, 0);
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
#if SHOW_IO
		print_bytes(LIT("> "), (string) {dst.data, num});
#endif
		byte_queue_end_write(queue, (size_t) num);

		// Input buffer can't go over 20Mb
		if (byte_queue_size(queue) > (size_t) INPUT_BUFFER_LIMIT_MB * 1024 * 1024) {
			remove = true;
			break;
		}
	}

	return remove;
}

bool write_to_socket(int fd, ByteQueue *queue)
{
	bool remove = false;
	for (;;) {

		string src = byte_queue_start_read(queue);
		if (src.size == 0) break;

		int num = send(fd, src.data, src.size, 0);
		if (num < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			log_perror(LIT("send"));
			remove = true;
			break;
		}

#if SHOW_IO
		print_bytes(LIT("< "), (string) {src.data, num});
#endif
		byte_queue_end_read(queue, (size_t) num);
	}

	return remove;
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	signal(SIGTERM, handle_sigterm);
	signal(SIGQUIT, handle_sigterm);
	signal(SIGINT,  handle_sigterm);

	log_init();
	log_data(LIT("starting\n"));

	for (int i = 0; i < MAX_CONNECTIONS+1; i++) {
		pollarray[i].fd = -1;
		pollarray[i].events = 0;
		pollarray[i].revents = 0;
	}

	for (int i = 0; i < MAX_CONNECTIONS; i++) {
		byte_queue_init(&conns[i].input);
		byte_queue_init(&conns[i].output);
	}

	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		log_perror(LIT("socket"));
		return -1;
	}

	if (!set_blocking(listen_fd, false)) {
		log_perror(LIT("fcntl"));
		return -1;
	}

	int one = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (char*) &one, sizeof(one));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr))) {
		log_perror(LIT("bind"));
		return -1;
	}

	if (listen(listen_fd, 32)) {
		log_perror(LIT("listen"));
		return -1;
	}

	pollarray[0].fd = listen_fd;
	pollarray[0].events = POLLIN;

	uint64_t last_log_time = 0;

	bool pending_accept = false;
	int timeout = -1;
	while (!stop) {

		int ret = poll(pollarray, MAX_CONNECTIONS, timeout);
		if (ret < 0) {
			if (errno == EINTR)
				break; // TODO: Should this be continue?
			log_perror(LIT("poll"));
			return -1;
		}

		now = get_current_time_ms();

		if (pollarray[0].revents || pending_accept) {

			pending_accept = false;

			for (;;) {

				// Look for a connection structure
				int free_index = 1;
				while (free_index-1 < MAX_CONNECTIONS && pollarray[free_index].fd != -1)
					free_index++;
				if (free_index-1 == MAX_CONNECTIONS) {
					pollarray[0].events &= ~POLLIN; // Stop listening for incoming connections
					pending_accept = true;
					break;
				}

				int accepted_fd = accept(listen_fd, NULL, NULL);
				if (accepted_fd < 0) {
					if (errno == EINTR)
						continue;
					if (errno == EAGAIN || errno == EWOULDBLOCK)
						break;
					log_perror(LIT("accept"));
					break;
				}
				if (!set_blocking(accepted_fd, false)) {
					log_perror(LIT("fcntl"));
					continue;
				}

				pollarray[free_index].fd = accepted_fd;
				pollarray[free_index].events = POLLIN;
				pollarray[free_index].revents = 0;
				byte_queue_init(&conns[free_index-1].input);
				byte_queue_init(&conns[free_index-1].output);
				conns[free_index-1].closing = false;
				conns[free_index-1].served_count = 0;
				conns[free_index-1].creation_time = now;
				conns[free_index-1].start_time = now;
				num_conns++;
			}
		}

		Connection *oldest = NULL;

		for (int i = 1; i-1 < MAX_CONNECTIONS; i++) {

			if (pollarray[i].fd == -1)
				continue;

			Connection *conn = &conns[i-1];
			bool remove = false;

			if (!remove && now >= deadline_of(conn)) {

				if (conn->closing) {
					// Closing timeout
					remove = true;
					log_data(LIT("Closing timeout\n"));
				} else {
					// Request timeout
					if (byte_queue_size(&conn->input) == 0) {
						// Connection was idle, so just close it
						remove = true;
						log_data(LIT("Idle connection timeout\n"));
					} else {
						byte_queue_write(&conn->output, LIT(
							"HTTP/1.1 408 Request Timeout\r\n"
							"Connection: Close\r\n"
							"\r\n"));
						conn->closing = true;
						conn->start_time = now;
						pollarray[i].events &= ~POLLIN;
						pollarray[i].events |= POLLOUT;
						pollarray[i].revents |= POLLOUT;
						log_data(LIT("Request timeout\n"));
					}
				}

			} else if (!remove && (pollarray[i].revents & (POLLIN | POLLHUP | POLLERR))) {

				remove = read_from_socket(pollarray[i].fd, &conn->input);
				if (!remove)
					remove = respond_to_available_requests(&pollarray[i], conn);
			} /* POLLIN */

			if (!remove && (pollarray[i].revents & POLLOUT)) {
				remove = write_to_socket(pollarray[i].fd, &conn->output);
				if (!remove && byte_queue_size(&conn->output) == 0) {
					pollarray[i].events &= ~POLLOUT;
					if (conn->closing)
						remove = true;
				}
			} /* POLLOUT */

			pollarray[i].revents = 0;

			if (remove) {
				close(pollarray[i].fd);
				pollarray[i].fd = -1;
				pollarray[i].events = 0;
				byte_queue_free(&conn->input);
				byte_queue_free(&conn->output);
				conn->start_time = -1;
				conn->closing = false;
				conn->creation_time = 0;
				if ((pollarray[0].events & POLLIN) == 0)
					pollarray[0].events |= POLLIN;
				num_conns--;
			} else {
				if (oldest == NULL || deadline_of(oldest) > deadline_of(conn)) oldest = conn;
			}
		}

		if (now - last_log_time > LOG_FLUSH_TIMEOUT_SEC * 1000) {
			log_flush();
			last_log_time = now;
		}

		/*
		 * Calculate the timeout for the next poll
		 */
		if (pending_accept && num_conns < MAX_CONNECTIONS)
			timeout = 0;
		else if (log_empty()) {
			if (oldest == NULL)
				timeout = -1;
			else {
				if (deadline_of(oldest) < now) timeout = 0;
				else timeout = deadline_of(oldest) - now;
			}
		} else {
			uint64_t deadline = last_log_time + LOG_FLUSH_TIMEOUT_SEC * 1000;
			if (oldest && deadline > deadline_of(oldest))
				deadline = deadline_of(oldest);
			if (deadline < now) timeout = 0;
			else timeout = deadline - now;
		}

	} /* main loop end */

	for (int i = 0; i < MAX_CONNECTIONS+1; i++)
		if (pollarray[i].fd != -1)
			close(pollarray[i].fd);
	for (int i = 0; i < MAX_CONNECTIONS; i++) {
		byte_queue_free(&conns[i].input);
		byte_queue_free(&conns[i].output);
	}
	log_data(LIT("closing\n"));

	close(listen_fd);
	log_free();
	return 0;
}

bool serve_file_or_dir(ResponseBuilder *b, string prefix, string docroot,
	string reqpath, string mime, bool enable_dir_listing);

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

#define PATH_SEP '/'

static bool is_print(char c)
{
    return c >= 32 && c < 127;
}

static bool is_pcomp(char c)
{
    return c != '/' && c != ':' && is_print(c);
}

bool streq(string s1, string s2)
{
	// TODO: What is s1.data or s2.data is NULL?
	return s1.size == s2.size && !memcmp(s1.data, s2.data, s1.size);
}

int split_path_components(string src, string *stack, int limit, bool allow_ddots)
{
    size_t cur = 0;

    // Skip the first slash
    if (cur < src.size && src.data[cur] == PATH_SEP)
        cur++;

    int depth = 0;
    while (cur < src.size) {

        if (depth == limit)
            return -1;

        size_t start = cur;
        while (cur < src.size && (is_pcomp(src.data[cur]) || (allow_ddots && src.data[cur] == ':')))
            cur++;

        string comp = substr(src, start, cur);

        if (comp.size == 0)
            return -1; // We consider paths with empty components invalid

        if (streq(comp, LIT(".."))) {
            if (depth == 0)
                return -1;
            depth--;
        } else {
            if (!streq(comp, LIT(".")))
                stack[depth++] = comp;
        }

        if (cur == src.size)
            break;

        if (src.data[cur] != PATH_SEP)
            return -1;
        cur++;
    }
    return depth;
}

/*
 * Sanitize a path string removing ./ and ../
 * components. The final path has an initial
 * / but not final.
 */
size_t sanitize_path(string src, char *mem, size_t max)
{
    #define MAX_COMPS 64

    string stack[MAX_COMPS];
    int depth;

    depth = split_path_components(src, stack, MAX_COMPS, false);
    if (depth < 0)
        return -1;

    /*
     * Count how many output bytes are required
     */
    size_t req = depth;
    for (int i = 0; i < depth; i++)
        req += stack[i].size;
    if (req >= max)
        return -1; // Buffer too small

    /*
     * Copy the sanitized path into the output
     * buffer.
     */
    size_t n = 0;
    for (int i = 0; i < depth; i++) {
        mem[n++] = PATH_SEP;
        memcpy(mem + n, stack[i].data, stack[i].size);
        n += stack[i].size;
    }
    mem[n] = '\0';
    return n;
}

int match_path_format(string path, char *fmt, ...)
{
    #define LIMIT 32
    string p_stack[LIMIT];
    string f_stack[LIMIT];
    int p_depth;
    int f_depth;

    p_depth = split_path_components(path,     p_stack, LIMIT, false);
    f_depth = split_path_components(LIT(fmt), f_stack, LIMIT, true);

    if (p_depth < 0 || f_depth < 0)
        return -1; // Error

    if (p_depth != f_depth)
        return 1; // No match

    va_list args;
    va_start(args, fmt);

    for (int i = 0; i < f_depth; i++) {

        assert(f_stack[i].size > 0);
        assert(p_stack[i].size > 0);

        if (f_stack[i].data[0] == ':') {
            if (f_stack[i].size != 2) {
				va_end(args);
                return -1; // Invalid format
			}
            switch (f_stack[i].data[1]) {
                
                case 'l':
                {
                    string *sl = va_arg(args, string*);
                    *sl = p_stack[i];
                }
                break;
                
                case 'n':
                {
                    uint32_t n = 0;
                    size_t cur = 0;
                    while (cur < p_stack[i].size && is_digit(p_stack[i].data[cur])) {
                        int d = p_stack[i].data[cur] - '0';
                        if (n > (UINT32_MAX - d) / 10) {
							va_end(args);
                            return -1; // Overflow
						}
                        n = n * 10 + d;
                        cur++;
                    }
                    if (cur != p_stack[i].size) {
						va_end(args);
                        return -1; // Component isn't a number
					}
                    uint32_t *p = va_arg(args, uint32_t*);
                    *p = n;
                }
                break;

                default:
				va_end(args);
                return -1; // Invalid formt
            }
        } else {
            if (f_stack[i].size != p_stack[i].size) {
				va_end(args);
                return 1; // No match
			}
            if (memcmp(f_stack[i].data, p_stack[i].data, f_stack[i].size)) {
				va_end(args);
                return 1;
			}
        }
    }

    va_end(args);
    return 0;
}

struct {
	string mime;
	string ext;
} mime_table[] = {
	{LIT("text/javascript"),  LIT(".js")},
	{LIT("text/javascript"),  LIT(".javascript")},
	{LIT("text/html"),        LIT(".html")},
	{LIT("text/html"),        LIT(".htm")},
	{LIT("image/gif"),        LIT(".gif")},
	{LIT("image/jpeg"),       LIT(".jpg")},
	{LIT("image/jpeg"),       LIT(".jpeg")},
	{LIT("image/svg+xml"),    LIT(".svg")},
	{LIT("video/mp4"),        LIT(".mp4")},
	{LIT("video/mpeg"),       LIT(".mpeg")},
	{LIT("font/ttf"),         LIT(".ttf")},
	{LIT("font/woff"),        LIT(".woff")},
	{LIT("font/woff2"),       LIT(".woff2")},
	{LIT("text/plain"),       LIT(".txt")},
	{LIT("audio/wav"),        LIT(".wav")},
	{LIT("application/x-7z-compressed"), LIT(".7z")},
	{LIT("application/zip"),  LIT(".zip")},
	{LIT("application/xml"),  LIT(".xml")},
	{LIT("application/json"), LIT(".json")},
	{NULLSTR, NULLSTR},
};

string mimetype_from_filename(string name)
{
	for (size_t i = 0; i < COUNTOF(mime_table); i++)
		if (endswith(mime_table[i].ext, name))
			return mime_table[i].mime;
	return NULLSTR;
}

bool serve_file_or_dir(ResponseBuilder *b, string prefix, string docroot,
	string reqpath, string mime, bool enable_dir_listing)
{

	// Sanitize the request path
	char pathmem[1<<10];
	string path;
	{
		size_t len = sanitize_path(reqpath, pathmem, sizeof(pathmem));
		if (len >= sizeof(pathmem)) {
			status_line(b, 500);
			return true;
		}
		path = (string) {pathmem, len};
		path.data[path.size] = '\0';
	}

	// Only handle this request if the prefix matches
	if (!startswith(prefix, path))
		return false;

	// Remove the matched prefix and put the docroot in its place
	{
		if (docroot.size + path.size - prefix.size >= sizeof(pathmem)) {
			status_line(b, 500);
			return true;
		}
		memmove(pathmem + docroot.size, pathmem + prefix.size, path.size - prefix.size);
		memcpy(pathmem, docroot.data, docroot.size);
		path.size -= prefix.size;
		path.size += docroot.size;
		path.data[path.size] = '\0';
	}

	struct stat buf;
	if (stat(path.data, &buf)) {
		if (errno == ENOENT)
			return false;
		status_line(b, 500);
		return true;
	}

	if (S_ISREG(buf.st_mode)) {

		int fd;
		do
			fd = open(path.data, O_RDONLY);
		while (fd < 0 && errno == EINTR);

		if (fd < 0) {
			status_line(b, 500);
			close(fd);
			return true;
		}
		
		status_line(b, 200);

		if (mime.size == 0) mime = mimetype_from_filename(path);
		if (mime.size > 0) add_header_f(b, "Content-Type: %.*s", (int) mime.size, mime.data);

		string dst = append_content_start(b, (size_t) buf.st_size);
		if (dst.size == 0) {
			status_line(b, 500);
			close(fd);
			return true;
		}
		assert(dst.size >= (size_t) buf.st_size);

		size_t copied = 0;
		while (copied < (size_t) buf.st_size) {
			int num = read(fd, dst.data + copied, (size_t) buf.st_size - copied);
			if (num <= 0) {
				if (num < 0)
					log_format("Failed reading from '%.*s'\n", (int) path.size, path.data);
				break;
			}
			copied += num;
		}

		append_content_end(b, copied);
		close(fd);
		return true;
	}

	if (enable_dir_listing && S_ISDIR(buf.st_mode)) {

		DIR *d = opendir(path.data);
		if (d == NULL) {
			status_line(b, 500);
			return true;
		}

		status_line(b, 200);
		append_content_s(b, LIT(
			"<html>\n"
			"    <head>\n"
			"    </head>\n"
			"    <body>\n"
			"        <ul>\n"
			"            <li><a href=\"\">(parent)</a></li>")); // TODO: Add links

		struct dirent *dir;
		while ((dir = readdir(d))) {
			if (!strcmp(dir->d_name, ".") ||
				!strcmp(dir->d_name, ".."))
				continue;
			append_content_f(b, "<li><a href=\"\">%s</a></li>\n", dir->d_name); // TODO: Add links
		}

		append_content_s(b, LIT(
			"        </ul>\n"
			"    </body>\n"
			"</html>\n"));
		closedir(d);
		return true;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////

int      log_last_file_index = 0;
int      log_fd = -1;
char    *log_buffer = NULL;
size_t   log_buffer_used = 0;
bool     log_failed = false;
size_t   log_total_size = 0;

void log_choose_file_name(char *dst, size_t max)
{
	for (;;) {

		int num = snprintf(dst, max, "logs/log_%d.txt", log_last_file_index);
		if (num < 0 || (size_t) num >= max) {
			fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		dst[num] = '\0';

		struct stat buf;
		if (stat(dst, &buf) && errno == ENOENT)
			break;

		if (log_last_file_index == 100000000) {
			fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		log_last_file_index++;
	}
}

void log_init(void)
{
	atexit(log_free);

	log_buffer = mymalloc(LOG_BUFFER_SIZE);
	if (log_buffer == NULL) {
		fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	char name[1<<12];
	log_choose_file_name(name, sizeof(name));
	if (log_failed) {
		return;
	}

	log_fd = open(name, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (log_fd < 0) {
		fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	log_total_size = 0;

	DIR *d = opendir("logs");
	if (d == NULL) {
		fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}
	struct dirent *dir;
	while ((dir = readdir(d))) {

		if (!strcmp(dir->d_name, ".") ||
			!strcmp(dir->d_name, ".."))
			continue;

		char path[1<<12];
		int k = snprintf(path, SIZEOF(path), "logs/%s", dir->d_name);
		if (k < 0 || k >= SIZEOF(path)) log_fatal(LIT("Bad format"));
		path[k] = '\0';

		struct stat buf;
		if (stat(path, &buf))
			log_fatal(LIT("Couldn't stat log file"));

		if ((size_t) buf.st_size > SIZE_MAX - log_total_size)
			log_fatal(LIT("Log file is too big"));
		log_total_size += (size_t) buf.st_size;
	}
	closedir(d);

	static_assert(SIZEOF(size_t) > 4, "It's assumed size_t can store a number of bytes in the order of 10gb");
	if (log_total_size > (size_t) LOG_DIRECTORY_SIZE_LIMIT_MB * 1024 * 1024) {
		fprintf(stderr, "Log reached disk limit at startup\n");
		log_failed = true;
		return;
	}
}

void log_free(void)
{
	if (log_buffer) {
		log_flush();
		if (log_fd > -1)
			close(log_fd);
		free(log_buffer);
		log_fd = -1;
		log_buffer = NULL;
		log_buffer_used = 0;
		log_failed = false;
	}
}

bool log_empty(void)
{
	return log_failed || log_buffer_used == 0;
}

void log_flush(void)
{
	if (log_failed || log_buffer_used == 0)
		return;

	/*
	 * Rotate the file if the limit was reached
	 */
	struct stat buf;
	if (fstat(log_fd, &buf)) {
		fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}
	if (buf.st_size + log_buffer_used >= LOG_BUFFER_LIMIT) {
		char name[1<<12];
		log_choose_file_name(name, SIZEOF(name));
		if (log_failed) return; 
		
		close(log_fd);
		log_fd = open(name, O_WRONLY | O_APPEND | O_CREAT, 0644);
		if (log_fd < 0) {
			fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
	}

	/*
	 * Buffer is full. We need to flush it to continue
	 */
	int zeros = 0;
	size_t copied = 0;
	while (copied < log_buffer_used) {

		int num = write(log_fd, log_buffer + copied, log_buffer_used - copied);
		if (num < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		if (num == 0) {
			zeros++;
			if (zeros == 1000) {
				fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
				log_failed = true;
				return;
			}
		} else {
			zeros = 0;
		}

		copied += num;
		log_total_size += num;

		if (log_total_size > (size_t) LOG_DIRECTORY_SIZE_LIMIT_MB * 1024 * 1024) {
			fprintf(stderr, "Log reached disk limit\n");
			log_failed = true;
			return;
		}
	}

	assert(copied == log_buffer_used);
	log_buffer_used = 0;
}

void log_fatal(string str)
{
	log_data(str);
	exit(-1);
}

void log_format(const char *fmt, ...)
{
	if (log_failed)
		return;

	if (log_buffer_used == LOG_BUFFER_SIZE) {
		log_flush();
		if (log_failed) return;
	}

	int num;
	{
		va_list args;
		va_start(args, fmt);
		num = vsnprintf(log_buffer + log_buffer_used, LOG_BUFFER_SIZE - log_buffer_used, fmt, args);
		va_end(args);
	}

	if (num < 0 || num > LOG_BUFFER_SIZE) {
		fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	if ((size_t) num > LOG_BUFFER_SIZE - log_buffer_used) {
		
		log_flush();
		if (log_failed) return;

		va_list args;
		va_start(args, fmt);
		int k = vsnprintf(log_buffer + log_buffer_used, LOG_BUFFER_SIZE - log_buffer_used, fmt, args);
		va_end(args);

		if (k != num) log_fatal(LIT("Bad format"));
	}

	log_buffer_used += num;
}

void log_data(string str)
{
	if (log_failed)
		return;

	if (str.size > LOG_BUFFER_SIZE - log_buffer_used) {
		if (str.size > LOG_BUFFER_SIZE) {
			fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		log_flush();
		if (log_failed) return;
	}
	assert(str.size <= LOG_BUFFER_SIZE - log_buffer_used);

	assert(log_buffer);
	memcpy(log_buffer + log_buffer_used, str.data, str.size);
	log_buffer_used += str.size;
}

void log_perror(string str)
{
	log_format("%.*s: %s\n", (int) str.size, str.data, strerror(errno));
}
