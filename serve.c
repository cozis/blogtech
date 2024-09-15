
///////////////////////////////////////////////////////////////////////////////////////////////
/// Headers                                                                                 ///
///////////////////////////////////////////////////////////////////////////////////////////////

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
#include <limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>

///////////////////////////////////////////////////////////////////////////////////////////////
/// Configuration                                                                           ///
///////////////////////////////////////////////////////////////////////////////////////////////

#ifndef HTTPS
#define HTTPS 0
#endif

#ifdef RELEASE
#define PORT 80
#define HTTPS_PORT 443
#define MAX_CONNECTIONS 1024
#define LOG_BUFFER_SIZE (1<<20)
#define LOG_FILE_LIMIT (1<<24)
#define LOG_DIRECTORY_SIZE_LIMIT_MB (25 * 1024)
#else
#define PORT 8080
#define HTTPS_PORT 8081
#define MAX_CONNECTIONS 32
#define LOG_BUFFER_SIZE (1<<10)
#define LOG_FILE_LIMIT (1<<20)
#define LOG_DIRECTORY_SIZE_LIMIT_MB 100
#endif

#define LOG_DIRECTORY "logs"

#define HTTPS_KEY_FILE  "key.pem"
#define HTTPS_CERT_FILE "cert.pem"

#define BLACKLIST 1
#define BLACKLIST_FILE "blacklist.txt"
#define BLACKLIST_LIMIT 1024

#define ACCESS_LOG 1
#define SHOW_IO 0
#define SHOW_REQUESTS 0
#define REQUEST_TIMEOUT_SEC 5
#define CLOSING_TIMEOUT_SEC 2
#define CONNECTION_TIMEOUT_SEC 60
#define LOG_FLUSH_TIMEOUT_SEC 3
#define INPUT_BUFFER_LIMIT_MB 1

///////////////////////////////////////////////////////////////////////////////////////////////
/// Optional Headers                                                                        ///
///////////////////////////////////////////////////////////////////////////////////////////////

#if HTTPS
#include <bearssl.h>
#endif

///////////////////////////////////////////////////////////////////////////////////////////////
/// Basic Definitions                                                                       ///
///////////////////////////////////////////////////////////////////////////////////////////////

static_assert(LOG_BUFFER_SIZE < LOG_FILE_LIMIT, "");

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

#ifndef NDEBUG
#define DEBUG(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#else
#define DEBUG(...) {}
#endif

///////////////////////////////////////////////////////////////////////////////////////////////
/// Forward Declarations                                                                    ///
///////////////////////////////////////////////////////////////////////////////////////////////

void log_init(void);
void log_free(void);
void log_data(string str);
void log_fatal(string str);
void log_perror(string str);
void log_format(const char *fmt, ...);
void log_flush(void);
bool log_empty(void);

#if BLACKLIST
bool ip_allowed(uint32_t ip);
bool load_blacklist(void);
#endif

#if HTTPS

// Aggregate type for a private key.
typedef struct {
	int key_type;  // BR_KEYTYPE_RSA or BR_KEYTYPE_EC
	union {
		br_rsa_private_key rsa;
		br_ec_private_key ec;
	} key;
} private_key;

br_x509_certificate *read_certificates_from_file(string file, size_t *num);
void                 free_certificates(br_x509_certificate *certs, size_t num);
private_key *read_private_key(string file);
void         free_private_key(private_key *sk);
#endif

bool load_file_contents(string file, string *out);

///////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION                                                                          ///
//////////////////////////////////////////////////////////////////////////////////////////////

uint64_t timespec_to_ms(struct timespec ts)
{
	if ((uint64_t) ts.tv_sec > UINT64_MAX / 1000)
		log_fatal(LIT("Time overflow\n"));
	uint64_t ms = ts.tv_sec * 1000;

	uint64_t nsec_part = ts.tv_nsec / 1000000;
	if (ms > UINT64_MAX - nsec_part)
		log_fatal(LIT("Time overflow\n"));
	ms += nsec_part;
	return ms;
}

uint64_t get_monotonic_time_ms(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret) log_fatal(LIT("Couldn't read monotonic time\n"));
	return timespec_to_ms(ts);
}

uint64_t get_real_time_ms(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (ret) log_fatal(LIT("Couldn't read real time\n"));
	return timespec_to_ms(ts);
}

void *mymalloc(size_t num)
{
	return malloc(num);
}

///////////////////////////////////////////////////////////////////////////////////////////////
/// HTTP Request Parser                                                                     ///
///////////////////////////////////////////////////////////////////////////////////////////////

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

// TODO: Make sure every string in request is reasonaly long
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
	uint32_t ipaddr;
	int served_count;
	bool https;
	bool closing;
	bool keep_alive;
	uint64_t creation_time;
	uint64_t start_time;
#if HTTPS
	br_ssl_server_context https_context;
	char https_buffer[BR_SSL_BUFSIZE_BIDI];
#endif
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
uint64_t real_now;

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

struct pollfd pollarray[MAX_CONNECTIONS+2];
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

#if ACCESS_LOG
		{
			// Log access
			time_t real_now_in_secs = real_now / 1000;
			struct tm timeinfo;
			localtime_r(&real_now_in_secs, &timeinfo);
			char timebuf[128];
			size_t timelen = strftime(timebuf, sizeof(timebuf), "%Y/%m/%d %H:%M:%S", &timeinfo);
			if (timelen == 0)
				log_fatal(LIT("Couldn't format time for access log"));
			timebuf[timelen] = '\0';

			char ipbuf[INET_ADDRSTRLEN];
			const char *ipstr = inet_ntop(AF_INET, &conn->ipaddr, ipbuf, sizeof(ipbuf));
			if (ipstr == NULL)
				log_fatal(LIT("Couldn't format IP address for access log"));

			if (res == P_OK) {
				string user_agent;
				if (!find_header(&request, LIT("User-Agent"), &user_agent))
					user_agent = LIT("No User-Agent");
				else
					user_agent = trim(user_agent);
				log_format("%s - %s - %.*s - %.*s\n", timebuf, ipstr,
					(int) request.path.size, request.path.data,
					(int) user_agent.size, user_agent.data);
			} else {
				log_format("%s - %s - Bad request\n", timebuf, ipstr);
			}
		}
#endif

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
				log_data(LIT("Pipeline limit reached\n"));
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
			log_perror(LIT("recv"));
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

int create_listening_socket(int port)
{
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
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(listen_fd, (struct sockaddr*) &addr, sizeof(addr))) {
		log_perror(LIT("bind"));
		return -1;
	}

	if (listen(listen_fd, 32)) {
		log_perror(LIT("listen"));
		return -1;
	}

	return listen_fd;
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, handle_sigterm);
	signal(SIGQUIT, handle_sigterm);
	signal(SIGINT,  handle_sigterm);

	log_init();
	log_data(LIT("starting\n"));

	for (int i = 0; i < MAX_CONNECTIONS+2; i++) {
		pollarray[i].fd = -1;
		pollarray[i].events = 0;
		pollarray[i].revents = 0;
	}

	for (int i = 0; i < MAX_CONNECTIONS; i++) {
		byte_queue_init(&conns[i].input);
		byte_queue_init(&conns[i].output);
	}

	int listen_fd = create_listening_socket(PORT);
	if (listen_fd < 0) log_fatal(LIT("Couldn't bind\n"));
	log_format("Listening on port %d\n", PORT);
	pollarray[0].fd = listen_fd;
	pollarray[0].events = POLLIN;
	pollarray[0].revents = 0;

#if HTTPS
	int secure_fd = create_listening_socket(HTTPS_PORT);
	if (secure_fd < 0) log_fatal(LIT("Couldn't bind\n"));
	log_format("Listening on port %d\n", HTTPS_PORT);
	pollarray[1].fd = secure_fd;
	pollarray[1].events = POLLIN;
	pollarray[1].revents = 0;

	size_t num_certs;
	br_x509_certificate *certs = read_certificates_from_file(LIT(HTTPS_CERT_FILE), &num_certs);
	if (certs == NULL)
		log_fatal(LIT("Couldn't load certificates\n"));

	private_key *pkey = read_private_key(LIT(HTTPS_KEY_FILE));
	if (pkey == NULL)
		log_fatal(LIT("Couldn't load private key\n"));
#endif

#if BLACKLIST
	if (!load_blacklist()) {
		log_data(LIT("Couldn't load blacklist\n"));
		return -1;
	}
#endif

	uint64_t last_log_time = 0;
	bool pending_accept = false;
	int timeout =  log_empty() ? -1 : LOG_FLUSH_TIMEOUT_SEC * 1000;
	while (!stop) {

		int ret = poll(pollarray, MAX_CONNECTIONS, timeout);
		if (ret < 0) {
			if (errno == EINTR)
				break; // TODO: Should this be continue?
			log_perror(LIT("poll"));
			return -1;
		}

		now = get_monotonic_time_ms();
		real_now = get_real_time_ms();

		if ((pollarray[0].revents & ~POLLIN) || (pollarray[1].revents & ~POLLIN)) {
			// TODO: Handle errors
			log_fatal(LIT("error occurred on listening sockets"));
		}

		if ((pollarray[0].revents & POLLIN) || (pollarray[1].revents & POLLIN) || pending_accept) {

			pending_accept = false;

			int desc_list[] = {
				listen_fd,
#if HTTPS
				secure_fd,
#endif
			};

			for (int i = 0; i < COUNTOF(desc_list); i++) {

				int current_listener_fd = desc_list[i];

				int pollarray_index = (listen_fd == current_listener_fd ? 0 : 1);

				for (;;) {

					// Look for a connection structure
					int free_index = 2;
					while (free_index-2 < MAX_CONNECTIONS && pollarray[free_index].fd != -1)
						free_index++;
					if (free_index-2 == MAX_CONNECTIONS) {
						// Stop listening for incoming connections
						pollarray[pollarray_index].events &= ~POLLIN;
						pending_accept = true;
						break;
					}

					struct sockaddr_in accepted_addr;
					socklen_t accepted_addrlen = sizeof(accepted_addr);
					int accepted_fd = accept(current_listener_fd, (struct sockaddr*) &accepted_addr, &accepted_addrlen);
					if (accepted_fd < 0) {
						if (errno == EINTR)
							continue;
						if (errno == EAGAIN || errno == EWOULDBLOCK)
							break;
						log_perror(LIT("accept"));
						close(accepted_fd);
						break;
					}

#if BLACKLIST
					if (!ip_allowed((uint32_t) accepted_addr.sin_addr.s_addr)) {
						log_data(LIT("Connection Rejected\n"));
						close(accepted_fd);
						continue;
					}
#endif

					if (!set_blocking(accepted_fd, false)) {
						log_perror(LIT("fcntl"));
						close(accepted_fd);
						continue;
					}

					struct pollfd *polldata = &pollarray[free_index];
					Connection *conn = &conns[free_index-2];

					polldata->fd = accepted_fd;
#if HTTPS
					polldata->events = POLLIN | POLLOUT;
#else
					polldata->events = POLLIN;
#endif
					polldata->revents = 0;

					byte_queue_init(&conn->input);
					byte_queue_init(&conn->output);
					conn->ipaddr = (uint32_t) accepted_addr.sin_addr.s_addr;
					conn->closing = false;
					conn->https = false;
					conn->served_count = 0;
					conn->creation_time = now;
					conn->start_time = now;
					num_conns++;
#if HTTPS
					if (current_listener_fd == secure_fd) {
						if (pkey->key_type == BR_KEYTYPE_RSA)
							br_ssl_server_init_full_rsa(&conn->https_context, certs, num_certs, &pkey->key.rsa);
						else {
							assert(pkey->key_type == BR_KEYTYPE_EC);
							unsigned issuer_key_type = BR_KEYTYPE_RSA; // Not sure if this or BR_KEYTYPE_EC
							br_ssl_server_init_full_ec(&conn->https_context, certs, num_certs, issuer_key_type, &pkey->key.ec);
						}
						br_ssl_engine_set_versions(&conn->https_context.eng, BR_TLS10, BR_TLS12);
						br_ssl_engine_set_buffer(&conn->https_context.eng, conn->https_buffer, sizeof(conn->https_buffer), 1);
						br_ssl_server_reset(&conn->https_context);
						conn->https = true;
					}
#endif
				} /* accept loop */
			} /* listener loop */
		}

		Connection *oldest = NULL;

		for (int i = 2; i-2 < MAX_CONNECTIONS; i++) {

			if (pollarray[i].fd == -1)
				continue;

			struct pollfd *polldata = &pollarray[i];
			Connection *conn = &conns[i-2];
			bool remove = false;

			if (now >= deadline_of(conn)) {

				assert(!remove);

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
						polldata->events &= ~POLLIN;
						polldata->events |= POLLOUT;
						polldata->revents |= POLLOUT;
						log_data(LIT("Request timeout\n"));
					}
				}
			}

			if (conn->https) {
#if !HTTPS
				log_fatal(LIT("Unreachable"));
#else
				br_ssl_engine_context *cc = &conn->https_context.eng;
				bool flushed = false;
				while (!remove) {

					int state = br_ssl_engine_current_state(cc);

					if (state & BR_SSL_CLOSED) {
						// Engine is finished, no more I/O (until next reset).
						int error = br_ssl_engine_last_error(cc);
						if (error != BR_ERR_OK) {
							const char *find_error_name(int err, const char **comment);
							const char *ename = find_error_name(error, NULL);
							if (ename == NULL) ename = "unknown";
							log_format("SSL failure: %s\n", ename);
						}
						remove = true;
						break;
					}

					if ((state & BR_SSL_SENDREC) && (polldata->revents & POLLOUT)) {
						// Engine has some bytes to send to the peer
						size_t len;
						unsigned char *buf = br_ssl_engine_sendrec_buf(cc, &len);
						size_t copied = 0;
						while (copied < len) {
							int num = send(polldata->fd, buf + copied, len - copied, 0);
							if (num < 0) {
								if (errno == EINTR)
									continue;
								if (errno == EAGAIN || errno == EWOULDBLOCK) {
									polldata->revents &= ~POLLOUT;
									break;
								}
								perror("send");
								remove = true;
								break;
							}
							// TODO: Handle num=0
							copied += (size_t) num;
						}
						if (remove) break;
						br_ssl_engine_sendrec_ack(cc, copied);
						flushed = false;
					}

					if ((state & BR_SSL_RECVAPP)) {
						// Engine has obtained some application data from the 
						// peer, that should be read by the caller.
						size_t len;
						unsigned char *buf = br_ssl_engine_recvapp_buf(cc, &len);
						if (!byte_queue_ensure_min_free_space(&conn->input, len)) {
							remove = true;
							break;
						}
						string dst = byte_queue_start_write(&conn->input);
						assert(dst.size >= len);
						memcpy(dst.data, buf, len);
#if SHOW_IO
						print_bytes(LIT("> "), (string) {dst.data, len});
#endif
						byte_queue_end_write(&conn->input, len);
						br_ssl_engine_recvapp_ack(cc, len);
						remove = respond_to_available_requests(polldata, conn);
						if (remove) break;
						flushed = false;
					}

					if ((state & BR_SSL_RECVREC) && (polldata->revents & POLLIN)) {
						// Engine expects some bytes from the peer
						size_t len;
						unsigned char *buf = br_ssl_engine_recvrec_buf(cc, &len);
						size_t copied = 0;
						while (copied < len) {
							int num = recv(polldata->fd, buf + copied, len - copied, 0);
							if (num < 0) {
								if (errno == EINTR)
									continue;
								if (errno == EAGAIN || errno == EWOULDBLOCK) {
									polldata->revents &= ~POLLIN;
									break;
								}
								perror("recv");
								remove = true;
								break;
							}
							if (num == 0) {
								remove = true;
								break;
							}
							// TODO: Handle num=0
							copied += (size_t) num;
						}
						if (remove) break;
						br_ssl_engine_recvrec_ack(cc, copied);
						flushed = false;
					}

					if ((state & BR_SSL_SENDAPP) && byte_queue_size(&conn->output) > 0) {
						// Engine may receive application data to send (or flush).
						size_t len;
						unsigned char *buf = br_ssl_engine_sendapp_buf(cc, &len);
						string src = byte_queue_start_read(&conn->output);
						size_t copy = MIN(len, src.size);
						memcpy(buf, src.data, copy);
#if SHOW_IO
						print_bytes(LIT("< "), (string) {src.data, copy});
#endif
						byte_queue_end_read(&conn->output, copy);
						br_ssl_engine_sendapp_ack(cc, copy);
						br_ssl_engine_flush(cc, 0); // TODO: Is this the right time to call it?
						flushed = false;
					}

					if (flushed)
						break;
					br_ssl_engine_flush(cc, 0);
					flushed = true;
				}

				if (!remove) {
					int state = br_ssl_engine_current_state(cc);

					polldata->events = 0;
					if (state & BR_SSL_SENDREC) {
						if (conn->closing && byte_queue_size(&conn->output) == 0)
							remove = true;
						else
							polldata->events |= POLLOUT;
					}

					if (state & BR_SSL_RECVREC)
						polldata->events |= POLLIN;
				}

#endif /* HTTPS */
			} else {

				if ((!remove && !conn->closing) && (polldata->revents & (POLLIN | POLLHUP | POLLERR))) {

					remove = read_from_socket(polldata->fd, &conn->input);
					if (!remove)
						remove = respond_to_available_requests(polldata, conn);
				} /* POLLIN */

				if (!remove && (polldata->revents & POLLOUT)) {
					remove = write_to_socket(polldata->fd, &conn->output);
					if (!remove && byte_queue_size(&conn->output) == 0) {
						polldata->events &= ~POLLOUT;
						if (conn->closing)
							remove = true;
					}
				} /* POLLOUT */
			}

			polldata->revents = 0;

			if (remove) {
				close(polldata->fd);
				polldata->fd = -1;
				polldata->events = 0;
				byte_queue_free(&conn->input);
				byte_queue_free(&conn->output);
				conn->start_time = -1;
				conn->closing = false;
				conn->creation_time = 0;
				if ((pollarray[0].events & POLLIN) == 0) pollarray[0].events |= POLLIN;
				if ((pollarray[1].events & POLLIN) == 0) pollarray[1].events |= POLLIN;
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

#if HTTPS
	free_private_key(pkey);
	free_certificates(certs, num_certs);
	close(secure_fd);
#endif

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

void log_choose_file_name(char *dst, size_t max, bool startup)
{
	size_t prev_size = -1;
	for (;;) {

		int num = snprintf(dst, max, LOG_DIRECTORY "/log_%d.txt", log_last_file_index);
		if (num < 0 || (size_t) num >= max) {
			fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		dst[num] = '\0';

		struct stat buf;
		if (stat(dst, &buf)) {
			if (errno == ENOENT)
				break;
			prev_size = -1;
		} else {
			prev_size = (size_t) buf.st_size;
		}

		if (log_last_file_index == 100000000) {
			fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		log_last_file_index++;
	}

	// At startup don't create a new log file if the last one didn't reache its limit
	if (startup && prev_size < LOG_FILE_LIMIT) {

		log_last_file_index--;

		int num = snprintf(dst, max, LOG_DIRECTORY "/log_%d.txt", log_last_file_index);
		if (num < 0 || (size_t) num >= max) {
			fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
			log_failed = true;
			return;
		}
		dst[num] = '\0';
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

	if (mkdir(LOG_DIRECTORY, 0666) && errno != EEXIST) {
		fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	char name[1<<12];
	log_choose_file_name(name, sizeof(name), true);
	if (log_failed) return; 

	log_fd = open(name, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (log_fd < 0) {
		fprintf(stderr, "log_failed (%s:%d)\n", __FILE__, __LINE__);
		log_failed = true;
		return;
	}

	log_total_size = 0;

	DIR *d = opendir(LOG_DIRECTORY);
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
		int k = snprintf(path, SIZEOF(path), LOG_DIRECTORY "/%s", dir->d_name);
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
	if (buf.st_size + log_buffer_used >= LOG_FILE_LIMIT) {
		char name[1<<12];
		log_choose_file_name(name, SIZEOF(name), false);
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

#if BLACKLIST

uint32_t blocked_ips[BLACKLIST_LIMIT];
int      blocked_num = 0;

bool ip_allowed(uint32_t ip)
{
	for (int i = 0; i < blocked_num; i++)
		if (ip == blocked_ips[i])
			return false;
	return true;
}
bool load_blacklist(void)
{
	string data = NULLSTR;
	if (!load_file_contents(LIT(BLACKLIST_FILE), &data)) {
		if (errno == ENOENT)
			return true;
		return false;
	}
	char  *str = data.data;
	size_t len = data.size;

	blocked_num = 0;

	// Parse the ip addresses
	size_t cur = 0;
	for (;;) {
		// Get the start and end of the line
		size_t start = cur;
		while (cur < len && str[cur] != '\n' && str[cur] != '#')
			cur++;
		string line = { str + start, cur - start };
		line = trim(line);

		if (line.size > 0) {

			char temp[sizeof("xxx.xxx.xxx.xxx")];
			if (line.size >= sizeof(temp)) {
				log_format("Invalid IP address \"%.*s\"\n", (int) line.size, line.data);
				free(str);
				return false;
			}
			memcpy(temp, line.data, line.size);
			temp[line.size] = '\0';

			uint32_t ip;
			if (inet_pton(AF_INET, temp, &ip) != 1) {
				log_format("Invalid IP address \"%.*s\"\n", (int) line.size, line.data);
				free(str);
				return false;
			}

			if (blocked_num == BLACKLIST_LIMIT) {
				log_format("IP buffer is too short\n");
				free(str);
				return false;
			}

			blocked_ips[blocked_num++] = ip;
		}

		if (cur < len && str[cur] == '#')
			while (cur < len && str[cur] != '\n')
				cur++;

		if (cur == len)
			break;
		assert(str[cur] == '\n');
		cur++;
	}

	free(str);
	return true;
}

#endif /* BLACKLIST */

#if HTTPS

#define VECTOR(type)   struct { \
		type *buf; \
		size_t ptr, len; \
	}

#define VEC_INIT   { 0, 0, 0 }

#define VEC_CLEAR(vec)   do { \
		free((vec).buf); \
		(vec).buf = NULL; \
		(vec).ptr = 0; \
		(vec).len = 0; \
	} while (0)

#define VEC_CLEAREXT(vec, fun)   do { \
		size_t vec_tmp; \
		for (vec_tmp = 0; vec_tmp < (vec).ptr; vec_tmp ++) { \
			(fun)(&(vec).buf[vec_tmp]); \
		} \
		VEC_CLEAR(vec); \
	} while (0)

#define VEC_ADD(vec, x)   do { \
		(vec).buf = vector_expand((vec).buf, sizeof *((vec).buf), \
			&(vec).ptr, &(vec).len, 1); \
		(vec).buf[(vec).ptr ++] = (x); \
	} while (0)

#define VEC_ADDMANY(vec, xp, num)   do { \
		size_t vec_num = (num); \
		(vec).buf = vector_expand((vec).buf, sizeof *((vec).buf), \
			&(vec).ptr, &(vec).len, vec_num); \
		memcpy((vec).buf + (vec).ptr, \
			(xp), vec_num * sizeof *((vec).buf)); \
		(vec).ptr += vec_num; \
	} while (0)

#define VEC_ELT(vec, idx)   ((vec).buf[idx])

#define VEC_LEN(vec)   ((vec).ptr)

#define VEC_TOARRAY(vec)    xblobdup((vec).buf, sizeof *((vec).buf) * (vec).ptr)

typedef VECTOR(unsigned char) bvector;

// Type for a named blob (the 'name' is a normalised PEM header name).
typedef struct {
	char *name;
	unsigned char *data;
	size_t data_len;
} pem_object;

static struct {
	int err;
	const char *name;
	const char *comment;
} errors[] = {
	{
		BR_ERR_BAD_PARAM,
		"BR_ERR_BAD_PARAM",
		"Caller-provided parameter is incorrect."
	}, {
		BR_ERR_BAD_STATE,
		"BR_ERR_BAD_STATE",
		"Operation requested by the caller cannot be applied with"
		" the current context state (e.g. reading data while"
		" outgoing data is waiting to be sent)."
	}, {
		BR_ERR_UNSUPPORTED_VERSION,
		"BR_ERR_UNSUPPORTED_VERSION",
		"Incoming protocol or record version is unsupported."
	}, {
		BR_ERR_BAD_VERSION,
		"BR_ERR_BAD_VERSION",
		"Incoming record version does not match the expected version."
	}, {
		BR_ERR_BAD_LENGTH,
		"BR_ERR_BAD_LENGTH",
		"Incoming record length is invalid."
	}, {
		BR_ERR_TOO_LARGE,
		"BR_ERR_TOO_LARGE",
		"Incoming record is too large to be processed, or buffer"
		" is too small for the handshake message to send."
	}, {
		BR_ERR_BAD_MAC,
		"BR_ERR_BAD_MAC",
		"Decryption found an invalid padding, or the record MAC is"
		" not correct."
	}, {
		BR_ERR_NO_RANDOM,
		"BR_ERR_NO_RANDOM",
		"No initial entropy was provided, and none can be obtained"
		" from the OS."
	}, {
		BR_ERR_UNKNOWN_TYPE,
		"BR_ERR_UNKNOWN_TYPE",
		"Incoming record type is unknown."
	}, {
		BR_ERR_UNEXPECTED,
		"BR_ERR_UNEXPECTED",
		"Incoming record or message has wrong type with regards to"
		" the current engine state."
	}, {
		BR_ERR_BAD_CCS,
		"BR_ERR_BAD_CCS",
		"ChangeCipherSpec message from the peer has invalid contents."
	}, {
		BR_ERR_BAD_ALERT,
		"BR_ERR_BAD_ALERT",
		"Alert message from the peer has invalid contents"
		" (odd length)."
	}, {
		BR_ERR_BAD_HANDSHAKE,
		"BR_ERR_BAD_HANDSHAKE",
		"Incoming handshake message decoding failed."
	}, {
		BR_ERR_OVERSIZED_ID,
		"BR_ERR_OVERSIZED_ID",
		"ServerHello contains a session ID which is larger than"
		" 32 bytes."
	}, {
		BR_ERR_BAD_CIPHER_SUITE,
		"BR_ERR_BAD_CIPHER_SUITE",
		"Server wants to use a cipher suite that we did not claim"
		" to support. This is also reported if we tried to advertise"
		" a cipher suite that we do not support."
	}, {
		BR_ERR_BAD_COMPRESSION,
		"BR_ERR_BAD_COMPRESSION",
		"Server wants to use a compression that we did not claim"
		" to support."
	}, {
		BR_ERR_BAD_FRAGLEN,
		"BR_ERR_BAD_FRAGLEN",
		"Server's max fragment length does not match client's."
	}, {
		BR_ERR_BAD_SECRENEG,
		"BR_ERR_BAD_SECRENEG",
		"Secure renegotiation failed."
	}, {
		BR_ERR_EXTRA_EXTENSION,
		"BR_ERR_EXTRA_EXTENSION",
		"Server sent an extension type that we did not announce,"
		" or used the same extension type several times in a"
		" single ServerHello."
	}, {
		BR_ERR_BAD_SNI,
		"BR_ERR_BAD_SNI",
		"Invalid Server Name Indication contents (when used by"
		" the server, this extension shall be empty)."
	}, {
		BR_ERR_BAD_HELLO_DONE,
		"BR_ERR_BAD_HELLO_DONE",
		"Invalid ServerHelloDone from the server (length is not 0)."
	}, {
		BR_ERR_LIMIT_EXCEEDED,
		"BR_ERR_LIMIT_EXCEEDED",
		"Internal limit exceeded (e.g. server's public key is too"
		" large)."
	}, {
		BR_ERR_BAD_FINISHED,
		"BR_ERR_BAD_FINISHED",
		"Finished message from peer does not match the expected"
		" value."
	}, {
		BR_ERR_RESUME_MISMATCH,
		"BR_ERR_RESUME_MISMATCH",
		"Session resumption attempt with distinct version or cipher"
		" suite."
	}, {
		BR_ERR_INVALID_ALGORITHM,
		"BR_ERR_INVALID_ALGORITHM",
		"Unsupported or invalid algorithm (ECDHE curve, signature"
		" algorithm, hash function)."
	}, {
		BR_ERR_BAD_SIGNATURE,
		"BR_ERR_BAD_SIGNATURE",
		"Invalid signature in ServerKeyExchange or"
		" CertificateVerify message."
	}, {
		BR_ERR_WRONG_KEY_USAGE,
		"BR_ERR_WRONG_KEY_USAGE",
		"Peer's public key does not have the proper type or is"
		" not allowed for the requested operation."
	}, {
		BR_ERR_NO_CLIENT_AUTH,
		"BR_ERR_NO_CLIENT_AUTH",
		"Client did not send a certificate upon request, or the"
		" client certificate could not be validated."
	}, {
		BR_ERR_IO,
		"BR_ERR_IO",
		"I/O error or premature close on transport stream."
	}, {
		BR_ERR_X509_INVALID_VALUE,
		"BR_ERR_X509_INVALID_VALUE",
		"Invalid value in an ASN.1 structure."
	},
	{
		BR_ERR_X509_TRUNCATED,
		"BR_ERR_X509_TRUNCATED",
		"Truncated certificate or other ASN.1 object."
	},
	{
		BR_ERR_X509_EMPTY_CHAIN,
		"BR_ERR_X509_EMPTY_CHAIN",
		"Empty certificate chain (no certificate at all)."
	},
	{
		BR_ERR_X509_INNER_TRUNC,
		"BR_ERR_X509_INNER_TRUNC",
		"Decoding error: inner element extends beyond outer element"
		" size."
	},
	{
		BR_ERR_X509_BAD_TAG_CLASS,
		"BR_ERR_X509_BAD_TAG_CLASS",
		"Decoding error: unsupported tag class (application or"
		" private)."
	},
	{
		BR_ERR_X509_BAD_TAG_VALUE,
		"BR_ERR_X509_BAD_TAG_VALUE",
		"Decoding error: unsupported tag value."
	},
	{
		BR_ERR_X509_INDEFINITE_LENGTH,
		"BR_ERR_X509_INDEFINITE_LENGTH",
		"Decoding error: indefinite length."
	},
	{
		BR_ERR_X509_EXTRA_ELEMENT,
		"BR_ERR_X509_EXTRA_ELEMENT",
		"Decoding error: extraneous element."
	},
	{
		BR_ERR_X509_UNEXPECTED,
		"BR_ERR_X509_UNEXPECTED",
		"Decoding error: unexpected element."
	},
	{
		BR_ERR_X509_NOT_CONSTRUCTED,
		"BR_ERR_X509_NOT_CONSTRUCTED",
		"Decoding error: expected constructed element, but is"
		" primitive."
	},
	{
		BR_ERR_X509_NOT_PRIMITIVE,
		"BR_ERR_X509_NOT_PRIMITIVE",
		"Decoding error: expected primitive element, but is"
		" constructed."
	},
	{
		BR_ERR_X509_PARTIAL_BYTE,
		"BR_ERR_X509_PARTIAL_BYTE",
		"Decoding error: BIT STRING length is not multiple of 8."
	},
	{
		BR_ERR_X509_BAD_BOOLEAN,
		"BR_ERR_X509_BAD_BOOLEAN",
		"Decoding error: BOOLEAN value has invalid length."
	},
	{
		BR_ERR_X509_OVERFLOW,
		"BR_ERR_X509_OVERFLOW",
		"Decoding error: value is off-limits."
	},
	{
		BR_ERR_X509_BAD_DN,
		"BR_ERR_X509_BAD_DN",
		"Invalid distinguished name."
	},
	{
		BR_ERR_X509_BAD_TIME,
		"BR_ERR_X509_BAD_TIME",
		"Invalid date/time representation."
	},
	{
		BR_ERR_X509_UNSUPPORTED,
		"BR_ERR_X509_UNSUPPORTED",
		"Certificate contains unsupported features that cannot be"
		" ignored."
	},
	{
		BR_ERR_X509_LIMIT_EXCEEDED,
		"BR_ERR_X509_LIMIT_EXCEEDED",
		"Key or signature size exceeds internal limits."
	},
	{
		BR_ERR_X509_WRONG_KEY_TYPE,
		"BR_ERR_X509_WRONG_KEY_TYPE",
		"Key type does not match that which was expected."
	},
	{
		BR_ERR_X509_BAD_SIGNATURE,
		"BR_ERR_X509_BAD_SIGNATURE",
		"Signature is invalid."
	},
	{
		BR_ERR_X509_TIME_UNKNOWN,
		"BR_ERR_X509_TIME_UNKNOWN",
		"Validation time is unknown."
	},
	{
		BR_ERR_X509_EXPIRED,
		"BR_ERR_X509_EXPIRED",
		"Certificate is expired or not yet valid."
	},
	{
		BR_ERR_X509_DN_MISMATCH,
		"BR_ERR_X509_DN_MISMATCH",
		"Issuer/Subject DN mismatch in the chain."
	},
	{
		BR_ERR_X509_BAD_SERVER_NAME,
		"BR_ERR_X509_BAD_SERVER_NAME",
		"Expected server name was not found in the chain."
	},
	{
		BR_ERR_X509_CRITICAL_EXTENSION,
		"BR_ERR_X509_CRITICAL_EXTENSION",
		"Unknown critical extension in certificate."
	},
	{
		BR_ERR_X509_NOT_CA,
		"BR_ERR_X509_NOT_CA",
		"Not a CA, or path length constraint violation."
	},
	{
		BR_ERR_X509_FORBIDDEN_KEY_USAGE,
		"BR_ERR_X509_FORBIDDEN_KEY_USAGE",
		"Key Usage extension prohibits intended usage."
	},
	{
		BR_ERR_X509_WEAK_PUBLIC_KEY,
		"BR_ERR_X509_WEAK_PUBLIC_KEY",
		"Public key found in certificate is too small."
	},
	{
		BR_ERR_X509_NOT_TRUSTED,
		"BR_ERR_X509_NOT_TRUSTED",
		"Chain could not be linked to a trust anchor."
	},
	{ 0, 0, 0 }
};

// Prepare a vector buffer for adding 'extra' elements.
//   buf      current buffer
//   esize    size of a vector element
//   ptr      pointer to the 'ptr' vector field
//   len      pointer to the 'len' vector field
//   extra    number of elements to add
//
// If the buffer must be enlarged, then this function allocates the new
// buffer and releases the old one. The new buffer address is then returned.
// If the buffer needs not be enlarged, then the buffer address is returned.
//
// In case of enlargement, the 'len' field is adjusted accordingly. The
// 'ptr' field is not modified.
void *
vector_expand(void *buf,
	size_t esize, size_t *ptr, size_t *len, size_t extra)
{
	size_t nlen;
	void *nbuf;

	if (*len - *ptr >= extra) {
		return buf;
	}
	nlen = (*len << 1);
	if (nlen - *ptr < extra) {
		nlen = extra + *ptr;
		if (nlen < 8) {
			nlen = 8;
		}
	}
	nbuf = malloc(nlen * esize);
	if (buf != NULL) {
		memcpy(nbuf, buf, *len * esize);
		free(buf);
	}
	*len = nlen;
	return nbuf;
}

/* see brssl.h */
const char *
find_error_name(int err, const char **comment)
{
	size_t u;

	for (u = 0; errors[u].name; u ++) {
		if (errors[u].err == err) {
			if (comment != NULL) {
				*comment = errors[u].comment;
			}
			return errors[u].name;
		}
	}
	return NULL;
}

void *xblobdup(const void *src, size_t len)
{
	void *buf;

	buf = mymalloc(len);
	memcpy(buf, src, len);
	return buf;
}

char *xstrdup(const void *src)
{
	return xblobdup(src, strlen(src) + 1);
}

int is_ign(int c)
{
	if (c == 0) {
		return 0;
	}
	if (c <= 32 || c == '-' || c == '_' || c == '.'
		|| c == '/' || c == '+' || c == ':')
	{
		return 1;
	}
	return 0;
}

// Get next non-ignored character, normalised:
//    ASCII letters are converted to lowercase
//    control characters, space, '-', '_', '.', '/', '+' and ':' are ignored
// A terminating zero is returned as 0.
static int
next_char(const char **ps, const char *limit)
{
	for (;;) {
		int c;

		if (*ps == limit) {
			return 0;
		}
		c = *(*ps) ++;
		if (c == 0) {
			return 0;
		}
		if (c >= 'A' && c <= 'Z') {
			c += 'a' - 'A';
		}
		if (!is_ign(c)) {
			return c;
		}
	}
}

int eqstr_chunk(const char *s1, size_t s1_len, const char *s2, size_t s2_len)
{
	const char *lim1, *lim2;

	lim1 = s1 + s1_len;
	lim2 = s2 + s2_len;
	for (;;) {
		int c1, c2;

		c1 = next_char(&s1, lim1);
		c2 = next_char(&s2, lim2);
		if (c1 != c2) {
			return 0;
		}
		if (c1 == 0) {
			return 1;
		}
	}
}

int eqstr(const char *s1, const char *s2)
{
	return eqstr_chunk(s1, strlen(s1), s2, strlen(s2));
}

static void
vblob_append(void *cc, const void *data, size_t len)
{
	bvector *bv;

	bv = cc;
	VEC_ADDMANY(*bv, data, len);
}

void free_pem_object_contents(pem_object *po)
{
	if (po != NULL) {
		free(po->name);
		free(po->data);
	}
}

pem_object *decode_pem(const void *src, size_t len, size_t *num)
{
	VECTOR(pem_object) pem_list = VEC_INIT;
	br_pem_decoder_context pc;
	pem_object po, *pos;
	const unsigned char *buf;
	bvector bv = VEC_INIT;
	int inobj;
	int extra_nl;

	*num = 0;
	br_pem_decoder_init(&pc);
	buf = src;
	inobj = 0;
	po.name = NULL;
	po.data = NULL;
	po.data_len = 0;
	extra_nl = 1;
	while (len > 0) {
		size_t tlen;

		tlen = br_pem_decoder_push(&pc, buf, len);
		buf += tlen;
		len -= tlen;
		switch (br_pem_decoder_event(&pc)) {

		case BR_PEM_BEGIN_OBJ:
			po.name = xstrdup(br_pem_decoder_name(&pc));
			br_pem_decoder_setdest(&pc, vblob_append, &bv);
			inobj = 1;
			break;

		case BR_PEM_END_OBJ:
			if (inobj) {
				po.data = VEC_TOARRAY(bv);
				po.data_len = VEC_LEN(bv);
				VEC_ADD(pem_list, po);
				VEC_CLEAR(bv);
				po.name = NULL;
				po.data = NULL;
				po.data_len = 0;
				inobj = 0;
			}
			break;

		case BR_PEM_ERROR:
			free(po.name);
			VEC_CLEAR(bv);
			log_data(LIT("Invalid PEM encoding"));
			VEC_CLEAREXT(pem_list, &free_pem_object_contents);
			return NULL;
		}

		/*
		 * We add an extra newline at the end, in order to
		 * support PEM files that lack the newline on their last
		 * line (this is somwehat invalid, but PEM format is not
		 * standardised and such files do exist in the wild, so
		 * we'd better accept them).
		 */
		if (len == 0 && extra_nl) {
			extra_nl = 0;
			buf = (const unsigned char *)"\n";
			len = 1;
		}
	}
	if (inobj) {
		log_data(LIT("Unfinished PEM object"));
		free(po.name);
		VEC_CLEAR(bv);
		VEC_CLEAREXT(pem_list, &free_pem_object_contents);
		return NULL;
	}

	*num = VEC_LEN(pem_list);
	VEC_ADD(pem_list, po);
	pos = VEC_TOARRAY(pem_list);
	VEC_CLEAR(pem_list);
	return pos;
}

int looks_like_DER(const unsigned char *buf, size_t len)
{
	int fb;
	size_t dlen;

	if (len < 2) {
		return 0;
	}
	if (*buf ++ != 0x30) {
		return 0;
	}
	fb = *buf ++;
	len -= 2;
	if (fb < 0x80) {
		return (size_t)fb == len;
	} else if (fb == 0x80) {
		return 0;
	} else {
		fb -= 0x80;
		if (len < (size_t)fb + 2) {
			return 0;
		}
		len -= (size_t)fb;
		dlen = 0;
		while (fb -- > 0) {
			if (dlen > (len >> 8)) {
				return 0;
			}
			dlen = (dlen << 8) + (size_t)*buf ++;
		}
		return dlen == len;
	}
}

br_x509_certificate *read_certificates_from_buffer(unsigned char *buf, size_t len, size_t *num)
{
	VECTOR(br_x509_certificate) cert_list = VEC_INIT;
	pem_object *pos;
	size_t u, num_pos;
	br_x509_certificate *xcs;
	br_x509_certificate dummy;

	*num = 0;

	// Check for a DER-encoded certificate.
	if (looks_like_DER(buf, len)) {
		xcs = mymalloc(2 * sizeof *xcs);
		xcs[0].data = buf;
		xcs[0].data_len = len;
		xcs[1].data = NULL;
		xcs[1].data_len = 0;
		*num = 1;
		return xcs;
	}

	pos = decode_pem(buf, len, &num_pos);
	if (pos == NULL)
		return NULL;

	for (u = 0; u < num_pos; u ++) {
		if (eqstr(pos[u].name, "CERTIFICATE")
			|| eqstr(pos[u].name, "X509 CERTIFICATE"))
		{
			br_x509_certificate xc;

			xc.data = pos[u].data;
			xc.data_len = pos[u].data_len;
			pos[u].data = NULL;
			VEC_ADD(cert_list, xc);
		}
	}
	for (u = 0; u < num_pos; u ++) {
		free_pem_object_contents(&pos[u]);
	}
	free(pos);

	if (VEC_LEN(cert_list) == 0) {
		log_data(LIT("No certificate in buffer\n"));
		return NULL;
	}
	*num = VEC_LEN(cert_list);
	dummy.data = NULL;
	dummy.data_len = 0;
	VEC_ADD(cert_list, dummy);
	xcs = VEC_TOARRAY(cert_list);
	VEC_CLEAR(cert_list);
	return xcs;
}

br_x509_certificate *read_certificates_from_file(string file, size_t *num)
{
	string data;
	if (!load_file_contents(file, &data))
		return false;
	br_x509_certificate *certs = read_certificates_from_buffer((unsigned char*) data.data, data.size, num);
	free(data.data);
	return certs;
}

void free_certificates(br_x509_certificate *certs, size_t num)
{
	size_t u;

	for (u = 0; u < num; u ++) {
		free(certs[u].data);
	}
	free(certs);
}

static private_key *
decode_key(const unsigned char *buf, size_t len)
{
	br_skey_decoder_context dc;
	int err;
	private_key *sk;

	br_skey_decoder_init(&dc);
	br_skey_decoder_push(&dc, buf, len);
	err = br_skey_decoder_last_error(&dc);
	if (err != 0) {
		const char *errname, *errmsg;

		errname = find_error_name(err, &errmsg);
		if (errname != NULL)
			log_format("Error decoding key: %s: %s (%d)", errname, errmsg, err);
		else
			log_format("Error decoding key: unknown (%d)", err);
		return NULL;
	}
	switch (br_skey_decoder_key_type(&dc)) {
		const br_rsa_private_key *rk;
		const br_ec_private_key *ek;

	case BR_KEYTYPE_RSA:
		rk = br_skey_decoder_get_rsa(&dc);
		sk = mymalloc(sizeof *sk);
		sk->key_type = BR_KEYTYPE_RSA;
		sk->key.rsa.n_bitlen = rk->n_bitlen;
		sk->key.rsa.p = xblobdup(rk->p, rk->plen);
		sk->key.rsa.plen = rk->plen;
		sk->key.rsa.q = xblobdup(rk->q, rk->qlen);
		sk->key.rsa.qlen = rk->qlen;
		sk->key.rsa.dp = xblobdup(rk->dp, rk->dplen);
		sk->key.rsa.dplen = rk->dplen;
		sk->key.rsa.dq = xblobdup(rk->dq, rk->dqlen);
		sk->key.rsa.dqlen = rk->dqlen;
		sk->key.rsa.iq = xblobdup(rk->iq, rk->iqlen);
		sk->key.rsa.iqlen = rk->iqlen;
		break;

	case BR_KEYTYPE_EC:
		ek = br_skey_decoder_get_ec(&dc);
		sk = mymalloc(sizeof *sk);
		sk->key_type = BR_KEYTYPE_EC;
		sk->key.ec.curve = ek->curve;
		sk->key.ec.x = xblobdup(ek->x, ek->xlen);
		sk->key.ec.xlen = ek->xlen;
		break;

	default:
		log_format("Unknown key type: %d\n", br_skey_decoder_key_type(&dc));
		sk = NULL;
		break;
	}

	return sk;
}

private_key *read_private_key(string file)
{
	unsigned char *buf;
	size_t len;
	private_key *sk;
	pem_object *pos;
	size_t num, u;

	buf = NULL;
	pos = NULL;
	sk = NULL;

	string out;
	if (!load_file_contents(file, &out))
		goto deckey_exit;
	buf = (unsigned char*) out.data;
	len = out.size;

	if (looks_like_DER(buf, len)) {
		sk = decode_key(buf, len);
		goto deckey_exit;
	} else {
		pos = decode_pem(buf, len, &num);
		if (pos == NULL) {
			goto deckey_exit;
		}
		for (u = 0; pos[u].name; u ++) {
			const char *name;

			name = pos[u].name;
			if (eqstr(name, "RSA PRIVATE KEY")
				|| eqstr(name, "EC PRIVATE KEY")
				|| eqstr(name, "PRIVATE KEY"))
			{
				sk = decode_key(pos[u].data, pos[u].data_len);
				goto deckey_exit;
			}
		}
		log_data(LIT("No private key in file\n"));
		goto deckey_exit;
	}

deckey_exit:
	if (buf != NULL) {
		free(buf);
	}
	if (pos != NULL) {
		for (u = 0; pos[u].name; u ++) {
			free_pem_object_contents(&pos[u]);
		}
		free(pos);
	}
	return sk;
}

void free_private_key(private_key *sk)
{
	if (sk == NULL) {
		return;
	}
	switch (sk->key_type) {
	case BR_KEYTYPE_RSA:
		free(sk->key.rsa.p);
		free(sk->key.rsa.q);
		free(sk->key.rsa.dp);
		free(sk->key.rsa.dq);
		free(sk->key.rsa.iq);
		break;
	case BR_KEYTYPE_EC:
		free(sk->key.ec.x);
		break;
	}
	free(sk);
}

#endif /* HTTPS */

bool load_file_contents(string file, string *out)
{
	char copy[1<<12];
	if (file.size >= sizeof(copy)) {
		log_data(LIT("File path is larger than the static buffer\n"));
		return false;
	}
	memcpy(copy, file.data, file.size);
	copy[file.size] = '\0';

	int fd = open(copy, O_RDONLY);
	if (fd < 0)
		return false;

	struct stat buf;
	if (fstat(fd, &buf) || !S_ISREG(buf.st_mode)) {
		log_data(LIT("Couldn't stat file or it's not a regular file\n"));
		close(fd);
		return false;
	}
	size_t size = (size_t) buf.st_size;

	char *str = mymalloc(size);
	if (str == NULL) {
		log_data(LIT("out of memory\n"));
		close(fd);
		return false;
	}

	size_t copied = 0;
	while (copied < size) {
		int n = read(fd, str + copied, size - copied);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_perror(LIT("read"));
			close(fd);
			free(str);
			return false;
		}
		if (n == 0)
			break; // EOF
		copied += n;
	}

	close(fd);

	*out = (string) {str, copied};
	return true;
}
