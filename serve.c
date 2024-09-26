///////////////////////////////////////////////////////////////////////////////////////////////
/// This is free and unencumbered software released into the public domain.                 ///
///                                                                                         ///
/// Anyone is free to copy, modify, publish, use, compile, sell, or                         ///
/// distribute this software, either in source code form or as a compiled                   ///
/// binary, for any purpose, commercial or non-commercial, and by any                       ///
/// means.                                                                                  ///
///                                                                                         ///
/// In jurisdictions that recognize copyright laws, the author or authors                   ///
/// of this software dedicate any and all copyright interest in the                         ///
/// software to the public domain. We make this dedication for the benefit                  ///
/// of the public at large and to the detriment of our heirs and                            ///
/// successors. We intend this dedication to be an overt act of                             ///
/// relinquishment in perpetuity of all present and future rights to this                   ///
/// software under copyright law.                                                           ///
///                                                                                         ///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,                         ///
/// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF                      ///
/// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.                  ///
/// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR                       ///
/// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,                   ///
/// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR                   ///
/// OTHER DEALINGS IN THE SOFTWARE.                                                         ///
///                                                                                         ///
/// For more information, please refer to <https://unlicense.org>                           ///
///                                                                                         ///
/// NOTE: Some code was adapted from BearSSL. That code uses the MIT license.               ///
///////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////
/// HEADERS                                                                                 ///
///////////////////////////////////////////////////////////////////////////////////////////////

#define _GNU_SOURCE
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
/// CONFIGURATION                                                                           ///
///////////////////////////////////////////////////////////////////////////////////////////////

#ifndef HTTPS
#define HTTPS 0
#endif

#ifdef RELEASE
#define PORT 80
#define HTTPS_PORT 443
#define MAX_CONNECTIONS (1024-2)
#define LOG_BUFFER_SIZE (1<<20)
#define LOG_FILE_LIMIT  (1<<24)
#define LOG_DIRECTORY_SIZE_LIMIT_MB (25 * 1024)
#else
#define PORT 8080
#define HTTPS_PORT 8081
#define MAX_CONNECTIONS 32
#define LOG_BUFFER_SIZE (1<<10)
#define LOG_FILE_LIMIT (1<<20)
#define LOG_DIRECTORY_SIZE_LIMIT_MB 100
#endif

#define KEEPALIVE_MAXREQS 1000

#define LOG_DIRECTORY "logs"

#define HTTPS_KEY_FILE  "key.pem"
#define HTTPS_CERT_FILE "cert.pem"

#define BACKTRACE        1
#define BACKTRACE_FILE   "backtrace.txt"
#define BACKTRACE_LIMIT 30

#define EOPALLOC      0
#define PROFILE       0
#define ACCESS_LOG    1
#define SHOW_IO       0
#define SHOW_REQUESTS 0
#define REQUEST_TIMEOUT_SEC     5
#define CLOSING_TIMEOUT_SEC     2
#define CONNECTION_TIMEOUT_SEC 60
#define LOG_FLUSH_TIMEOUT_SEC   3
#define INPUT_BUFFER_LIMIT_MB   1


static_assert(LOG_BUFFER_SIZE < LOG_FILE_LIMIT, "");

///////////////////////////////////////////////////////////////////////////////////////////////
/// OPTIONAL HEADERS                                                                        ///
///////////////////////////////////////////////////////////////////////////////////////////////

#if HTTPS
#include <bearssl.h>
#endif

#if PROFILE
#include <x86intrin.h>
#endif

#if EOPALLOC
#include <sys/mman.h>
#endif

#if BACKTRACE
#include <dlfcn.h>
#include <execinfo.h>
#endif

///////////////////////////////////////////////////////////////////////////////////////////////
/// TYPES & DEFINITIONS                                                                     ///
///////////////////////////////////////////////////////////////////////////////////////////////

typedef struct {
	char  *data;
	size_t size;
} string;

#define LIT(S) ((string) {.data=(S), .size=sizeof(S)-1})
#define STR(S) ((string) {.data=(S), .size=strlen(S)})
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define SIZEOF(X) ((ssize_t) sizeof(X))
#define COUNTOF(X) (SIZEOF(X) / SIZEOF((X)[0]))
#define NULLSTR ((string) {.data=NULL, .size=0})

#ifndef NDEBUG
#define DEBUG(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#else
#define DEBUG(...) {}
#endif

#if PROFILE
#define TIME(label) for (uint64_t start__ = __rdtsc(), done__ = 0; !done__; timed_scope_result(__COUNTER__, __rdtsc() - start__, LIT(label)), (done__=1))
#else
#define TIME(...)
#endif

#if HTTPS
typedef struct {
	int type;  // BR_KEYTYPE_RSA or BR_KEYTYPE_EC
	union {
		br_rsa_private_key rsa;
		br_ec_private_key ec;
	};
} PrivateKey;

typedef struct {
	br_x509_certificate *items;
	int count;
	int capacity;
} CertArray;

typedef struct {
	int code;
	string name;
	string comment;
} BearSSLErrorInfo;
#endif

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

typedef struct {
	char  *data;
	size_t head;
	size_t size;
	size_t capacity;
} ByteQueue;

typedef struct {
	int fd;
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

///////////////////////////////////////////////////////////////////////////////////////////////
/// FORWARD DECLARATIONS                                                                    ///
///////////////////////////////////////////////////////////////////////////////////////////////

void   log_init(void);
void   log_free(void);
void   log_data(string str);
void   log_fatal(string str);
void   log_perror(string str);
void   log_format(const char *fmt, ...);
void   log_flush(void);
bool   log_empty(void);

void   byte_queue_init(ByteQueue *q);
void   byte_queue_free(ByteQueue *q);
size_t byte_queue_size(ByteQueue *q);
bool   byte_queue_ensure_min_free_space(ByteQueue *q, size_t num);
string byte_queue_start_write(ByteQueue *q);
void   byte_queue_end_write(ByteQueue *q, size_t num);
string byte_queue_start_read(ByteQueue *q);
void   byte_queue_end_read(ByteQueue *q, size_t num);
bool   byte_queue_write(ByteQueue *q, string src);
void   byte_queue_patch(ByteQueue *q, size_t offset, char *src, size_t len);

#if PROFILE
void   timing_init(void);
void   print_timing_results(void);
void   timed_scope_result(int scope_index, uint64_t delta_cycles, string label);
#endif

#if HTTPS
bool   load_private_key_from_file(string file, PrivateKey *pkey);
void   free_private_key(PrivateKey *pkey);
bool   load_certs_from_file(string file, CertArray *array);
void   free_certs(CertArray *array);
BearSSLErrorInfo get_bearssl_error_info(int code);
#endif

char   to_lower(char c);
bool   is_print(char c);
bool   is_pcomp(char c);
bool   is_digit(char c);
bool   is_space(char c);

string trim(string s);
string substr(string str, size_t start, size_t end);
bool   streq(string s1, string s2);
bool   string_match_case_insensitive(string x, string y);
bool   endswith(string suffix, string name);
bool   startswith(string prefix, string str);
void   print_bytes(string prefix, string str);

void  *mymalloc(size_t num);
void   myfree(void *ptr, size_t num);

uint64_t get_real_time_ms(void);
uint64_t get_monotonic_time_ms(void);
uint64_t get_monotonic_time_ns(void);

bool   load_file_contents(string file, string *out);
bool   set_blocking(int fd, bool blocking);
bool   read_from_socket(int fd, ByteQueue *queue);
bool   write_to_socket(int fd, ByteQueue *queue);
int    create_listening_socket(int port);

void   status_line(ResponseBuilder *b, int status);
void   add_header(ResponseBuilder *b, string header);
void   add_header_f(ResponseBuilder *b, const char *fmt, ...);
void   append_content_s(ResponseBuilder *b, string str);
void   append_content_f(ResponseBuilder *b, const char *fmt, ...);
string append_content_start(ResponseBuilder *b, size_t cap);
void   append_content_end(ResponseBuilder *b, size_t num);
bool   serve_file_or_dir(ResponseBuilder *b, string prefix, string docroot, string reqpath, string mime, bool enable_dir_listing);

///////////////////////////////////////////////////////////////////////////////////////////////
/// GLOBALS                                                                                 ///
///////////////////////////////////////////////////////////////////////////////////////////////

volatile sig_atomic_t stop = 0;

Connection conns[MAX_CONNECTIONS];
int num_conns = 0;

uint64_t now;
uint64_t real_now;

int insecure_fd;
int secure_fd;

#if HTTPS
PrivateKey pkey;
CertArray certs;
#endif

int    log_last_file_index = 0;
int    log_fd = -1;
char  *log_buffer = NULL;
size_t log_buffer_used = 0;
bool   log_failed = false;
size_t log_total_size = 0;

///////////////////////////////////////////////////////////////////////////////////////////////
/// IMPLEMENTATION                                                                          ///
///////////////////////////////////////////////////////////////////////////////////////////////

#if BACKTRACE
void crash_signal_handler(int signo)
{
	string signame;
	switch (signo) {
		case SIGSEGV: signame = LIT("Segmentation fault");       break;
		case SIGABRT: signame = LIT("Aborted");                  break;
		case SIGFPE:  signame = LIT("Floating-point exception"); break;
		case SIGILL:  signame = LIT("Illegal instruction");      break;
		default:      signame = LIT("Unknown signal");           break;
	}

	void *stack_buf[BACKTRACE_LIMIT];
	int num_stack = backtrace(stack_buf, COUNTOF(stack_buf));

	char buffer[4096];
	int used = snprintf(buffer, sizeof(buffer), "\n%.*s\nStack trace:\n", (int) signame.size, signame.data);

	for (int i = 0; i < num_stack; i++) {

		int n;
		Dl_info info;
		if (dladdr(stack_buf[i], &info) && info.dli_sname) {
			n = snprintf(buffer + used, sizeof(buffer) - used, "  #%d: %s (%p, %s)\n", i, info.dli_sname, info.dli_fbase, info.dli_fname);
		} else {
			n = snprintf(buffer + used, sizeof(buffer) - used, "  #%d: ??? (%p)\n", i, stack_buf[i]);
		}
		used = MIN(COUNTOF(buffer)-1, used + n);
	}

	int fd = open(BACKTRACE_FILE, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0) return;

	int cpy = 0;
	while (cpy < used) {
		int n = write(fd, buffer + cpy, used - cpy);
		if (n < 0) return;
		cpy += n;
	}

	close(fd);

	signal(signo, SIG_DFL);
	raise(signo);
}
#endif

void termination_signal_handler(int signo) 
{
	(void) signo;
	stop = 1;
}

void init_globals(void)
{
#if BACKTRACE
	struct sigaction sa_crash;
	sa_crash.sa_handler = crash_signal_handler;
	sigemptyset(&sa_crash.sa_mask);
	sa_crash.sa_flags = SA_RESTART | SA_NODEFER;
	sigaction(SIGSEGV, &sa_crash, NULL);
	sigaction(SIGABRT, &sa_crash, NULL);
	sigaction(SIGFPE,  &sa_crash, NULL);
	sigaction(SIGILL,  &sa_crash, NULL);
#endif

	struct sigaction sa_term;
	sa_term.sa_handler = termination_signal_handler;
	sigemptyset(&sa_term.sa_mask);
	sa_term.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &sa_term, NULL);
	sigaction(SIGQUIT, &sa_term, NULL);
	sigaction(SIGINT,  &sa_term, NULL);

	DEBUG("Signals configured\n");

	log_init();
	log_data(LIT("starting\n"));

#if PROFILE
	timing_init();
#endif

	for (int i = 0; i < MAX_CONNECTIONS; i++) {
		conns[i].fd = -1;
		byte_queue_init(&conns[i].input);
		byte_queue_init(&conns[i].output);
	}

	insecure_fd = create_listening_socket(PORT);
	if (insecure_fd < 0) log_fatal(LIT("Couldn't bind\n"));
	log_format("Listening on port %d\n", PORT);

	DEBUG("HTTP started\n");

#if HTTPS
	secure_fd = create_listening_socket(HTTPS_PORT);
	if (secure_fd < 0) log_fatal(LIT("Couldn't bind\n"));
	log_format("Listening on port %d\n", HTTPS_PORT);

	if (!load_certs_from_file(LIT(HTTPS_CERT_FILE), &certs))
		log_fatal(LIT("Couldn't load certificates\n"));
	DEBUG("Certificates loaded\n");

	if (!load_private_key_from_file(LIT(HTTPS_KEY_FILE), &pkey))
		log_fatal(LIT("Couldn't load private key\n"));
	DEBUG("Private key loaded\n");

	DEBUG("HTTPS started\n");
#else
	secure_fd = -1;
#endif
}

void free_globals(void)
{

#if PROFILE
	print_timing_results();
#endif

#if HTTPS
	free_private_key(&pkey);
	free_certs(&certs);
	close(secure_fd);
#endif

	close(insecure_fd);

	for (int i = 0; i < MAX_CONNECTIONS; i++) {
		if (conns[i].fd != -1) {
			close(conns[i].fd);
			byte_queue_free(&conns[i].input);
			byte_queue_free(&conns[i].output);
		}
	}
	log_data(LIT("closing\n"));

	log_free();
}

///////////////////////////////////////////////////////////////////////////////////////////////
/// RESPONSE CALLBACK                                                                       ///
///////////////////////////////////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////////////////////////////
/// REQUEST PARSER                                                                          ///
///////////////////////////////////////////////////////////////////////////////////////////////

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

bool find_header(Request *request, string name, string *value)
{
	for (int i = 0; i < request->nheaders; i++)
		if (string_match_case_insensitive(request->headers[i].name, name)) {
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
		assert(num > 0 && num < SIZEOF(buf));
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

void append_special_headers(ResponseBuilder *b)
{
	if (should_keep_alive(b->conn))
		add_header(b, LIT("Connection: Keep-Alive"));
	else {
		add_header(b, LIT("Connection: Close"));
		b->conn->closing = true;
		b->conn->start_time = now;
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

bool should_keep_alive(Connection *conn)
{
	// Don't keep alive if the peer doesn't want to
	if (conn->keep_alive == false)
		return false;

	// Don't keep alive if the request is too old
	if (now - conn->creation_time > CONNECTION_TIMEOUT_SEC * 1000)
		return false;

	// Don't keep alive if we served a lot of requests to this connection
	if (conn->served_count > KEEPALIVE_MAXREQS)
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

bool respond_to_available_requests(Connection *conn)
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
		TIME("log_access") {
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

		conn->keep_alive = true;
		string keep_alive_header;
		if (find_header(&request, LIT("Connection"), &keep_alive_header)) {
			if (string_match_case_insensitive(trim(keep_alive_header), LIT("Close")))
				conn->keep_alive = false;
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
			if (!conn->keep_alive) {
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

void build_poll_array(struct pollfd pollarray[static MAX_CONNECTIONS+2], int *timeout)
{
	pollarray[0].fd = insecure_fd;
	pollarray[0].events = (num_conns < MAX_CONNECTIONS ? POLLIN : 0);
	pollarray[0].revents = 0;

#if HTTPS
	pollarray[1].fd = secure_fd;
	pollarray[1].events = (num_conns < MAX_CONNECTIONS ? POLLIN : 0);
	pollarray[1].revents = 0;
#else
	pollarray[1].fd = -1;
	pollarray[1].events = 0;
	pollarray[1].revents = 0;
#endif

	Connection *oldest = NULL;

	for (int i = 0; i < MAX_CONNECTIONS; i++) {

		Connection *conn = &conns[i];

		int events = 0;

		if (conn->fd == -1) {
			pollarray[i+2].fd = -1;
			pollarray[i+2].events = 0;
			pollarray[i+2].revents = 0;
			continue;
		}

		if (conn->https) {
#if HTTPS
			int state = br_ssl_engine_current_state(&conn->https_context.eng);
			if (state & BR_SSL_SENDREC) events |= POLLOUT;
			if (state & BR_SSL_RECVREC) events |= POLLIN;
#endif
		} else {
			if (byte_queue_size(&conn->output) > 0)
				events |= POLLOUT;
			if (!conn->closing)
				events |= POLLIN;
		}

		pollarray[i+2].fd = conn->fd;
		pollarray[i+2].events = events;
		pollarray[i+2].revents = 0;

		if (oldest == NULL || deadline_of(oldest) > deadline_of(conn)) oldest = conn;
	}

	if (oldest == NULL)
		*timeout = -1;
	else {
		if (deadline_of(oldest) < now)
			*timeout = 0;
		else
			*timeout = deadline_of(oldest) - now;
	}
}

void init_connection(Connection *conn, int fd, uint32_t ipaddr, bool https)
{
	byte_queue_init(&conn->input);
	byte_queue_init(&conn->output);
	conn->fd = fd;
	conn->ipaddr = ipaddr;
	conn->closing = false;
	conn->https = https;
	conn->served_count = 0;
	conn->creation_time = now;
	conn->start_time = now;
#if HTTPS
	if (https) {
		if (pkey.type == BR_KEYTYPE_RSA)
			br_ssl_server_init_full_rsa(&conn->https_context, certs.items, certs.count, &pkey.rsa);
		else {
			assert(pkey.type == BR_KEYTYPE_EC);
			unsigned issuer_key_type = BR_KEYTYPE_RSA; // Not sure if this or BR_KEYTYPE_EC
			br_ssl_server_init_full_ec(&conn->https_context, certs.items, certs.count, issuer_key_type, &pkey.ec);
		}
		br_ssl_engine_set_versions(&conn->https_context.eng, BR_TLS10, BR_TLS12);
		br_ssl_engine_set_buffer(&conn->https_context.eng, conn->https_buffer, sizeof(conn->https_buffer), 1);
		br_ssl_server_reset(&conn->https_context);
	}
#endif
}

void free_connection(Connection *conn)
{
	assert(conn->fd != -1);
	close(conn->fd);
	byte_queue_free(&conn->input);
	byte_queue_free(&conn->output);
	conn->fd = -1;
	conn->start_time = -1;
	conn->closing = false;
	conn->creation_time = 0;
}

bool accept_connection(int listen_fd, bool https)
{
	// Look for a connection structure
	int index = 0;
	while (index < MAX_CONNECTIONS && conns[index].fd != -1)
		index++;
	if (index == MAX_CONNECTIONS)
		return false; // Stop listening for incoming connections

	struct sockaddr_in accepted_addr;
	socklen_t accepted_addrlen = sizeof(accepted_addr);
	int accepted_fd = accept(listen_fd, (struct sockaddr*) &accepted_addr, &accepted_addrlen);
	if (accepted_fd < 0) {
		if (errno == EINTR)
			return true;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return false;
		log_perror(LIT("accept"));
		return false;
	}
	uint32_t ipaddr = (uint32_t) accepted_addr.sin_addr.s_addr;

	if (!set_blocking(accepted_fd, false)) {
		log_perror(LIT("fcntl"));
		close(accepted_fd);
		return true;
	}

	Connection *conn = &conns[index];
	init_connection(conn, accepted_fd, ipaddr, https);

	assert(num_conns < MAX_CONNECTIONS);
	num_conns++;

	return true;
}

// Returns true iff the connection should be dropped
bool update_connection_http(Connection *conn, struct pollfd *polldata)
{
	// POLLIN
	if ((!conn->closing) && (polldata->revents & (POLLIN | POLLHUP | POLLERR))) {

		if (read_from_socket(conn->fd, &conn->input))
			return true;
		if (respond_to_available_requests(conn))
			return true;

	}

	// POLLOUT
	if (polldata->revents & POLLOUT) {
		if (write_to_socket(conn->fd, &conn->output))
			return true;
		if (byte_queue_size(&conn->output) == 0 && conn->closing)
			return true;
	}

	return false; // Don't close
}

#if HTTPS
// Returns true iff the connection should be dropped
bool update_connection_https(Connection *conn, struct pollfd *polldata)
{
	br_ssl_engine_context *cc = &conn->https_context.eng;
	bool flushed = false;

	for (;;) {

		int state = br_ssl_engine_current_state(cc);

		if (state & BR_SSL_CLOSED) TIME("BR_SSL_CLOSED") {
			// Engine is finished, no more I/O (until next reset).
			int error = br_ssl_engine_last_error(cc);
			if (error != BR_ERR_OK) {
				BearSSLErrorInfo error_info = get_bearssl_error_info(error);
				log_format("SSL failure: %.*s (%.*s)\n",
					(int) error_info.name.size, error_info.name.data,
					(int) error_info.comment.size, error_info.comment.data);
			}

			return true;
		}

		if ((state & BR_SSL_SENDREC) && (polldata->revents & POLLOUT)) TIME("BR_SSL_SENDREC") {
			// Engine has some bytes to send to the peer
			size_t len;
			unsigned char *buf = br_ssl_engine_sendrec_buf(cc, &len);
			size_t copied = 0;
			while (copied < len) {
				int num = send(conn->fd, buf + copied, len - copied, 0);
				if (num < 0) {
					if (errno == EINTR)
						continue;
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						polldata->revents &= ~POLLOUT;
						break;
					}
					log_perror(LIT("send"));
					return true;
				}
				// TODO: Handle num=0
				copied += (size_t) num;
			}
			br_ssl_engine_sendrec_ack(cc, copied);
			flushed = false;
		}

		if ((state & BR_SSL_RECVAPP)) TIME("BR_SSL_RECVAPP") {
			// Engine has obtained some application data from the 
			// peer, that should be read by the caller.
			size_t len;
			unsigned char *buf = br_ssl_engine_recvapp_buf(cc, &len);
			if (!byte_queue_ensure_min_free_space(&conn->input, len))
				return true;
			string dst = byte_queue_start_write(&conn->input);
			assert(dst.size >= len);
			memcpy(dst.data, buf, len);
#if SHOW_IO
			print_bytes(LIT("> "), (string) {dst.data, len});
#endif
			byte_queue_end_write(&conn->input, len);
			br_ssl_engine_recvapp_ack(cc, len);
			if (respond_to_available_requests(conn))
				return true;
			flushed = false;
		}

		if ((state & BR_SSL_RECVREC) && (polldata->revents & POLLIN)) TIME("BR_SSL_RECVREC") {
			// Engine expects some bytes from the peer
			size_t len;
			unsigned char *buf = br_ssl_engine_recvrec_buf(cc, &len);
			size_t copied = 0;
			while (copied < len) {
				int num = recv(conn->fd, buf + copied, len - copied, 0);
				if (num < 0) {
					if (errno == EINTR)
						continue;
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						polldata->revents &= ~POLLIN;
						break;
					}
					log_perror(LIT("recv"));
					return true;
				}
				if (num == 0) {
					return true;
				}
				// TODO: Handle num=0
				copied += (size_t) num;
			}
			br_ssl_engine_recvrec_ack(cc, copied);
			flushed = false;
		}

		if ((state & BR_SSL_SENDAPP) && byte_queue_size(&conn->output) > 0) TIME("BR_SSL_SENDAPP") {
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

		if (flushed) break;
		br_ssl_engine_flush(cc, 0);
		flushed = true;
	}

	int state = br_ssl_engine_current_state(cc);
	if ((state & BR_SSL_SENDREC) == 0 && conn->closing && byte_queue_size(&conn->output) == 0)
		return true;

	return false; // Don't remove
}
#endif

bool update_connection(Connection *conn, struct pollfd *polldata)
{
	bool ok;

	TIME("update") {
#if HTTPS
		if (conn->https)
			TIME("update-https") ok = update_connection_https(conn, polldata);
		else
#endif
		TIME("update-http") ok = update_connection_http(conn, polldata);
	}

	return ok;
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	init_globals();

	log_format("BACKTRACE=%d\n", BACKTRACE);
	log_format("EOPALLOC=%d\n", EOPALLOC);
	log_format("PROFILE=%d\n", PROFILE);
	log_format("ACCESS_LOG=%d\n", ACCESS_LOG);
	log_format("SHOW_IO=%d\n", SHOW_IO);
	log_format("SHOW_REQUESTS=%d\n", SHOW_REQUESTS);

	DEBUG("Globals initialized\n");

	uint64_t last_log_time = 0;
	while (!stop) {

		int timeout;
		struct pollfd pollarray[MAX_CONNECTIONS+2];
		build_poll_array(pollarray, &timeout);

		if (!log_empty()) {
			int log_timeout = (last_log_time + LOG_FLUSH_TIMEOUT_SEC * 1000) - now;
			if (timeout < 0)
				timeout = log_timeout;
			else
				timeout = MIN(log_timeout, timeout);
		}

		int ret = poll(pollarray, MAX_CONNECTIONS+2, timeout);
		if (ret < 0) {
			if (errno == EINTR)
				break; // TODO: Should this be continue?
			log_perror(LIT("poll"));
			return -1;
		}

		now = get_monotonic_time_ms();
		real_now = get_real_time_ms();

		if (pollarray[0].revents & POLLIN)
			while (accept_connection(insecure_fd, false));

#if HTTPS
		if (pollarray[1].revents & POLLIN)
			while (accept_connection(secure_fd, true));
#endif

		for (int i = 0; i < MAX_CONNECTIONS; i++) {

			Connection *conn = &conns[i];
			if (conn->fd == -1)
				continue;

			struct pollfd *polldata = &pollarray[i+2];
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
						log_data(LIT("Request timeout\n"));
					}
				}
			}

			if (!remove)
				remove = update_connection(conn, polldata);

			if (remove) {
				free_connection(conn);
				num_conns--;
			}
		}

		if (now - last_log_time > LOG_FLUSH_TIMEOUT_SEC * 1000) {
			log_flush();
			last_log_time = now;
		}

	} /* main loop end */

	free_globals();
	return 0;
}

#define PATH_SEP '/'

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
			if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
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

///////////////////////////////////////////////////////////////////////////////////////////////
/// LOGGER                                                                                  ///
///////////////////////////////////////////////////////////////////////////////////////////////

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

	if (mkdir(LOG_DIRECTORY, 0755) && errno != EEXIST) {
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

		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
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
		myfree(log_buffer, LOG_BUFFER_SIZE);
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
		fprintf(stderr, "log_failed: %s (%s:%d)\n", strerror(errno), __FILE__, __LINE__);
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

	if (str.size > LOG_BUFFER_SIZE)
		str = LIT("Log message was too long to log");

	if (str.size > LOG_BUFFER_SIZE - log_buffer_used) {
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

///////////////////////////////////////////////////////////////////////////////////////////////
/// BASIC UTILITIES                                                                         ///
///////////////////////////////////////////////////////////////////////////////////////////////

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

uint64_t timespec_to_ns(struct timespec ts)
{
	if ((uint64_t) ts.tv_sec > UINT64_MAX / 1000000000)
		log_fatal(LIT("Time overflow\n"));
	uint64_t ns = ts.tv_sec * 1000000000;

	if (ns > UINT64_MAX - ts.tv_nsec)
		log_fatal(LIT("Time overflow\n"));
	ns += ts.tv_nsec;
	return ns;
}

uint64_t get_monotonic_time_ms(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret) log_fatal(LIT("Couldn't read monotonic time\n"));
	return timespec_to_ms(ts);
}

uint64_t get_monotonic_time_ns(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret) log_fatal(LIT("Couldn't read monotonic time\n"));
	return timespec_to_ns(ts);
}

uint64_t get_real_time_ms(void)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (ret) log_fatal(LIT("Couldn't read real time\n"));
	return timespec_to_ms(ts);
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

char to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	else
		return c;
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

bool is_digit(char c)
{
	return c >= '0' && c <= '9';
}

bool is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool is_print(char c)
{
	return c >= 32 && c < 127;
}

bool is_pcomp(char c)
{
	return c != '/' && c != ':' && is_print(c);
}

bool streq(string s1, string s2)
{
	// TODO: What is s1.data or s2.data is NULL?
	return s1.size == s2.size && !memcmp(s1.data, s2.data, s1.size);
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
			myfree(str, size);
			return false;
		}
		if (n == 0)
			break; // EOF
		copied += n;
	}
	if (copied != size) {
		log_format("Read %d bytes from file but %d were expected\n", copied, size);
		return false;
	}

	close(fd);

	*out = (string) {str, size};
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////
/// BYTE QUEUE                                                                              ///
///////////////////////////////////////////////////////////////////////////////////////////////

void byte_queue_init(ByteQueue *q)
{
	q->data = NULL;
	q->head = 0;
	q->size = 0;
	q->capacity = 0;
}

void byte_queue_free(ByteQueue *q)
{
	myfree(q->data, q->capacity);
	byte_queue_init(q);
}

bool byte_queue_ensure_min_free_space(ByteQueue *q, size_t num)
{
	size_t total_free_space = q->capacity - q->size;
	size_t free_space_after_data = q->capacity - q->size - q->head;

	if (free_space_after_data < num) {
		if (total_free_space < num) {
			// Resize required

			size_t capacity = MAX(2 * q->capacity, q->size + num);

			char *data = mymalloc(capacity);
			if (!data) return false;

			if (q->size > 0)
				memcpy(data, q->data + q->head, q->size);

			myfree(q->data, q->capacity);

			q->data = data;
			q->head = 0;
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
	if (q->data == NULL)
		return NULLSTR;
	return (string) {
		.data = q->data     + (q->head + q->size),
		.size = q->capacity - (q->head + q->size),
	};
}

void byte_queue_end_write(ByteQueue *q, size_t num)
{
	q->size += num;
}

string byte_queue_start_read(ByteQueue *q)
{
	if (q->data == NULL)
		return NULLSTR;
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

///////////////////////////////////////////////////////////////////////////////////////////////
/// SOCKET UTILITIES                                                                        ///
///////////////////////////////////////////////////////////////////////////////////////////////

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

bool set_blocking(int fd, bool blocking)
{
	int flags = fcntl(fd, F_GETFL, 0);

	if (flags == -1)
		return false;

	if (blocking)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags))
		return false;

	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////
/// PROFILING                                                                               ///
///////////////////////////////////////////////////////////////////////////////////////////////

#if PROFILE
typedef struct {
	string label;
	uint64_t delta_cycles;
	uint64_t exec_count;
} TimedScope;

TimedScope timed_scopes[__COUNTER__+1]; // +1 is just to avoid the zero length array
uint64_t timing_init_time_ns;
uint64_t timing_init_time_cycles;

void timing_init(void)
{
	timing_init_time_ns = get_monotonic_time_ns();
	timing_init_time_cycles = __rdtsc();
}

void human_readable_time_interval(uint64_t ns, char *dst, size_t max)
{
    if (ns > 1000000000)
        snprintf(dst, max, "%.1Lf s", (long double) ns / 1000000000);
    else if (ns > 1000000)
        snprintf(dst, max, "%.1Lf ms", (long double) ns / 1000000);
    else if (ns > 1000)
        snprintf(dst, max, "%.1Lf us", (long double) ns / 1000);
    else
        snprintf(dst, max, "%.1Lf ns", (long double) ns);
}

void print_timing_results(void)
{
	uint64_t end_cycles = __rdtsc();
	uint64_t end_ns = get_monotonic_time_ns();

	double cy2ns = (double) (end_ns - timing_init_time_ns) / (end_cycles - timing_init_time_cycles);

	printf("Printing timing results\n");
	for (int i = 0; i < COUNTOF(timed_scopes); i++) {
		TimedScope scope = timed_scopes[i];
		if (scope.exec_count == 0)
			continue;

		char total_str[128];
		char average_str[128];
		human_readable_time_interval(cy2ns * scope.delta_cycles, total_str, sizeof(total_str));
		human_readable_time_interval(cy2ns * scope.delta_cycles / scope.exec_count, average_str, sizeof(average_str));

		printf("%-20.*s| tot %s\t| avg %s\t| calls %lu\n",
			(int) scope.label.size, scope.label.data,
			total_str, average_str, scope.exec_count);
	}
}

void timed_scope_result(int scope_index, uint64_t delta_cycles, string label)
{
	timed_scopes[scope_index].label = label;
	timed_scopes[scope_index].delta_cycles += delta_cycles;
	timed_scopes[scope_index].exec_count++;
}
#endif

///////////////////////////////////////////////////////////////////////////////////////////////
/// ALLOCATORS                                                                              ///
///////////////////////////////////////////////////////////////////////////////////////////////

#if EOPALLOC
void *mymalloc(size_t num)
{
	int page_size = sysconf(_SC_PAGE_SIZE);

	size_t num_pages = (num + page_size - 1) / page_size;
	assert(num_pages > 0);

	void *addr = mmap(NULL, (num_pages + 1) * page_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED)
		return NULL;

	void *head_page = addr;
	addr = (char*) addr + page_size;

	if (mprotect(head_page, page_size, PROT_NONE)) {
		log_perror(LIT("mprotect"));
		exit(-1);
	}

	return addr;
}

void myfree(void *ptr, size_t num)
{
	if (ptr == NULL)
		return;

	int page_size = sysconf(_SC_PAGE_SIZE);
	size_t num_pages = (num + page_size - 1) / page_size;

	void *head_page = (char*) ptr - page_size;

	munmap(head_page, (num_pages + 1) * page_size);
}

#else

void *mymalloc(size_t num)
{
	return malloc(num);
}

void myfree(void *ptr, size_t num)
{
	(void) num;
	free(ptr);
}
#endif

///////////////////////////////////////////////////////////////////////////////////////////////
/// CERTIFICATE AND PRIVATE KEY PARSING (Adapted from BearSSL)                              ///
///////////////////////////////////////////////////////////////////////////////////////////////
/// Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>                                     ///
///                                                                                         ///
/// Permission is hereby granted, free of charge, to any person obtaining                   ///
/// a copy of this software and associated documentation files (the                         ///
/// "Software"), to deal in the Software without restriction, including                     ///
/// without limitation the rights to use, copy, modify, merge, publish,                     ///
/// distribute, sublicense, and/or sell copies of the Software, and to                      ///
/// permit persons to whom the Software is furnished to do so, subject to                   ///
/// the following conditions:                                                               ///
///                                                                                         ///
/// The above copyright notice and this permission notice shall be                          ///
/// included in all copies or substantial portions of the Software.                         ///
///                                                                                         ///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,                         ///
/// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF                      ///
/// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                                   ///
/// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS                     ///
/// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN                      ///
/// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN                       ///
/// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE                        ///
/// SOFTWARE.                                                                               ///
///////////////////////////////////////////////////////////////////////////////////////////////

#if HTTPS
BearSSLErrorInfo bearssl_error_table[] = {
	{ BR_ERR_BAD_PARAM,                LIT("BR_ERR_BAD_PARAM"),                LIT("Caller-provided parameter is incorrect.") },
	{ BR_ERR_BAD_STATE,                LIT("BR_ERR_BAD_STATE"),                LIT("Operation requested by the caller cannot be applied with the current context state (e.g. reading data while outgoing data is waiting to be sent).") },
	{ BR_ERR_UNSUPPORTED_VERSION,      LIT("BR_ERR_UNSUPPORTED_VERSION"),      LIT("Incoming protocol or record version is unsupported.") },
	{ BR_ERR_BAD_VERSION,              LIT("BR_ERR_BAD_VERSION"),              LIT("Incoming record version does not match the expected version.") },
	{ BR_ERR_BAD_LENGTH,               LIT("BR_ERR_BAD_LENGTH"),               LIT("Incoming record length is invalid.") },
	{ BR_ERR_TOO_LARGE,                LIT("BR_ERR_TOO_LARGE"),                LIT("Incoming record is too large to be processed, or buffer is too small for the handshake message to send.") },
	{ BR_ERR_BAD_MAC,                  LIT("BR_ERR_BAD_MAC"),                  LIT("Decryption found an invalid padding, or the record MAC is not correct.") },
	{ BR_ERR_NO_RANDOM,                LIT("BR_ERR_NO_RANDOM"),                LIT("No initial entropy was provided, and none can be obtained from the OS.") },
	{ BR_ERR_UNKNOWN_TYPE,             LIT("BR_ERR_UNKNOWN_TYPE"),             LIT("Incoming record type is unknown.") },
	{ BR_ERR_UNEXPECTED,               LIT("BR_ERR_UNEXPECTED"),               LIT("Incoming record or message has wrong type with regards to the current engine state.") },
	{ BR_ERR_BAD_CCS,                  LIT("BR_ERR_BAD_CCS"),                  LIT("ChangeCipherSpec message from the peer has invalid contents.") },
	{ BR_ERR_BAD_ALERT,                LIT("BR_ERR_BAD_ALERT"),                LIT("Alert message from the peer has invalid contents (odd length).") },
	{ BR_ERR_BAD_HANDSHAKE,            LIT("BR_ERR_BAD_HANDSHAKE"),            LIT("Incoming handshake message decoding failed.") },
	{ BR_ERR_OVERSIZED_ID,             LIT("BR_ERR_OVERSIZED_ID"),             LIT("ServerHello contains a session ID which is larger than 32 bytes.") },
	{ BR_ERR_BAD_CIPHER_SUITE,         LIT("BR_ERR_BAD_CIPHER_SUITE"),         LIT("Server wants to use a cipher suite that we did not claim to support. This is also reported if we tried to advertise a cipher suite that we do not support.") },
	{ BR_ERR_BAD_COMPRESSION,          LIT("BR_ERR_BAD_COMPRESSION"),          LIT("Server wants to use a compression that we did not claim to support.") },
	{ BR_ERR_BAD_FRAGLEN,              LIT("BR_ERR_BAD_FRAGLEN"),              LIT("Server's max fragment length does not match client's.") },
	{ BR_ERR_BAD_SECRENEG,             LIT("BR_ERR_BAD_SECRENEG"),             LIT("Secure renegotiation failed.") },
	{ BR_ERR_EXTRA_EXTENSION,          LIT("BR_ERR_EXTRA_EXTENSION"),          LIT("Server sent an extension type that we did not announce, or used the same extension type several times in a single ServerHello.") },
	{ BR_ERR_BAD_SNI,                  LIT("BR_ERR_BAD_SNI"),                  LIT("Invalid Server Name Indication contents (when used by the server, this extension shall be empty).") },
	{ BR_ERR_BAD_HELLO_DONE,           LIT("BR_ERR_BAD_HELLO_DONE"),           LIT("Invalid ServerHelloDone from the server (length is not 0).") },
	{ BR_ERR_LIMIT_EXCEEDED,           LIT("BR_ERR_LIMIT_EXCEEDED"),           LIT("Internal limit exceeded (e.g. server's public key is too large).") },
	{ BR_ERR_BAD_FINISHED,             LIT("BR_ERR_BAD_FINISHED"),             LIT("Finished message from peer does not match the expected value.") },
	{ BR_ERR_RESUME_MISMATCH,          LIT("BR_ERR_RESUME_MISMATCH"),          LIT("Session resumption attempt with distinct version or cipher suite.") },
	{ BR_ERR_INVALID_ALGORITHM,        LIT("BR_ERR_INVALID_ALGORITHM"),        LIT("Unsupported or invalid algorithm (ECDHE curve, signature algorithm, hash function).") },
	{ BR_ERR_BAD_SIGNATURE,            LIT("BR_ERR_BAD_SIGNATURE"),            LIT("Invalid signature in ServerKeyExchange or CertificateVerify message.") },
	{ BR_ERR_WRONG_KEY_USAGE,          LIT("BR_ERR_WRONG_KEY_USAGE"),          LIT("Peer's public key does not have the proper type or is not allowed for the requested operation.") },
	{ BR_ERR_NO_CLIENT_AUTH,           LIT("BR_ERR_NO_CLIENT_AUTH"),           LIT("Client did not send a certificate upon request, or the client certificate could not be validated.") },
	{ BR_ERR_IO,                       LIT("BR_ERR_IO"),                       LIT("I/O error or premature close on transport stream.") },
	{ BR_ERR_X509_INVALID_VALUE,       LIT("BR_ERR_X509_INVALID_VALUE"),       LIT("Invalid value in an ASN.1 structure.") },
	{ BR_ERR_X509_TRUNCATED,           LIT("BR_ERR_X509_TRUNCATED"),           LIT("Truncated certificate or other ASN.1 object.") },
	{ BR_ERR_X509_EMPTY_CHAIN,         LIT("BR_ERR_X509_EMPTY_CHAIN"),         LIT("Empty certificate chain (no certificate at all).") },
	{ BR_ERR_X509_INNER_TRUNC,         LIT("BR_ERR_X509_INNER_TRUNC"),         LIT("Decoding error: inner element extends beyond outer element size.") },
	{ BR_ERR_X509_BAD_TAG_CLASS,       LIT("BR_ERR_X509_BAD_TAG_CLASS"),       LIT("Decoding error: unsupported tag class (application or private).") },
	{ BR_ERR_X509_BAD_TAG_VALUE,       LIT("BR_ERR_X509_BAD_TAG_VALUE"),       LIT("Decoding error: unsupported tag value.") },
	{ BR_ERR_X509_INDEFINITE_LENGTH,   LIT("BR_ERR_X509_INDEFINITE_LENGTH"),   LIT("Decoding error: indefinite length.") },
	{ BR_ERR_X509_EXTRA_ELEMENT,       LIT("BR_ERR_X509_EXTRA_ELEMENT"),       LIT("Decoding error: extraneous element.") },
	{ BR_ERR_X509_UNEXPECTED,          LIT("BR_ERR_X509_UNEXPECTED"),          LIT("Decoding error: unexpected element.") },
	{ BR_ERR_X509_NOT_CONSTRUCTED,     LIT("BR_ERR_X509_NOT_CONSTRUCTED"),     LIT("Decoding error: expected constructed element, but is primitive.") },
	{ BR_ERR_X509_NOT_PRIMITIVE,       LIT("BR_ERR_X509_NOT_PRIMITIVE"),       LIT("Decoding error: expected primitive element, but is constructed.") },
	{ BR_ERR_X509_PARTIAL_BYTE,        LIT("BR_ERR_X509_PARTIAL_BYTE"),        LIT("Decoding error: BIT STRING length is not multiple of 8.") },
	{ BR_ERR_X509_BAD_BOOLEAN,         LIT("BR_ERR_X509_BAD_BOOLEAN"),         LIT("Decoding error: BOOLEAN value has invalid length.") },
	{ BR_ERR_X509_OVERFLOW,            LIT("BR_ERR_X509_OVERFLOW"),            LIT("Decoding error: value is off-limits.") },
	{ BR_ERR_X509_BAD_DN,              LIT("BR_ERR_X509_BAD_DN"),              LIT("Invalid distinguished name.") },
	{ BR_ERR_X509_BAD_TIME,            LIT("BR_ERR_X509_BAD_TIME"),            LIT("Invalid date/time representation.") },
	{ BR_ERR_X509_UNSUPPORTED,         LIT("BR_ERR_X509_UNSUPPORTED"),         LIT("Certificate contains unsupported features that cannot be ignored.") },
	{ BR_ERR_X509_LIMIT_EXCEEDED,      LIT("BR_ERR_X509_LIMIT_EXCEEDED"),      LIT("Key or signature size exceeds internal limits.") },
	{ BR_ERR_X509_WRONG_KEY_TYPE,      LIT("BR_ERR_X509_WRONG_KEY_TYPE"),      LIT("Key type does not match that which was expected.") },
	{ BR_ERR_X509_BAD_SIGNATURE,       LIT("BR_ERR_X509_BAD_SIGNATURE"),       LIT("Signature is invalid.") },
	{ BR_ERR_X509_TIME_UNKNOWN,        LIT("BR_ERR_X509_TIME_UNKNOWN"),        LIT("Validation time is unknown.") },
	{ BR_ERR_X509_EXPIRED,             LIT("BR_ERR_X509_EXPIRED"),             LIT("Certificate is expired or not yet valid.") },
	{ BR_ERR_X509_DN_MISMATCH,         LIT("BR_ERR_X509_DN_MISMATCH"),         LIT("Issuer/Subject DN mismatch in the chain.") },
	{ BR_ERR_X509_BAD_SERVER_NAME,     LIT("BR_ERR_X509_BAD_SERVER_NAME"),     LIT("Expected server name was not found in the chain.") },
	{ BR_ERR_X509_CRITICAL_EXTENSION,  LIT("BR_ERR_X509_CRITICAL_EXTENSION"),  LIT("Unknown critical extension in certificate.") },
	{ BR_ERR_X509_NOT_CA,              LIT("BR_ERR_X509_NOT_CA"),              LIT("Not a CA, or path length constraint violation.") },
	{ BR_ERR_X509_FORBIDDEN_KEY_USAGE, LIT("BR_ERR_X509_FORBIDDEN_KEY_USAGE"), LIT("Key Usage extension prohibits intended usage.") },
	{ BR_ERR_X509_WEAK_PUBLIC_KEY,     LIT("BR_ERR_X509_WEAK_PUBLIC_KEY"),     LIT("Public key found in certificate is too small.") },
	{ BR_ERR_X509_NOT_TRUSTED,         LIT("BR_ERR_X509_NOT_TRUSTED"),         LIT("Chain could not be linked to a trust anchor.") },
};

BearSSLErrorInfo get_bearssl_error_info(int code)
{
	for (int i = 0; i < COUNTOF(bearssl_error_table); i++)
		if (bearssl_error_table[i].code == code)
			return bearssl_error_table[i];
	BearSSLErrorInfo fallback;
	fallback.code = code;
	fallback.name = LIT("Unknown");
	fallback.comment = LIT(":/");
	return fallback;
}

typedef struct {
	string name;
	string content;
} PemObject;

typedef struct {

	bool   failed;

	char  *buffer;
	size_t buffer_count;
	size_t buffer_capacity;

} PemDecodeContext;

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
char next_char(string *s)
{
	size_t i = 0;
	while (i < s->size && is_ign(s->data[i]))
		i++;

	char c;
	if (i == s->size)
		c = '\0';
	else {
		c = s->data[i++];
		assert(c != '\0');
	}

	s->data += i;
	s->size -= i;
	return to_lower(c);
}

bool eqstr__(string a, string b)
{
	for (;;) {
		char c1 = next_char(&a);
		char c2 = next_char(&b);
		if (c1 != c2) return false;
		if (c1 == 0)  return true;
	}
}

void append_bytes(void *userptr, const void *str, size_t len)
{
	PemDecodeContext *context = userptr;

	if (context->failed)
		return;

	if (context->buffer_capacity - context->buffer_count < len) {

		size_t newcap = MAX(2 * context->buffer_capacity, context->buffer_count + len);
		void  *newstr = mymalloc(newcap);
		if (newstr == NULL) {
			context->failed = true;
			return;
		}

		if (context->buffer) {
			memcpy(newstr, context->buffer, context->buffer_count);
			myfree(context->buffer, context->buffer_capacity);
		}
		context->buffer = newstr;
		context->buffer_capacity = newcap;
	}

	memcpy(context->buffer + context->buffer_count, str, len);
	context->buffer_count += len;
}

typedef struct {
	PemObject *items;
	int count;
	int capacity;
} PemArray;

bool append_pem(PemArray *arr, PemObject obj)
{
	if (arr->count == arr->capacity) {
		int newcap = MAX(2 * arr->capacity, 4);
		PemObject *newitems = mymalloc(newcap * sizeof(PemObject));
		if (newitems == NULL)
			return false;
		if (arr->count)
			memcpy(arr->items, newitems, arr->count * sizeof(PemObject));
		myfree(arr->items, arr->capacity * sizeof(PemObject));
		arr->items = newitems;
		arr->capacity = newcap;
	}

	arr->items[arr->count++] = obj;
	return true;
}

void free_pem_array(PemArray *arr)
{
	for (int i = 0; i < arr->count; i++) {

		string name = arr->items[i].name;
		myfree(name.data, name.size);

		string content = arr->items[i].content;
		if (content.data)
			myfree(content.data, content.size);
	}
	myfree(arr->items, arr->capacity * sizeof(PemObject));
}

bool decode_pem(string src, PemArray *array)
{
	br_pem_decoder_context context;
	br_pem_decoder_init(&context);

	PemDecodeContext context2;
	context2.failed = false;
	context2.buffer = NULL;
	context2.buffer_count = 0;
	context2.buffer_capacity = 0;

	array->items = NULL;
	array->count = 0;
	array->capacity = 0;

	PemObject po;
	po.name = NULLSTR;
	po.content = NULLSTR;

	bool inside_object = false;
	bool extra_newline = true;
	while (src.size > 0) {

		size_t n = br_pem_decoder_push(&context, src.data, src.size);
		src.data += n;
		src.size -= n;

		switch (br_pem_decoder_event(&context)) {
			case BR_PEM_BEGIN_OBJ:
			{
				const char *name = br_pem_decoder_name(&context);
				size_t name_len = strlen(name);

				po.name.data = mymalloc(name_len);
				po.name.size = name_len;

				if (po.name.data == NULL) {
					myfree(context2.buffer, context2.buffer_capacity);
					free_pem_array(array);
					return false;
				}
				memcpy(po.name.data, name, name_len);

				br_pem_decoder_setdest(&context, append_bytes, &context2);
				inside_object = true;
			}
			break;

			case BR_PEM_END_OBJ:
			if (inside_object) {

				void *copy = mymalloc(context2.buffer_count);
				if (copy == NULL) {
					myfree(po.name.data, po.name.size);
					myfree(context2.buffer, context2.buffer_capacity);
					free_pem_array(array);
					return false;
				}
				memcpy(copy, context2.buffer, context2.buffer_count);

				po.content.data = copy;
				po.content.size = context2.buffer_count;

				if (!append_pem(array, po)) {
					myfree(po.name.data, po.name.size);
					myfree(context2.buffer, context2.buffer_capacity);
					free_pem_array(array);
					return false;
				}

				po.name = NULLSTR;
				po.content = NULLSTR;

				context2.buffer_count = 0;
				inside_object = false;
			}
			break;

			case BR_PEM_ERROR:
			myfree(po.name.data, po.name.size);
			myfree(context2.buffer, context2.buffer_capacity);
			free_pem_array(array);
			log_data(LIT("Invalid PEM"));
			return false;
		}

		if (src.size == 0 && extra_newline) {
			src.data = "\n";
			src.size = 1;
			extra_newline = false;
		}
	}

	if (context2.buffer)
		myfree(context2.buffer, context2.buffer_capacity);

	if (context2.failed) {
		myfree(po.name.data, po.name.size);
		free_pem_array(array);
		return false;
	}
	if (inside_object) {
		myfree(po.name.data, po.name.size);
		free_pem_array(array);
		log_data(LIT("Unfinished PEM"));
		return false;
	}

	return true;
}

int looks_like_DER(string content)
{
	int fb;
	size_t dlen;

	if (content.size < 2) {
		return 0;
	}
	if (*content.data ++ != 0x30) {
		return 0;
	}
	fb = *content.data ++;
	content.size -= 2;
	if (fb < 0x80) {
		return (size_t)fb == content.size;
	} else if (fb == 0x80) {
		return 0;
	} else {
		fb -= 0x80;
		if (content.size < (size_t)fb + 2) {
			return 0;
		}
		content.size -= (size_t)fb;
		dlen = 0;
		while (fb -- > 0) {
			if (dlen > (content.size >> 8)) {
				return 0;
			}
			dlen = (dlen << 8) + (size_t)*content.data ++;
		}
		return dlen == content.size;
	}
}

bool decode_key(string src, PrivateKey *pkey)
{
	br_skey_decoder_context context;
	br_skey_decoder_init(&context);
	br_skey_decoder_push(&context, src.data, src.size);

	int err = br_skey_decoder_last_error(&context);
	if (err) {
		BearSSLErrorInfo error_info = get_bearssl_error_info(err);
		log_format("Error decoding key: %.*s: (code=%d, %.*s)\n", 
			(int) error_info.name.size, error_info.name.data, err,
			(int) error_info.comment.size, error_info.comment.data);
		return false;
	}

	switch (br_skey_decoder_key_type(&context)) {

		const br_rsa_private_key *rsa_key;
		const br_ec_private_key *ec_key;

		case BR_KEYTYPE_RSA:
		{
			rsa_key = br_skey_decoder_get_rsa(&context);

			unsigned char *mem = mymalloc(rsa_key->plen + rsa_key->qlen + rsa_key->dplen + rsa_key->dqlen + rsa_key->iqlen);
			if (mem == NULL) return false;

			pkey->type = BR_KEYTYPE_RSA;
			pkey->rsa.n_bitlen = rsa_key->n_bitlen;

			pkey->rsa.p  = mem;
			pkey->rsa.q  = mem + rsa_key->plen;
			pkey->rsa.dp = mem + rsa_key->plen + rsa_key->qlen;
			pkey->rsa.dq = mem + rsa_key->plen + rsa_key->qlen + rsa_key->dplen;
			pkey->rsa.iq = mem + rsa_key->plen + rsa_key->qlen + rsa_key->dplen + rsa_key->dqlen;

			memcpy(pkey->rsa.p, rsa_key->p, rsa_key->plen);
			memcpy(pkey->rsa.q, rsa_key->q, rsa_key->qlen);
			memcpy(pkey->rsa.dp, rsa_key->dp, rsa_key->dplen);
			memcpy(pkey->rsa.dq, rsa_key->dq, rsa_key->dqlen);
			memcpy(pkey->rsa.iq, rsa_key->iq, rsa_key->iqlen);

			pkey->rsa.plen = rsa_key->plen;
			pkey->rsa.qlen = rsa_key->qlen;
			pkey->rsa.dplen = rsa_key->dplen;
			pkey->rsa.dqlen = rsa_key->dqlen;
			pkey->rsa.iqlen = rsa_key->iqlen;
		}
		break;

		case BR_KEYTYPE_EC:
		{
			ec_key = br_skey_decoder_get_ec(&context);
			pkey->type = BR_KEYTYPE_EC;
			pkey->ec.curve = ec_key->curve;
			pkey->ec.x = mymalloc(ec_key->xlen);
			if (pkey->ec.x == NULL)
				return false;
			memcpy(pkey->ec.x, ec_key->x, ec_key->xlen);
			pkey->ec.xlen = ec_key->xlen;
		}
		break;
	
		default:
		log_format("Unknown key type: %d\n", br_skey_decoder_key_type(&context));
		return false;
	}

	return true;
}

bool load_private_key_from_file(string file, PrivateKey *pkey)
{
	string file_contents;
	if (!load_file_contents(file, &file_contents))
		return false;

	DEBUG("loading key: file contents loaded\n");

	bool ok;
	if (looks_like_DER(file_contents)) {
		DEBUG("loading key: detected DER file\n");
		ok = decode_key(file_contents, pkey);
	} else {

		DEBUG("loading key: detected PEM file\n");

		PemArray pem_array;
		if (!decode_pem(file_contents, &pem_array)) {
			myfree(file_contents.data, file_contents.size);
			return false;
		}

		bool found = false;
		bool decoded = false;
		for (int i = 0; i < pem_array.count; i++)
			if (eqstr__(pem_array.items[i].name, LIT("RSA PRIVATE KEY"))
				|| eqstr__(pem_array.items[i].name, LIT("EC PRIVATE KEY"))
				|| eqstr__(pem_array.items[i].name, LIT("PRIVATE KEY"))) {

				DEBUG("loading key: found key in PEM file\n");

				if (decode_key(pem_array.items[i].content, pkey))
					decoded = true;

				found = true;
				break;
			}

		ok = false;
		if (!found)
			log_data(LIT("Missing private key in file\n"));
		else {
			if (!decoded)
				log_data(LIT("Couldn't decode key\n"));
			else
				ok = true;
		}
		free_pem_array(&pem_array);
	}

	myfree(file_contents.data, file_contents.size);
	return ok;
}

void free_private_key(PrivateKey *pkey)
{
	switch (pkey->type) {
	
		case BR_KEYTYPE_RSA:
		myfree(pkey->rsa.p, pkey->rsa.plen + pkey->rsa.qlen + pkey->rsa.dplen + pkey->rsa.dqlen + pkey->rsa.iqlen);
		break;

		case BR_KEYTYPE_EC:
		myfree(pkey->ec.x, pkey->ec.xlen);
		break;
	}
}

bool append_cert(CertArray *arr, br_x509_certificate cert)
{
	if (arr->count == arr->capacity) {
		int newcap = MAX(2 * arr->capacity, 4);
		br_x509_certificate *newitems = mymalloc(newcap * sizeof(br_x509_certificate));
		if (newitems == NULL)
			return false;
		if (arr->count)
			memcpy(arr->items, newitems, arr->count * sizeof(br_x509_certificate));
		myfree(arr->items, arr->capacity * sizeof(br_x509_certificate));
		arr->items = newitems;
		arr->capacity = newcap;
	}

	arr->items[arr->count++] = cert;
	return true;
}

bool load_certs_from_file(string file, CertArray *array)
{
	string file_contents;
	if (!load_file_contents(file, &file_contents))
		return false;
	
	DEBUG("loading certs: file contents loaded\n");

	array->items = NULL;
	array->count = 0;
	array->capacity = 0;

	if (looks_like_DER(file_contents)) {

		DEBUG("loading certs: detected DER file\n");

		br_x509_certificate xc = {
			(unsigned char*) file_contents.data,
			file_contents.size,
		};
		if (!append_cert(array, xc)) {
			myfree(file_contents.data, file_contents.size);
			return false;
		}

		DEBUG("loading certs: DER file parsed\n");

	} else {

		DEBUG("loading certs: detected PEM file\n");

		PemArray pem_array;
		if (!decode_pem(file_contents, &pem_array)) {
			myfree(file_contents.data, file_contents.size);
			return false;
		}

		DEBUG("loading certs: PEM file parsed (%d entries)\n", pem_array.count);

		for (int i = 0; i < pem_array.count; i++) {

			PemObject po = pem_array.items[i];

			if (eqstr__(po.name, LIT("CERTIFICATE")) || eqstr__(po.name, LIT("X509 CERTIFICATE"))) {

				DEBUG("loading certs: found certificate in PEM file\n");

				br_x509_certificate xc = { (unsigned char*) po.content.data, po.content.size };

				if (!append_cert(array, xc)) {
					free_pem_array(&pem_array);
					free_certs(array);
					myfree(file_contents.data, file_contents.size);
					return false;
				}

				pem_array.items[i].content = NULLSTR;
			} else {
				DEBUG("loading certs: ignoring entry [%.*s] in PEM file\n", (int) po.name.size, po.name.data);
			}
		}

		DEBUG("loading certs: finished loading certificates from PEM file\n");

		if (array->count == 0) {
			free_pem_array(&pem_array);
			free_certs(array);
			myfree(file_contents.data, file_contents.size);
			log_data(LIT("No certificates in file\n"));
			return false;
		}

		free_pem_array(&pem_array);
		myfree(file_contents.data, file_contents.size);
	}

	DEBUG("loading certs: certificate loaded\n");
	return true;
}

void free_certs(CertArray *array)
{
	for (int i = 0; i < array->count; i++) {
		br_x509_certificate item = array->items[i];
		myfree(item.data, item.data_len);
	}
	myfree(array->items, array->capacity * sizeof(br_x509_certificate));
}
#endif /* HTTPS */
