#include "auth.h"

#include "lib/file_system.h"
#include "lib/string_builder.h"

int auth_init(Auth *auth, string password_file, b8 skip_auth_check, Logger *logger)
{
    auth->skip = skip_auth_check;
    auth->logger = logger;

    if (skip_auth_check) {
        auth->password = EMPTY_STRING;
    } else {

        if (password_file.len == 0)
            return -1;

        string password;
        int ret = file_read_all(password_file, &password);
        if (ret < 0)
            return -1;
        void *p = password.ptr;

        password = trim(password);
        if (password.len == 0)
            return -1;

        auth->password = fmtorempty(S("{}"), V(password), auth->password_buf, SIZEOF(auth->password_buf));

        free(p);

        if (auth->password.len == 0)
            return -1;
    }

    for (int i = 0; i < INVALID_NONCE_LIMIT; i++)
        auth->invalid_nonces[i].expire = INVALID_UNIX_TIME;

    return 0;
}

void auth_free(Auth *auth)
{
    // Nothing to be done here, really.

    (void) auth;
}

static int get_request_host(CHTTP_Request *request, string *host, Logger *logger)
{
    int idx = chttp_find_header(request->headers, request->num_headers, CHTTP_STR("Host"));
    if (idx < 0) {
        log(logger, S("Request marked as not authenticated because it's missing the 'Host' header\n"), V());
        return 1;
    }
    *host = request->headers[idx].value;

    // Remove port from the host
    //
    // TODO: verify this loop
    {
        int len = host->len;
        while (len > 0 && is_digit(host->ptr[len-1]))
            len--;
        if (len > 0 && host->ptr[len-1] == ':')
            host->len = len-1;
    }

    return 0;
}

static int get_request_nonce(CHTTP_Request *request, Nonce *nonce, Logger *logger)
{
    int idx = chttp_find_header(request->headers, request->num_headers, CHTTP_STR("X-BlogTech-Nonce"));
    if (idx < 0) {
        log(logger, S("Request marked as not authenticated because it's missing the 'X-BlogTech-Nonce' header\n"), V());
        return 1;
    }
    string nonce_b64 = request->headers[idx].value;

    // Copy the Base64-encoded nonce to a buffer
    char buf[BASE64_LEN(RAW_NONCE_LEN)];
    if (nonce_b64.len > sizeof(buf)) {
        log(logger, S("Request marked as not authenticated because the nonce is too long\n"), V());
        return 1;
    }
    memcpy(buf, nonce_b64.ptr, nonce_b64.len);

    // Decode in-place
    int ret = decode_inplace(buf, nonce_b64.len, sizeof(buf), ENCODING_B64);
    if (ret != RAW_NONCE_LEN) {
        log(logger, S("Request marked as not authenticated because the nonce couldn't be decode from Base64\n"), V());
        return 1;
    }

    // Copy out the result
    memcpy(nonce->data, buf, RAW_NONCE_LEN);
    return 0;
}

static int parse_string_as_u64(string str, u64 *num)
{
    char *src = str.ptr;
    int   len = str.len;
    int   cur = 0;

    if (cur == len || !is_digit(src[cur]))
        return -1;
    *num = src[cur] - '0';
    cur++;

    while (cur < len && is_digit(src[cur])) {

        int d = src[cur] - '0';
        cur++;

        if (*num > (U64_MAX - d) / 10)
            return -1;

        *num = *num * 10 + d;
    }

    if (cur < len)
        return -1;
    return 0;
}

static int parse_string_as_unix_time(string str, UnixTime *time)
{
    u64 buf;
    int ret = parse_string_as_u64(str, &buf);
    if (ret < 0)
        return -1;
    ASSERT(ret == 0);

    if (buf > UNIX_TIME_MAX)
        return -1;
    *time = (UnixTime) buf;
    return 0;
}

static int get_request_timestamp(CHTTP_Request *request, UnixTime *timestamp, Logger *logger)
{
    int idx = chttp_find_header(request->headers, request->num_headers, CHTTP_STR("X-BlogTech-Timestamp"));
    if (idx < 0) {
        log(logger, S("Request marked as not authenticated because it's missing the 'X-BlogTech-Timestamp' header\n"), V());
        return 1;
    }

    int ret = parse_string_as_unix_time(request->headers[idx].value, timestamp);
    if (ret < 0) {
        log(logger, S("Request marked as not authenticated because the 'X-BlogTech-Timestamp' header doesn't contain a valid timestamp\n"), V());
        return 1;
    }

    return 0;
}

static int get_request_expire(CHTTP_Request *request, u32 *expire, Logger *logger)
{
    int idx = chttp_find_header(request->headers, request->num_headers, CHTTP_STR("X-BlogTech-Expire"));
    if (idx < 0) {
        log(logger, S("Request marked as not authenticated because it's missing the 'X-BlogTech-Expire' header\n"), V());
        return 1;
    }

    u64 buf;
    int ret = parse_string_as_u64(request->headers[idx].value, &buf);
    if (ret < 0 || buf > U32_MAX) {
        log(logger, S("Request marked as not authenticated because the 'X-BlogTech-Expire' header is not a valid expiration\n"), V());
        return 1;
    }

    *expire = (u32) buf;
    return 0;
}

static int get_request_signature(CHTTP_Request *request, string *signature, Logger *logger)
{
    int idx = chttp_find_header(request->headers, request->num_headers, CHTTP_STR("X-BlogTech-Signature"));
    if (idx < 0) {
        log(logger, S("Request marked as not authenticated because it's missing the 'X-BlogTech-Signature' header\n"), V());
        return 1;
    }
    *signature = request->headers[idx].value;

    return 0;
}

static b8 streqct(volatile const char *p1,
    volatile const char *p2, int n)
{
    volatile char c = 0;
    for (int i = 0; i < n; i++)
        c |= p1[i] ^ p2[i];
    return (c == 0);
}

static int check_signature(
    string       signature,
    CHTTP_Method method,
    string       path,
    string       host,
    UnixTime     timestamp,
    u32          expire,
    Nonce        nonce,
    string       body,
    string       password,
    Logger*      logger)
{
    char buf[128]; // TODO: this shouldn't be hard-coded
    int ret = calculate_request_signature(
        method,
        path,
        host,
        timestamp,
        expire,
        nonce,
        body,
        password,
        buf,
        sizeof(buf)
    );
    if (ret < 0) {
        log(logger, S("Request verification failed because it wasn't possible to calculate the signature\n"), V());
        return -1;
    }
    string expected = { buf, ret };

    if (signature.len != expected.len) {
        log(logger, S("Request marked as not authenticated because its signature has a wrong length\n"), V());
        return 1;
    }
    if (!streqct(signature.ptr, expected.ptr, expected.len)) {
        log(logger, S("Request marked as not authenticated because its signature is invalid\n"), V());
        return 1;
    }

    return 0;
}

static int check_expiration(UnixTime timestamp, u32 expire, Logger *logger)
{
    UnixTime now = get_current_unix_time();
    if (now == INVALID_UNIX_TIME) {
        log(logger, S("Couldn't read the time to check for expiration\n"), V());
        return -1;
    }

    if (expire > UNIX_TIME_MAX - timestamp) {
        log(logger, S("Expiration and timestamp would overflow\n"), V());
        return 1;
    }

    if (timestamp + expire < now) {
        log(logger, S("Request expired\n"), V());
        return 1;
    }

    return 0;
}

static int check_nonce(Auth *auth, Nonce nonce)
{
    for (int i = 0; i < INVALID_NONCE_LIMIT; i++) {

        // Ignore unused structs
        if (auth->invalid_nonces[i].expire == INVALID_UNIX_TIME)
            continue;

        // If the nonce matches, it is invalid. Note
        // that if the entry in the invalid list is
        // expired, this won't change the result.
        if (!memcmp(&nonce, &auth->invalid_nonces[i].value, sizeof(Nonce)))
            return 1;
    }

    return 0;
}

static int invalidate_nonce(Auth *auth, Nonce nonce,
    UnixTime timestamp, u32 expire)
{
    UnixTime now = get_current_unix_time();
    if (now == INVALID_UNIX_TIME)
        return -1;

    // Find a slot that is unused or expired
    int found = -1;
    for (int i = 0; i < INVALID_NONCE_LIMIT; i++) {
        UnixTime e = auth->invalid_nonces[i].expire;
        if (e == INVALID_UNIX_TIME || e < now) {
            found = i;
            break;
        }
    }

    if (found < 0)
        return -1;

    if (expire > UNIX_TIME_MAX - timestamp)
        return -1;
    UnixTime absolute_expire = timestamp + expire;

    auth->invalid_nonces[found].value = nonce;
    auth->invalid_nonces[found].expire = absolute_expire;
    return 0;
}

int auth_verify(Auth *auth, CHTTP_Request *request)
{
    if (auth->skip) {
        log(auth->logger, S("Skipping request authentication\n"), V());
        return 0;
    }

    log(auth->logger, S("Verifying request authentication\n"), V());

    string path = request->url.path;
    pop_first(&path, '/');

    string host;
    int ret = get_request_host(request, &host, auth->logger);
    if (ret != 0)
        return ret;

    Nonce nonce;
    ret = get_request_nonce(request, &nonce, auth->logger);
    if (ret != 0)
        return ret;

    UnixTime timestamp;
    ret = get_request_timestamp(request, &timestamp, auth->logger);
    if (ret != 0)
        return ret;

    u32 expire;
    ret = get_request_expire(request, &expire, auth->logger);
    if (ret != 0)
        return ret;

    string signature;
    ret = get_request_signature(request, &signature, auth->logger);
    if (ret != 0)
        return ret;

    ret = check_signature(
        signature,
        request->method,
        path,
        host,
        timestamp,
        expire,
        nonce,
        request->body,
        auth->password,
        auth->logger
    );
    if (ret != 0)
        return ret;

    // The signature is valid, but the request may still
    // be unauthenticated due to the request being expired
    // or the nonce already used.

    ret = check_expiration(timestamp, expire, auth->logger);
    if (ret != 0)
        return ret;

    ret = check_nonce(auth, nonce);
    if (ret != 0)
        return ret;

    if (invalidate_nonce(auth, nonce, timestamp, expire) < 0)
        return -1;

    return 0;
}
