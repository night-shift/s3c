#include "s3c.h"

#include <assert.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    "OpenSSL version 1.1.0 or higher is required"
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>


static const char* S3_SIGNATURE_PREFIX  = "AWS4";
static const char* S3_SIGNATURE_ALGO    = "AWS4-HMAC-SHA256";
static const char* S3_REQUEST_TYPE      = "aws4_request";
static const char* S3_HTTP_VERSION      = "HTTP/1.1";

#define S3C_SHA256_BIN_SIZE 32
#define S3C_SHA256_HEX_SIZE (S3C_SHA256_BIN_SIZE * 2)

#define S3C_DATE_TIME_STAMP_SIZE sizeof("yyyymmddThhmmssZ")
#define S3C_DATE_STAMP_SIZE      sizeof("yyyymmdd")

static struct {
    uint32_t net_io_timeout_sec;
    uint32_t max_reply_prealloc_size_mb;
    uint32_t str_buf_max_cap_reserve_mb;
    uint32_t multipart_file_sz_trigger_mb;
    uint32_t multipart_send_max_retries;

} S3C_GLOBAL_CONFS = {
    .net_io_timeout_sec           = 15,
    .max_reply_prealloc_size_mb   = 128,
    .str_buf_max_cap_reserve_mb   = 10,
    .multipart_file_sz_trigger_mb = 6,
    .multipart_send_max_retries   = 2,
};

typedef struct {
    SSL*     ssl;
    SSL_CTX* ssl_ctx;
} OsslContext;

static const char* ossl_init(OsslContext*);
static void        ossl_free(OsslContext*);
static const char* ossl_connect(OsslContext*, const char* host);

typedef struct {
    const char*    bucket;
    const char*    object_key;
    const uint8_t* data;
    uint64_t       data_size;
    FILE*          fp;
    const s3cKVL*  headers;
    const s3cKVL*  query_args;
} OpArgs;

typedef struct {
    bool           ok;
    const s3cKeys* keys;
    s3cReply*      reply;
    OsslContext*   ossl_ctx;
    OpArgs         args;
} OpContext;

typedef struct {
    char*  ptr;
    size_t len;
    size_t cap;
} StrBuf;

typedef struct {
    char date_time [S3C_DATE_TIME_STAMP_SIZE];
    char date      [S3C_DATE_STAMP_SIZE];
} DateStamps;

static void op_context_init(OpContext*, OpArgs args, const s3cKeys*,  s3cReply*);
static void op_context_free(OpContext*);
static void op_run_request(OpContext* op, const char* html_verb);
static void op_send_request(OpContext*, StrBuf* http_request);
static void op_read_reply(OpContext*);
static void op_proc_reply(OpContext*, StrBuf* reply, unsigned http_resp_code);
static void op_set_error(OpContext* op, const char* error);
static void op_set_error_fmt(OpContext* op, const char* fmt, ...);

static StrBuf str_init(size_t cap);
static size_t str_set_cap(StrBuf*, size_t cap);
static void   str_destroy(StrBuf*);
static size_t str_push(StrBuf*, const char* a, size_t a_len);
static size_t str_push_char(StrBuf*, char);
static size_t str_push_int(StrBuf*, int64_t);
static size_t str_push_str(StrBuf*, const StrBuf*);
static size_t str_push_cstr(StrBuf*, const char*);
static size_t str_push_many(StrBuf* s, ...);
static size_t str_set(StrBuf*, const char*);
static char*  str_extract(StrBuf*);

static void s3c_kvl_upsert(s3cKVL** head, const char* name, const char* value);

uint32_t
s3c_set_global_config(uint32_t opt, uint32_t value)
{
    switch (opt) {
        case S3C_CONF_NET_IO_TIMEOUT_SEC:
            S3C_GLOBAL_CONFS.net_io_timeout_sec = value;
            return 1;

        case S3C_CONF_MAX_REPLY_PREALLOC_SIZE_MB:
            S3C_GLOBAL_CONFS.max_reply_prealloc_size_mb = value;
            return 1;
    }

    return 0;
}

static char*
str_dup(const char* s)
{
    size_t len = strlen(s);
    char* res = malloc(len + 1);

    memcpy(res, s, len + 1);

    return res;
}

s3cReply*
s3c_reply_alloc(const char* error)
{
    s3cReply* reply = calloc(1, sizeof(s3cReply));

    reply->error = NULL;

    if (error != NULL) {
        char* copy = str_dup(error);
        reply->error = copy;
    }

    return reply;
}

void
s3c_reply_free(s3cReply* reply)
{
    if (reply == NULL) {
        return;
    }

    s3c_kvl_free(reply->headers);

    free(reply->error);
    free(reply->data);

    free(reply);
}

static s3cReply*
check_arg_str(const char* arg, const char* arg_name)
{
    StrBuf err_buf = str_init(0);

    if (arg == NULL) {

        str_push_many(
            &err_buf,
            "provided arguments missing value for <", arg_name, ">", NULL
        );

    } else if (*arg == '\0') {
        str_push_many(
            &err_buf,
            "provided argument empty string for value <", arg_name, ">", NULL
        );
    }

    if (err_buf.len > 0) {
        s3cReply* rep = s3c_reply_alloc(err_buf.ptr);
        str_destroy(&err_buf);

        return rep;
    }

    return NULL;
}

static s3cReply*
check_arg_bucket_key(const char* bucket, const char* object_key)
{
    s3cReply* err = NULL;

    err = check_arg_str(bucket, "bucket");
    if (err != NULL) {
        return err;
    }

    err = check_arg_str(object_key, "object_key");
    if (err != NULL) {
        return err;
    }

    return NULL;
}

static s3cReply*
run_s3_op(const s3cKeys* keys, const char* html_verb, OpArgs args)
{
    OpContext* op = calloc(1, sizeof(OpContext));
    s3cReply* reply = s3c_reply_alloc(NULL);

    op_context_init(op, args, keys, reply);

    if (!op->ok) {
        goto cleanup_and_ret;
    }

    op_run_request(op, html_verb);

cleanup_and_ret:
    op_context_free(op);

    return reply;
}

s3cReply*
s3c_get_object(const s3cKeys* keys,
               const char* bucket, const char* object_key)
{
    s3cReply* err = NULL;

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key
    };

    return run_s3_op(keys, "GET", args);
}

s3cReply*
s3c_get_object_to_file(const s3cKeys* keys,
                       const char* bucket, const char* object_key,
                       const char* file)
{
    s3cReply* err = NULL;

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }


    if ((err = check_arg_str(file, "out_file")) != NULL) {
        return err;
    }

    FILE* fp = fopen(file, "w");

    if (fp == NULL) {
        err = s3c_reply_alloc("failed to open file for write");
        return err;
    }

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .fp = fp,
    };

    s3cReply* res = run_s3_op(keys, "GET", args);

    fclose(fp);

    return res;
}

s3cReply*
s3c_put_object(const s3cKeys* keys,
               const char* bucket, const char* object_key,
               const uint8_t* data, uint64_t data_size,
               const s3cKVL* headers)
{
    s3cReply* err = check_arg_bucket_key(bucket, object_key);

    if (err != NULL) {
        return err;
    }

    if (data == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <data>");
    }

    if (!data_size) {
        return s3c_reply_alloc("provided argument value for <data_size> is 0");
    }

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .data = data,
        .data_size = data_size,
        .headers = headers,
    };

    s3cReply* reply = run_s3_op(keys, "PUT", args);

    return reply;
}

static void
parse_xml_tag(const char* xml, const char* tag_name, StrBuf* out_buf)
{
    StrBuf tag_str = str_init(strlen(tag_name) + strlen("<>/"));
    str_set(out_buf, "");

    str_push_many(&tag_str, "<", tag_name, ">", NULL);

    const char* msg_start = strstr(xml, tag_str.ptr);

    if (msg_start == NULL) {
        goto cleanup_and_ret;
    }

    msg_start += tag_str.len;

    tag_str.len = 0;
    str_push_many(&tag_str, "</", tag_name, ">", NULL);

    const char* msg_end = strstr(msg_start, tag_str.ptr);

    if (msg_end == NULL) {
        goto cleanup_and_ret;
    }

    ptrdiff_t diff = msg_end - msg_start;
    str_push(out_buf, msg_start, diff);

cleanup_and_ret:
    str_destroy(&tag_str);
}

static s3cReply*
s3c_multipart_upload_abort(const s3cKeys* keys,
                           const char* bucket, const char* obj_key,
                           const char* upload_id)
{
    s3cKVL query_args = {
        .key = "uploadId",
        .value = (char*)upload_id,
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = obj_key,
        .query_args = &query_args,
    };

    return run_s3_op(keys, "DELETE", args);
}

static s3cReply*
s3c_multipart_upload_init(const s3cKeys* keys,
                          const char* bucket, const char* object_key,
                          const s3cKVL* headers,
                          StrBuf* out_upload_id)
{
    s3cKVL query_args = {
        .key = "uploads",
        .value = "",
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .headers = headers,
        .query_args = &query_args,
    };

    s3cReply* reply = run_s3_op(keys, "POST", args);

    if (reply->error) {
        return reply;
    }

    if (reply->data == NULL) {
        reply->error = str_dup("multipart init failed to parse reply upload id, no reply body");
        return reply;
    }

    str_set(out_upload_id, "");
    parse_xml_tag((const char*)reply->data, "UploadId", out_upload_id);

    if (out_upload_id->len < 1) {
        reply->error = str_dup("multipart init failed to parse reply upload id");
        return reply;
    }

    return reply;
}

static s3cReply*
s3c_multipart_upload_finish(const s3cKeys* keys,
                           const char* bucket, const char* object_key,
                           const char* upload_id, s3cKVL* etags)
{
    StrBuf body = str_init(512);
    StrBuf error_tag = {0};

    str_push_cstr(&body, "<CompleteMultipartUpload "
                         "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    s3cKVL* etag = etags;
    int part_num = 0;

    for (; etag != NULL; etag = etag->next, part_num++) {
        str_push_many(
            &body,
            "<Part>",
            "<ETag>", etag->value, "</ETag>",
            "<PartNumber>",
            NULL
        );
        str_push_int(&body, part_num + 1);
        str_push_cstr(&body, "</PartNumber></Part>");
    }

    str_push_cstr(&body, "</CompleteMultipartUpload>");

    s3cKVL query_args = {
        .key = "uploadId",
        .value = (char*)upload_id,
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .data = (const uint8_t*)body.ptr,
        .data_size = body.len,
        .query_args = &query_args,
    };

    s3cReply* reply = run_s3_op(keys, "POST", args);

    if (reply->error) {
        goto cleanup_and_ret;
    }

    // CompleteMultipartUpload can return 200 OK with error specified in body
    parse_xml_tag((const char*)reply->data, "Error", &error_tag);

    if (error_tag.len > 0) {
        parse_xml_tag((const char*)reply->data, "Message", &error_tag);

        reply->error = error_tag.len > 0
            ? str_extract(&error_tag)
            : str_dup((const char*)reply->data);
    }


cleanup_and_ret:
    str_destroy(&body);
    str_destroy(&error_tag);
    return reply;
}

static s3cReply*
s3c_multipart_upload_run(const s3cKeys* keys, const char* bucket, const char* obj_key,
                         FILE* fp, size_t file_size, const char* upload_id)
{
    const size_t MULTIPART_CHUNK_SZ = 5 * 1024 * 1024;

    uint8_t* chunk_buf = malloc(MULTIPART_CHUNK_SZ);
    s3cReply* reply = NULL;
    s3cKVL* etags_head = NULL;
    s3cKVL* etags_tail = NULL;
    StrBuf iota_buf = {0};

    fseek(fp, 0, SEEK_SET);

    size_t left_to_send = file_size;

    s3cKVL q_arg_upload_id = {
        .key = "uploadId",
        .value = (char*)upload_id,
    };

    s3cKVL q_arg_part_num = {
        .key = "partNumber",
        .value = NULL,
        .next = &q_arg_upload_id,
    };

    OpArgs op_args = {
        .bucket = bucket,
        .object_key = obj_key,
        .query_args = &q_arg_part_num,
    };

    int part_number = 0;

    while (left_to_send > 0) {
        size_t send_now = left_to_send > MULTIPART_CHUNK_SZ
            ? MULTIPART_CHUNK_SZ
            : left_to_send;

        size_t bytes_read = fread(chunk_buf, 1, send_now, fp);

        if (bytes_read < send_now) {
            reply = s3c_reply_alloc("failed to read file");
            goto cleanup_and_ret;
        }

        iota_buf.len = 0;
        str_push_int(&iota_buf, part_number + 1);
        q_arg_part_num.value = iota_buf.ptr;

        op_args.data = chunk_buf;
        op_args.data_size = send_now;

        unsigned num_retries = 0;

        while (1) {
            reply = run_s3_op(keys, "PUT", op_args);

            if (reply->error == NULL) {
                break;
            }

            bool server_err = reply->http_resp_code == 500 ||
                              reply->http_resp_code == 502 ||
                              reply->http_resp_code == 503 ||
                              reply->http_resp_code == 504;

            if (!server_err || num_retries >= S3C_GLOBAL_CONFS.multipart_send_max_retries) {
                goto cleanup_and_ret;
            }

            s3c_reply_free(reply);
            num_retries += 1;
        }

        s3cKVL* etag = s3c_kvl_find(reply->headers, "ETag");

        if (etag == NULL) {
            s3c_reply_free(reply);
            reply = s3c_reply_alloc("S3 reply missing header ETag");
            goto cleanup_and_ret;
        }

        s3cKVL* etag_copy = malloc(sizeof(s3cKVL));
        *etag_copy = *etag;
        etag->key = NULL;
        etag->value = NULL;
        etag_copy->next = NULL;

        if (etags_head == NULL) {
            etags_head = etag_copy;
        } else {
            etags_tail->next = etag_copy;
        }

        etags_tail = etag_copy;
        left_to_send -= send_now;
        part_number += 1;
        s3c_reply_free(reply);
    }

    reply = s3c_multipart_upload_finish(
        keys, bucket, obj_key, upload_id, etags_head
    );

cleanup_and_ret:
    free(chunk_buf);
    s3c_kvl_free(etags_head);
    str_destroy(&iota_buf);

    return reply;
}

s3cReply*
s3c_put_object_from_file(const s3cKeys* keys,
                         const char* bucket, const char* object_key,
                         const char* file, const s3cKVL* headers)
{
    size_t multipart_size_lim =
        S3C_GLOBAL_CONFS.multipart_file_sz_trigger_mb
        * 1024 * 1024;

    s3cReply* err = check_arg_bucket_key(bucket, object_key);

    if (err != NULL) {
        return err;
    }

    if ((err = check_arg_str(file, "file")) != NULL) {
        return err;
    }

    s3cReply* reply = NULL;
    uint8_t* file_buf = NULL;
    StrBuf upload_id = {0};
    FILE* fp = fopen(file, "r");

    if (fp == NULL) {
        reply = s3c_reply_alloc("failed to open file for read");
        goto cleanup_and_ret;
    }

    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size < multipart_size_lim) {
        file_buf = malloc(file_size);

        if (file_buf == NULL) {
            reply = s3c_reply_alloc("failed to alloc file buf");
            goto cleanup_and_ret;
        }

        size_t bytes_read = fread(file_buf, 1, file_size, fp);

        if (bytes_read < file_size) {
            reply = s3c_reply_alloc("failed to read file");
            goto cleanup_and_ret;
        }

        OpArgs args = {
            .bucket = bucket,
            .object_key = object_key,
            .headers = headers,
            .data = (const uint8_t*)file_buf,
            .data_size = file_size,
        };

        reply = run_s3_op(keys, "PUT", args);
        goto cleanup_and_ret;
    }

    reply = s3c_multipart_upload_init(
        keys, bucket, object_key, headers,
        &upload_id
    );

    if (reply->error) {
        goto cleanup_and_ret;
    }

    s3c_reply_free(reply);

    reply = s3c_multipart_upload_run(
        keys, bucket, object_key,
        fp, file_size, upload_id.ptr
    );

    if (reply->error) {
        s3cReply* abort = s3c_multipart_upload_abort(
            keys, bucket, object_key, upload_id.ptr
        );

        s3c_reply_free(abort);
        goto cleanup_and_ret;
    }


cleanup_and_ret:
    if (fp != NULL) {
        fclose(fp);
    }
    free(file_buf);
    str_destroy(&upload_id);

    return reply;
}

s3cReply*
s3c_delete_object(const s3cKeys* keys,
                  const char* bucket, const char* object_key)
{
    s3cReply* err = NULL;

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
    };

    return run_s3_op(keys, "DELETE", args);
}

s3cReply*
s3c_create_bucket(const s3cKeys* keys, const char* bucket, const s3cKVL* headers)
{
    s3cReply* err = NULL;

    if ((err = check_arg_str(bucket, "bucket")) != NULL) {
        return err;
    }

    StrBuf req_body = str_init(256);
    str_push_cstr(&req_body, "<CreateBucketConfiguration "
                             "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                             "<LocationConstraint>");
    str_push_cstr(&req_body, keys->region);
    str_push_cstr(&req_body, "</LocationConstraint>"
                             "</CreateBucketConfiguration>");
    OpArgs args = {
        .bucket = bucket,
        .data = (const uint8_t*)req_body.ptr,
        .data_size = req_body.len,
        .headers = headers,
    };

    s3cReply* reply = run_s3_op(keys, "PUT", args);
    str_destroy(&req_body);

    return reply;
}

s3cReply*
s3c_delete_bucket(const s3cKeys* keys, const char* bucket)
{
    s3cReply* err = NULL;

    if ((err = check_arg_str(bucket, "bucket")) != NULL) {
        return err;
    }

    OpArgs args = {
        .bucket = bucket
    };

    return run_s3_op(keys, "DELETE", args);
}

static void
set_date_stamps(DateStamps* dates)
{
    time_t unix_now;
    time(&unix_now);

    struct tm* cal_now = gmtime(&unix_now);

    size_t fmt_res = strftime(dates->date_time, S3C_DATE_TIME_STAMP_SIZE,
                              "%Y%m%dT%H%M%SZ",
                              cal_now);
    assert(fmt_res == 16);

    memcpy(dates->date, dates->date_time, S3C_DATE_STAMP_SIZE - 1);
    dates->date[S3C_DATE_STAMP_SIZE - 1] = '\0';
}

static StrBuf
get_req_host(const s3cKeys* keys)
{
    StrBuf endpoint = str_init(128);

    const char* conf_endpoint = keys->endpoint;

    if (conf_endpoint == NULL || *conf_endpoint == '\0') {
        str_set      (&endpoint, "s3.");
        str_push_cstr(&endpoint, keys->region);
        str_push_cstr(&endpoint, ".amazonaws.com");

        return endpoint;
    }

    char* proto = strstr(conf_endpoint, "https://");

    if (proto == conf_endpoint) {
        conf_endpoint += sizeof("https://") - 1;
    }

    str_set(&endpoint, conf_endpoint);

    return endpoint;
}

static void
op_context_init(OpContext* op, OpArgs args, const s3cKeys* keys, s3cReply* reply)
{
    op->ok = false;
    op->reply = reply;
    op->keys = keys;
    op->args = args;

    if (keys->access_key_id == NULL ||
        strlen(keys->access_key_id) < 1) {

        op_set_error(op, "provided keys no access key ID set");
        return;
    }

    if (keys->access_key_secret == NULL ||
        strlen(keys->access_key_secret) < 1) {

        op_set_error(op, "provided keys no access key secret set");
        return;
    }

    if (keys->region == NULL || strlen(keys->region) < 1) {
        op_set_error(op, "provided keys no region set");
        return;
    }

    OsslContext* octx = calloc(1, sizeof(OsslContext));

    op->ossl_ctx = octx;
    const char* err = ossl_init(op->ossl_ctx);

    if (err != NULL) {
        op_set_error(op, err);
        return;
    }

    op->ok = true;
}

static void
op_context_free(OpContext* op)
{
    ossl_free(op->ossl_ctx);
    free(op);
}

static void
op_set_error(OpContext* op, const char* error)
{
    op->ok = false;

    free(op->reply->error);
    op->reply->error = NULL;

    char* copy = str_dup(error);

    op->reply->error = copy;
}

static void
op_set_error_fmt(OpContext* op, const char* fmt, ...)
{
    char mbuf[256];

    va_list arg_ptr;
    va_start(arg_ptr, fmt);

    vsnprintf(mbuf, sizeof(mbuf), fmt, arg_ptr);
    va_end(arg_ptr);

    op_set_error(op, mbuf);
}

static StrBuf
gen_scope_string(const char* date, const char* s3_region)
{
    StrBuf scope = str_init(128);

    str_push_many(
        &scope,
        date, "/", s3_region, "/s3/", S3_REQUEST_TYPE,
        NULL
    );

    return scope;
}

static void
gen_sig_header_entries(s3cKVL* headers_in,
                       StrBuf* out_sig_headers,
                       StrBuf* out_sig_header_names)
{
    StrBuf sbuf = str_init(128);

    str_set(out_sig_headers, "");
    str_set(out_sig_header_names, "");

    for (s3cKVL* h = headers_in; h; h = h->next) {

        // header name for signature
        str_set(&sbuf, h->key);

        for (char* p = sbuf.ptr; *p != '\0'; p++) {
            *p = tolower(*p);
        }

        if (out_sig_header_names->len > 0) {
            str_push_char(out_sig_header_names, ';');
        }

        str_push_str(out_sig_header_names, &sbuf);

        // header name + value for signature
        str_push_many(
            out_sig_headers,
            sbuf.ptr, ":", h->value, "\n",
            NULL
        );
    }

    str_destroy(&sbuf);
}

static void
append_s3_escaped_string(StrBuf* str_buf, const char* str)
{
    const char legal_chars[] = "/-_.";

    const char* hex_lk = "0123456789ABCDEF";

    for (size_t i = 0; i < strlen(str); i++) {
        char c = str[i];
        bool do_escape = (c < '0' || c > '9') &&
                         (c < 'A' || c > 'Z') &&
                         (c < 'a' || c > 'z');
        // except legal chars
        for (size_t j = 0; do_escape && j < sizeof(legal_chars) - 1; j++) {
            do_escape = c != legal_chars[j];
        }

        if (!do_escape) {
            str_push_char(str_buf, c);
            continue;
        }

        str_push_char(str_buf, '%');
        str_push_char(str_buf, hex_lk[(c >> 4) & 0x0F]);
        str_push_char(str_buf, hex_lk[c & 0x0F]);
    }
}

static void
bytes_to_hex(const uint8_t* bytes, size_t num_bytes, char* hex_out)
{
    const char* hex_lk = "0123456789abcdef";

    for (size_t in_idx = 0, out_idx = 0; in_idx < num_bytes;
                in_idx += 1, out_idx += 2) {

        hex_out[out_idx]     = hex_lk[(bytes[in_idx] >> 4) & 0x0F];
        hex_out[out_idx + 1] = hex_lk[bytes[in_idx] & 0x0F];
    }
}

static bool
sha256_hex_from_bytes(const uint8_t* data, uint64_t data_size,
                      char out_buf[S3C_SHA256_HEX_SIZE])
{
    uint8_t sha_hash[SHA256_DIGEST_LENGTH];

    if (SHA256(data, data_size, sha_hash) == NULL) {
        return false;
    }

    bytes_to_hex(sha_hash, S3C_SHA256_BIN_SIZE, out_buf);

    return true;
}

static bool
hmac_sha256_from_bytes(const uint8_t* key, size_t key_size,
                       const uint8_t* data, uint64_t data_size,
                       uint8_t out_buf[S3C_SHA256_BIN_SIZE])
{
    unsigned int digest_size = S3C_SHA256_BIN_SIZE;

    void* res = HMAC(
        EVP_sha256(),
        key, key_size,
        data, data_size,
        out_buf, &digest_size
    );

    return res != NULL && digest_size == S3C_SHA256_BIN_SIZE;
}

static bool
gen_signing_key(const s3cKeys* keys, const char* date_stamp,
                uint8_t out_buf[S3C_SHA256_BIN_SIZE])
{
    uint8_t tmp_buf_a[S3C_SHA256_BIN_SIZE];
    uint8_t tmp_buf_b[S3C_SHA256_BIN_SIZE];

    StrBuf sig_root = str_init(256);

    str_set(&sig_root, S3_SIGNATURE_PREFIX);
    str_push_cstr(&sig_root, keys->access_key_secret);

    // date key
    bool gen_ok = hmac_sha256_from_bytes(
        (const uint8_t*)sig_root.ptr, sig_root.len,
        (const uint8_t*)date_stamp, S3C_DATE_STAMP_SIZE - 1,
        tmp_buf_a
    );
    // date region key
    gen_ok = gen_ok && hmac_sha256_from_bytes(
        tmp_buf_a, S3C_SHA256_BIN_SIZE,
        (const uint8_t*)keys->region,
        strlen(keys->region),
        tmp_buf_b
    );
    // date region service key
    gen_ok = gen_ok && hmac_sha256_from_bytes(
        tmp_buf_b, S3C_SHA256_BIN_SIZE,
        (const uint8_t*)"s3", 2,
        tmp_buf_a
    );
    // final signing key
    gen_ok = gen_ok && hmac_sha256_from_bytes(
        tmp_buf_a, S3C_SHA256_BIN_SIZE,
        (const uint8_t*)S3_REQUEST_TYPE,
        strlen(S3_REQUEST_TYPE),
        out_buf
    );

    str_destroy(&sig_root);

    return gen_ok;
}

static bool
gen_string_to_sign(const StrBuf* request_sig, const StrBuf* scope_string,
                   const char* date_time, StrBuf* out_string)
{
    char hashed_request_sig[S3C_SHA256_HEX_SIZE + 1] = {'\0'};

    bool gen_ok = sha256_hex_from_bytes(
        (const uint8_t*)request_sig->ptr,
        request_sig->len,
        hashed_request_sig
    );

    if (!gen_ok) {
        return false;
    }

    str_set(out_string, "");

    str_push_many(
        out_string,
        S3_SIGNATURE_ALGO, "\n",
        date_time, "\n",
        scope_string->ptr, "\n",
        hashed_request_sig,
        NULL
    );

    return true;
}

static bool
gen_auth_header(const s3cKeys* keys,
                const DateStamps* dates,
                const StrBuf* request_sig,
                const StrBuf* sig_header_names,
                StrBuf* out_header)
{
    uint8_t signing_key   [S3C_SHA256_BIN_SIZE];
    uint8_t signature_bin [S3C_SHA256_BIN_SIZE];
    char    signature_hex [S3C_SHA256_HEX_SIZE + 1] = {'\0'};

    StrBuf scope_string = gen_scope_string(dates->date, keys->region);

    str_set(out_header, "");

    bool gen_ok = gen_string_to_sign(
        request_sig, &scope_string, dates->date_time,
        out_header
    );

    gen_ok = gen_ok && gen_signing_key(keys, dates->date, signing_key);

    // sign request string with the signing key
    gen_ok = gen_ok && hmac_sha256_from_bytes(
        signing_key, S3C_SHA256_BIN_SIZE,
        (const uint8_t*)out_header->ptr, out_header->len,
        signature_bin
    );

    if (!gen_ok) {
        goto cleanup_and_ret;
    }

    bytes_to_hex(signature_bin, S3C_SHA256_BIN_SIZE, signature_hex);

    // build authorization header value
    str_set(out_header, "");

    str_push_many(
        out_header,
        S3_SIGNATURE_ALGO,
        " Credential=", keys->access_key_id, "/", scope_string.ptr,
        ", SignedHeaders=", sig_header_names->ptr,
        ", Signature=", signature_hex,
        NULL
    );

cleanup_and_ret:
    str_destroy(&scope_string);

    return gen_ok;
}

static void
op_run_request(OpContext* op, const char* html_verb)
{
    StrBuf request = str_init(128),
           request_sig = str_init(128),
           sig_headers = str_init(128),
           sig_header_names = str_init(128),
           auth_header = str_init(128),
           sig_url = str_init(128),
           req_url = str_init(128),
           query_str = str_init(128),
           endpoint = get_req_host(op->keys);

    s3cKVL* headers = NULL;

    DateStamps dates;
    set_date_stamps(&dates);

    // copy and sort headers
    for (const s3cKVL* h = op->args.headers; h; h = h->next) {
        s3c_kvl_ins(&headers, h->key, h->value);
    }

    // asserting query args are sorted
    for (const s3cKVL* h = op->args.query_args; h; h = h->next) {
        str_push_many(
            &query_str, h->key, "=", h->value,
            (h->next ? "&" : ""),
            NULL
        );
    }

    s3c_kvl_upsert(&headers, "host", endpoint.ptr);
    s3c_kvl_upsert(&headers, "x-amz-date", dates.date_time);

    char content_sha_hex[] =
    // sha256 hash for empty string
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    if (op->args.data) {
        sha256_hex_from_bytes(op->args.data, op->args.data_size, content_sha_hex);

        s3c_kvl_remove(&headers, "content-length");
        s3c_kvl_ins_int(&headers, "content-length", op->args.data_size);
    }

    s3c_kvl_upsert(&headers, "x-amz-content-sha256", content_sha_hex);

    str_push_char(&sig_url, '/');
    append_s3_escaped_string(&sig_url, op->args.bucket);

    if (op->args.object_key != NULL) {
        str_push_char(&sig_url, '/');
        append_s3_escaped_string(&sig_url, op->args.object_key);
    }

    str_push_str(&req_url, &sig_url);

    if (query_str.len > 0) {
        str_push_char(&req_url, '?');
        str_push_str(&req_url, &query_str);
    }

    gen_sig_header_entries(headers, &sig_headers, &sig_header_names);

    // build request signature to sign as per spec
    str_push_many(
        &request_sig,
        html_verb, "\n",
        sig_url.ptr, "\n",
        query_str.ptr, "\n",
        sig_headers.ptr, "\n",
        sig_header_names.ptr, "\n",
        content_sha_hex,
        NULL
    );

    // create signature for the authorization header
    bool sig_ok = gen_auth_header(
        op->keys, &dates,
        &request_sig, &sig_header_names,
        &auth_header
    );

    if (!sig_ok) {
        op_set_error(op, "AWS4 signature generation failed => "
                         "hmac sha256 hash gen unsuccessful");
        goto cleanup_and_ret;
    }

    s3c_kvl_upsert(&headers, "authorization", auth_header.ptr);
    s3c_kvl_upsert(&headers, "connection", "close");

    // build http request head
    str_push_many(
        &request,
        html_verb, " ", req_url.ptr, " ", S3_HTTP_VERSION, "\r\n",
        NULL
    );

    for (s3cKVL* h = headers; h; h = h->next) {
        str_push_many(
            &request,
            h->key, ": ", h->value, "\r\n",
            NULL
        );
    }

    str_push_cstr(&request, "\r\n");

    op_send_request(op, &request);

cleanup_and_ret:
    str_destroy(&request);
    str_destroy(&request_sig);
    str_destroy(&sig_url);
    str_destroy(&req_url);
    str_destroy(&query_str);
    str_destroy(&sig_headers);
    str_destroy(&sig_header_names);
    str_destroy(&auth_header);
    str_destroy(&endpoint);

    s3c_kvl_free(headers);
}

static const char*
ossl_init(OsslContext* octx)
{
    octx->ssl_ctx = SSL_CTX_new(TLS_client_method());

    if (octx->ssl_ctx == NULL) {
        return "openssl failed to allocate ssl context";
    }

    octx->ssl = SSL_new(octx->ssl_ctx);

    if (octx->ssl == NULL) {
        return "openssl failed to allocate ssl object";
    }

    SSL_CTX_set_verify(octx->ssl_ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_set_default_verify_paths(octx->ssl_ctx)) {
        return "openssl failed to set the default trusted certificate store";
    }

    if (!SSL_CTX_set_min_proto_version(octx->ssl_ctx, TLS1_2_VERSION)) {
        return "openssl failed to set the minimum TLS protocol version";
    }

    SSL_set_mode(octx->ssl, SSL_MODE_AUTO_RETRY);

    return NULL;
}

static void
ossl_free(OsslContext* octx)
{
    if (octx == NULL) {
        return;
    }

    if (octx->ssl != NULL) {
        int socket_fd = SSL_get_fd(octx->ssl);
        if (socket_fd >= 0) {
            BIO_closesocket(socket_fd);
        }
    }

    SSL_free(octx->ssl);
    SSL_CTX_free(octx->ssl_ctx);

    free(octx);
}

const char*
ossl_proc_io_res(OsslContext* octx, int io_res)
{
    if (io_res == 1) {
        return NULL;
    }

    int ssl_err = SSL_get_error(octx->ssl, io_res);

    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        return NULL;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return "net timeout";
    }

    return  "unknown net error occured";
}

static BIO*
create_socket_bio(const char *host, const char *port, int family)
{
    BIO_ADDRINFO* bio_addr_info;

    int lk_res = BIO_lookup_ex(
        host, port, BIO_LOOKUP_CLIENT,
        family, SOCK_STREAM, 0,
        &bio_addr_info
    );

    if (!lk_res || bio_addr_info == NULL) {
        return NULL;
    }

    int sock = -1;
    const BIO_ADDRINFO *ai = NULL;

    struct timeval timeout;
    timeout.tv_sec = S3C_GLOBAL_CONFS.net_io_timeout_sec;
    timeout.tv_usec = 0;

    for (ai = bio_addr_info; sock == -1 && ai != NULL; ai = BIO_ADDRINFO_next(ai)) {

        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);

        if (sock == -1) {
            continue;
        }

        if (S3C_GLOBAL_CONFS.net_io_timeout_sec > 0) {

            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
                setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {

                BIO_closesocket(sock);
                sock = -1;
                continue;
            }
        }

        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai),
                         BIO_SOCK_NODELAY | BIO_SOCK_REUSEADDR)) {

            BIO_closesocket(sock);
            sock = -1;
            continue;
        }
    }

    BIO_ADDRINFO_free(bio_addr_info);

    if (sock == -1) {
        return NULL;
    }

    BIO* bio = BIO_new(BIO_s_socket());

    if (bio == NULL) {
        BIO_closesocket(sock);
        return NULL;
    }

    BIO_set_fd(bio, sock, BIO_CLOSE);

    return bio;
}

static const char*
ossl_connect(OsslContext* octx, const char* host)
{
    BIO* bio = create_socket_bio(host, "443", AF_INET);

    if (bio == NULL) {
        bio = create_socket_bio(host, "443", AF_INET6);
    }

    if (bio == NULL) {
        return "failed to resolve host";
    }

    SSL_set_bio(octx->ssl, bio, bio);

    if (!SSL_set_tlsext_host_name(octx->ssl, host)) {
        return "failed to set sni hostname";
    }

    if (!SSL_set1_host(octx->ssl, host)) {
        return "failed to set certificate verification hostname";
    }

    int io_res = SSL_connect(octx->ssl);

    if (io_res == 1) {
        return NULL;
    }

    if (SSL_get_verify_result(octx->ssl) != X509_V_OK) {
        return "openssl failed to verify host";
    }

    return "failed to connect to host";
}

static char*
trim_string(char* s, size_t len)
{
    if (s== NULL || len < 1) {
        return s;
    }

    char* start = s;
    char* end   = s + len - 1;

    for (; start != end && isspace(*start); start += 1) { }

    for (; end != start && isspace(*end); end -= 1) {
        *end = '\0';
    }

    return start;
}

static int
parse_http_resp_code(char* header_line)
{
    char* code_start = strchr(header_line, ' ');

    if (!code_start) {
        return -1;
    }

    int64_t resp_code = strtol(code_start, NULL, 10);

    if (resp_code < 100 || resp_code > 599) {
        return -1;
    }

    return resp_code;
}

static void
parse_header_line(s3cKVL** headers, char* header_string)
{
    char* delim = strstr(header_string, ":");

    if (delim == NULL || delim == header_string) {
        return;
    }

    *delim = '\0';

    char* name = trim_string(header_string, delim - header_string - 1);
    char* value = delim + 1;
    value = trim_string(value, strlen(value));

    if (*name == '\0' || *value == '\0') {
        return;
    }

    s3c_kvl_ins(headers, name, value);
}

static const char*
parse_header_block(char* header_block, size_t header_block_len,
                   s3cKVL** out_headers, unsigned* out_resp_code)
{
    char* str_ptr = header_block;
    size_t len_left = header_block_len;

    bool first_line_parsed = false;

    for (;;) {
        char* line_break = memchr(str_ptr, '\n', len_left);

        if (line_break == NULL) {
            break;
        }

        ptrdiff_t line_len = line_break - str_ptr;

        if (line_len < 2) {
            break;
        }

        str_ptr = trim_string(str_ptr, line_len);

        if (first_line_parsed) {

            parse_header_line(out_headers, str_ptr);

        } else {

            int resp_code = parse_http_resp_code(str_ptr);
            bool http_proto_ok = memcmp(S3_HTTP_VERSION, str_ptr, strlen(S3_HTTP_VERSION)) == 0;

            if (!http_proto_ok || resp_code < 0) {
                return "wrong http protocol";
            }

            *out_resp_code = (unsigned)resp_code;

            first_line_parsed = true;
        }

        str_ptr += line_len + 1;
        len_left -= line_len;
    }

    if (!first_line_parsed) {
        return "failed to parse http headers";
    }

    return NULL;
}

static const char*
ossl_io_read(OsslContext* octx, uint8_t* in_buf, size_t in_buf_size,
             size_t* out_bytes_recv)
{
    *out_bytes_recv = 0;
    int io_res = 0;

    errno = 0;
    io_res = SSL_read_ex(
        octx->ssl, in_buf, in_buf_size,
        out_bytes_recv
    );

    const char* err = ossl_proc_io_res(octx, io_res);

    if (err) {
        return err;
    }

    if (*out_bytes_recv == 0 &&
        SSL_get_error(octx->ssl, 0) != SSL_ERROR_ZERO_RETURN) {

        return "host hang up";
    }

    return NULL;
}

static const char*
ossl_io_write(OsslContext* octx, const uint8_t* data,
              size_t data_size, size_t* out_bytes_sent)
{
    *out_bytes_sent = 0;
    int io_res = 0;

    errno = 0;
    io_res = SSL_write_ex(
        octx->ssl, data, data_size,
        out_bytes_sent
    );

    const char* err = ossl_proc_io_res(octx, io_res);

    if (err) {
        return err;
    }

    return NULL;
}

static int64_t
parse_reply_content_length(s3cKVL* rep_headers)
{
    s3cKVL* ct_len = s3c_kvl_find(rep_headers, "content-length");

    if (ct_len == NULL) {
        return -1;
    }

    errno = 0;
    char* p_end;
    int64_t res = strtol(ct_len->value, &p_end, 10);

    if (errno != 0 || p_end == NULL ||
        *p_end != '\0' || p_end == ct_len->value) {

        return -1;
    }

    return res;
}

static void
op_read_reply(OpContext* op)
{
    StrBuf reply_buf  = str_init(0),
           recv_cache = str_init(49152);

    bool headers_parsed = false;
    unsigned http_resp_code = 0;

    size_t max_mem_prealloc_size =
        S3C_GLOBAL_CONFS.max_reply_prealloc_size_mb * 1024 * 1024;

    for (;;) {

        size_t bytes_recv = 0;

        const char* err = ossl_io_read(
            op->ossl_ctx,
            (uint8_t*)recv_cache.ptr, recv_cache.cap,
            &bytes_recv
        );

        if (err != NULL) {
            op_set_error_fmt(op, "failed to read http reply: %s", err);
            goto cleanup_and_ret;
        }

        if (bytes_recv == 0) {
            break;
        }

        if (!op->args.fp || !headers_parsed) {
            size_t num_pushed = str_push(&reply_buf, recv_cache.ptr, bytes_recv);

            if (num_pushed < bytes_recv) {
                op_set_error(op, "http reply allocation failed");
                goto cleanup_and_ret;
            }
        }

        if (op->args.fp && headers_parsed) {
            size_t bytes_written = fwrite(recv_cache.ptr, 1, bytes_recv, op->args.fp);
            if (bytes_written < bytes_recv) {
                op_set_error(op, "http reply write to file failed");
                goto cleanup_and_ret;
            }
        }

        if (headers_parsed) {
            continue;
        }

        const char* delim = strstr(reply_buf.ptr, "\r\n\r\n");

        if (delim == NULL || delim == reply_buf.ptr) {
            continue;
        }

        ptrdiff_t block_len = delim - reply_buf.ptr;

        if (block_len < 4) {
            op_set_error(op, "http reply internal parse error");
            goto cleanup_and_ret;
        }

        const char* parse_err = parse_header_block(
            reply_buf.ptr, block_len,
            &op->reply->headers,
            &http_resp_code
        );

        if (parse_err != NULL) {
            op_set_error(op, parse_err);
            goto cleanup_and_ret;
        }

        size_t to_copy = reply_buf.len - block_len - 4;

        assert(to_copy < reply_buf.len);

        reply_buf.len = 0;
        str_push(&reply_buf, recv_cache.ptr + bytes_recv - to_copy, to_copy);

        headers_parsed = true;

        int64_t rep_len = parse_reply_content_length(op->reply->headers);

        if (op->args.fp) {

            size_t bytes_written = fwrite(reply_buf.ptr, 1, reply_buf.len, op->args.fp);
            if (bytes_written < reply_buf.len) {
                op_set_error(op, "http reply write to file failed");
                goto cleanup_and_ret;
            }


        } else if (rep_len > 0 && (size_t)rep_len <= max_mem_prealloc_size) {

            if (str_set_cap(&reply_buf, rep_len) < (size_t)rep_len) {
                op_set_error_fmt(
                    op, "http reply allocation failed, content-length: [%zu]",
                    (size_t)rep_len
                );
                goto cleanup_and_ret;
            }
        }
    }

    op_proc_reply(op, &reply_buf, http_resp_code);

cleanup_and_ret:
    SSL_shutdown(op->ossl_ctx->ssl);

    str_destroy(&reply_buf);
    str_destroy(&recv_cache);
}

static void
op_send_request(OpContext* op, StrBuf* rq_head)
{
    StrBuf endpoint = get_req_host(op->keys);

    const char* conn_err = ossl_connect(op->ossl_ctx, endpoint.ptr);

    if (conn_err) {
        op_set_error(op, conn_err);
        goto cleanup_and_ret;
    }

    size_t bytes_sent_now;
    const char* io_err = ossl_io_write(
        op->ossl_ctx,
        (const uint8_t*)rq_head->ptr, rq_head->len,
        &bytes_sent_now
    );

    if (io_err != NULL) {
        op_set_error_fmt(op, "failed to send http request: %s", io_err);
        goto cleanup_and_ret;
    }

    if ((unsigned)bytes_sent_now < rq_head->len) {
        op_set_error(op, "failed to send http request, transmission error");
        goto cleanup_and_ret;
    }

    const uint8_t* data = op->args.data;
    uint64_t data_size = op->args.data_size;

    assert(data_size < 1 || data != NULL);

    size_t bytes_sent_total = 0;
    bytes_sent_now = 0;

    while (bytes_sent_total < data_size) {

        size_t bytes_left = data_size - bytes_sent_total;

        io_err = ossl_io_write(
            op->ossl_ctx,
            data + bytes_sent_total,
            bytes_left,
            &bytes_sent_now
        );

        if (io_err != NULL) {
            op_set_error_fmt(op, "failed to send http request: %s", io_err);
            goto cleanup_and_ret;
        }

        bytes_sent_total += bytes_sent_now;
    }

    op_read_reply(op);

cleanup_and_ret:
    str_destroy(&endpoint);
}

static void
op_proc_reply(OpContext* op, StrBuf* reply, unsigned http_resp_code)
{
    if (!op->ok) {
        return;
    }

    op->reply->http_resp_code = http_resp_code;

    if (http_resp_code < 300 && http_resp_code > 199) {

        if (reply->len > 0 && !op->args.fp) {
            op->reply->data_size = reply->len;
            op->reply->data = (uint8_t*)str_extract(reply);
        }
        return;
    }

    StrBuf err_buf = str_init(0);

    str_set(&err_buf, "S3 endpoint replied with HTTP response code ");
    str_push_int(&err_buf, http_resp_code);

    if (reply->len > 0) {
        str_push_cstr(&err_buf, ": ");
        parse_xml_tag(reply->ptr, "Message", &err_buf);
    }

    op_set_error(op, err_buf.ptr);
    str_destroy(&err_buf);
}

static int
cmp_no_case(char const *a, char const *b)
{
  int ca, cb;

  do {
     ca = tolower(*a);
     cb = tolower(*b);
     a++;
     b++;

   } while (ca == cb && ca != '\0');

   return ca - cb;
}

void
s3c_kvl_ins_int(s3cKVL** head_ref, const char* name, int64_t int_value)
{
    StrBuf sbuf = str_init(20);
    str_push_int(&sbuf, int_value);

    s3c_kvl_ins(head_ref, name, sbuf.ptr);

    str_destroy(&sbuf);
}

void
s3c_kvl_ins(s3cKVL** head_ref, const char* name, const char* value)
{
    s3cKVL* cur = *head_ref;
    s3cKVL* prev = NULL;

    int order_diff = -1;

    while (cur != NULL) {

        order_diff = cmp_no_case(name, cur->key);

        if (order_diff <= 0) {
            break;
        }

        prev = cur;
        cur = cur->next;
    }

    // append value to existing head_refer
    if (order_diff == 0) {

        StrBuf sbuf = str_init(
            strlen(value) + strlen(cur->value) + 2
        );

        str_set      (&sbuf, cur->value);
        str_push_cstr(&sbuf, ", ");
        str_push_cstr(&sbuf, value);

        free(cur->value);
        cur->value = str_extract(&sbuf);

        return;
    }

    s3cKVL* new_node = malloc(sizeof(s3cKVL));

    new_node->key = str_dup(name);
    new_node->value = str_dup(value);
    new_node->next  = NULL;

    if (*head_ref == NULL) {
        *head_ref = new_node;
        return;
    }

    assert(prev != NULL || (cur == *head_ref && order_diff < 0));

    if (order_diff < 0) {
        // prepend
        new_node->next = cur;

        if (cur == *head_ref) {
            // set new head_ref
            *head_ref = new_node;
            return;
        }

        new_node->next = cur;
        prev->next = new_node;

    } else {
        // append
        new_node->next = prev->next;
        prev->next = new_node;
    }
}

s3cKVL*
s3c_kvl_find(s3cKVL* head_ref, const char* name)
{
    for (; head_ref != NULL; head_ref = head_ref->next) {
        if (cmp_no_case(name, head_ref->key) == 0) {
            return head_ref;
        }
    }
    return NULL;
}

void
s3c_kvl_remove(s3cKVL** head_ref, const char* name)
{
    s3cKVL* prev = NULL;
    s3cKVL* cur = *head_ref;

    for (; cur != NULL; prev = cur, cur = cur->next) {
        if (cmp_no_case(name, cur->key) == 0) {

            if (cur == *head_ref) {
                *head_ref = cur->next;

            } else if (prev != NULL) {
                prev->next = cur->next;
            }

            cur->next = NULL;
            s3c_kvl_free(cur);

            break;
        }
    }
}

static void
s3c_kvl_upsert(s3cKVL** head, const char* name, const char* value)
{
    s3cKVL* h = s3c_kvl_find(*head, name);

    if (h != NULL) {
        free(h->value);
        h->value = str_dup(value);
    } else {
        s3c_kvl_ins(head, name, value);
    }
}

void
s3c_kvl_free(s3cKVL* head)
{
    while (head != NULL) {
        s3cKVL* next = head->next;

        free(head->key);
        free(head->value);

        memset(head, 0, sizeof(s3cKVL));
        free(head);

        head = next;
    }
}

static
StrBuf str_init(size_t cap)
{
    char* ptr = cap > 0 ? calloc(1, cap + 1) : NULL;

    StrBuf res = {
        .ptr = ptr,
        .len = 0,
        .cap = cap
    };

    return res;
}

static void
str_destroy(StrBuf* s)
{
    free(s->ptr);
    *s = str_init(0);
}

static char*
str_extract(StrBuf* s)
{
    char* ret = s->ptr;
    *s = str_init(0);

    return ret;
}

static size_t
str_set_cap(StrBuf* s, size_t cap)
{
    if (s->cap >= cap) {
        return cap;
    }

    char* new_ptr = s->ptr != NULL
        ? realloc(s->ptr, cap + 1)
        : calloc(1, cap + 1);

    if (!new_ptr) {
        return 0;
    }

    s->ptr = new_ptr;
    s->cap = cap;

    return cap;
}

static size_t
str_push(StrBuf* s, const char* a, size_t a_len)
{
    if (s->ptr != NULL && a_len < 1) {
        return 0;
    }

    if (s->cap < 1 || s->len + a_len > s->cap) {

        if (s->cap < 1) {
            s->cap = 64;
        }

        size_t max_reserve_size =
            S3C_GLOBAL_CONFS.str_buf_max_cap_reserve_mb * 1024 * 1024;

        size_t cap_growth = s->cap / 2 < max_reserve_size
            ? s->cap / 2
            : max_reserve_size;

        size_t new_len = s->len + a_len;
        size_t new_cap = s->cap + cap_growth;

        if (new_len > new_cap) {
            new_cap = new_len;
        }

        size_t allocd = str_set_cap(s, new_cap);

        if (allocd < new_cap) {
            return 0;
        }
    }

    assert(s->cap + 1 > s->len + a_len);

    memcpy(s->ptr + s->len, a, a_len);

    s->len += a_len;
    s->ptr[s->len] = '\0';

    return a_len;
}

static size_t
str_push_char(StrBuf* s, char c)
{
    return str_push(s, &c, 1);
}

static size_t
str_push_str(StrBuf* s, const StrBuf* a)
{
    return str_push(s, a->ptr, a->len);
}

static size_t
str_push_cstr(StrBuf* s, const char* a)
{
    return str_push(s, a, strlen(a));
}

static size_t
str_push_many(StrBuf* s, ...)
{
    va_list cstrs;
    va_start(cstrs, s);

    size_t bytes_pushed = 0;
    const char* a;

    while ((a = va_arg(cstrs, const char*)) != NULL) {
        bytes_pushed += str_push(s, a, strlen(a));
    }

    va_end(cstrs);
    return bytes_pushed;
}

static size_t
str_set(StrBuf* s, const char* a)
{
    s->len = 0;
    return str_push_cstr(s, a);
}

static size_t
str_push_int(StrBuf* s, int64_t i)
{
    char buf [20 + 1];
    size_t len = snprintf(buf, sizeof(buf), "%" PRId64 , i);

    return str_push(s, buf, len);
}







