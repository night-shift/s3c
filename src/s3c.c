#define _POSIX_C_SOURCE 200809L
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
#include <time.h>

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
#define S3C_MULTIPART_MIN_PART_SIZE (5U * 1024U * 1024U)

#define S3C_DEF_NET_IO_TIMEOUT_SEC          15U
#define S3C_DEF_MAX_REPLY_PREALLOC_SIZE_MB 128U
#define S3C_DEF_STR_BUF_MAX_CAP_RESERVE_MB  10U
#define S3C_DEF_CLIENT_IDLE_SEC_MAX         300

typedef struct {
    uint64_t net_io_timeout_sec;
    uint64_t max_reply_prealloc_size_mb;
    uint64_t str_buf_max_cap_reserve_mb;
    uint64_t client_idle_sec_max;
} RuntimeConfs;

static RuntimeConfs S3C_DEFAULT_CONFS = {
    .net_io_timeout_sec = S3C_DEF_NET_IO_TIMEOUT_SEC,
    .max_reply_prealloc_size_mb = S3C_DEF_MAX_REPLY_PREALLOC_SIZE_MB,
    .str_buf_max_cap_reserve_mb = S3C_DEF_STR_BUF_MAX_CAP_RESERVE_MB,
    .client_idle_sec_max = S3C_DEF_CLIENT_IDLE_SEC_MAX
};

typedef struct {
    SSL* ssl;
} OsslContext;

struct s3cClient {
    s3cKeys keys;
    RuntimeConfs confs;
    SSL_CTX* ssl_ctx;
    OsslContext* conn;
    time_t last_used;
};

static const char* ossl_ctx_init(SSL_CTX** out_ctx);
static const char* ossl_init(OsslContext*, SSL_CTX* ssl_ctx);
static void        ossl_free(OsslContext*);
static void        ossl_disconnect(OsslContext*);
static const char* ossl_connect(OsslContext*, const char* host, uint64_t net_timeout_sec);


typedef struct {
    size_t total_size;
    size_t cursor;
    void* opaque;
    const RuntimeConfs* confs;
} StreamContext;

typedef struct {
    const char* (*fn_write)(const char*, size_t, StreamContext*);
    StreamContext ctx;
} StreamWrite;

typedef struct {
    const char* (*fn_read)(size_t, StreamContext*, const char**, size_t*);
    const char* (*fn_reset)(StreamContext*);
    StreamContext ctx;
} StreamRead;


typedef struct {
    const char*   bucket;
    const char*   object_key;
    const s3cKVL* headers;
    const s3cKVL* query_args;
    StreamWrite*  stream_wr;
    StreamRead*   stream_rd;
} OpArgs;

typedef struct {
    bool           ok;
    bool           should_retry;
    bool           can_reuse_conn;
    s3cClient*     client;
    s3cReply*      reply;
    OpArgs         args;
} OpContext;

typedef struct {
    char*  ptr;
    size_t len;
    size_t cap;
    uint64_t max_cap_reserve_mb;
} StrBuf;

typedef struct {
    FILE* fp;
    StrBuf* buf;
} BufferedFile;

typedef struct {
    char date_time [S3C_DATE_TIME_STAMP_SIZE];
    char date      [S3C_DATE_STAMP_SIZE];
} DateStamps;

static void op_context_init(OpContext*, OpArgs args, s3cClient*,  s3cReply*);
static void op_context_free(OpContext*);
static void op_run_request(OpContext* op, const char* html_verb);
static void op_send_request(OpContext*, const char* html_verb, StrBuf* http_request);
static void op_read_reply(OpContext*, const char* html_verb);
static void op_proc_reply(OpContext*, StrBuf* reply, unsigned http_resp_code);
static void op_set_error(OpContext* op, const char* error);
static void op_set_error_fmt(OpContext* op, const char* fmt, ...);

static StrBuf str_init(size_t cap);
static StrBuf str_init_conf(size_t cap, uint64_t max_cap_reserve_mb);
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
static void set_runtime_confs(RuntimeConfs* out, const s3cClientOpts* opts);
static char* normalize_endpoint_host(const char* endpoint);

uint64_t s3c_set_global_config(uint64_t opt, uint64_t value)
{
    switch (opt) {
        case S3C_CONF_NET_IO_TIMEOUT_SEC:
            S3C_DEFAULT_CONFS.net_io_timeout_sec = value;
            return 1;

        case S3C_CONF_MAX_REPLY_PREALLOC_SIZE_MB:
            S3C_DEFAULT_CONFS.max_reply_prealloc_size_mb = value;
            return 1;

        case S3C_CONF_CLIENT_IDLE_SEC_MAX:
            S3C_DEFAULT_CONFS.client_idle_sec_max = value;
            return 1;
    }

    return 0;
}

static char* str_dup(const char* s)
{
    size_t len = strlen(s);
    char* res = malloc(len + 1);

    memcpy(res, s, len + 1);

    return res;
}

s3cReply* s3c_reply_alloc(const char* error)
{
    s3cReply* reply = calloc(1, sizeof(s3cReply));

    reply->error = NULL;

    if (error != NULL) {
        char* copy = str_dup(error);
        reply->error = copy;
    }

    return reply;
}

void s3c_list_entry_free(s3cListEntry* entry)
{
    while (entry != NULL) {
        s3cListEntry* next = entry->next;
        free(entry->key);
        free(entry->etag);
        free(entry->last_modified);
        free(entry);
        entry = next;
    }
}

void s3c_mp_entry_free(s3cMpEntry* entry)
{
    while (entry != NULL) {
        s3cMpEntry* next = entry->next;
        free(entry->key);
        free(entry->upload_id);
        free(entry->initiated);
        free(entry);
        entry = next;
    }
}

static void s3c_reply_reset(s3cReply* reply)
{
    if (reply == NULL) {
        return;
    }

    s3c_kvl_free(reply->headers);

    free(reply->error);
    free(reply->data);

    switch (reply->result_kind) {

        case S3C_RESULT_LIST:
            s3c_list_entry_free(reply->result.list.entries);
            free(reply->result.list.continuation_token);
            break;

        case S3C_RESULT_UPLOADS:
            s3c_mp_entry_free(reply->result.uploads.entries);
            break;

        default:
            break;
    }

    memset(reply, 0, sizeof(s3cReply));
}

void s3c_reply_free(s3cReply* reply)
{
    s3c_reply_reset(reply);
    free(reply);
}

static void set_runtime_confs(RuntimeConfs* out, const s3cClientOpts* opts)
{
    *out = S3C_DEFAULT_CONFS;

    if (opts == NULL) {
        return;
    }

    if (opts->net_io_timeout_sec > 0) {
        out->net_io_timeout_sec = opts->net_io_timeout_sec;
    }
    if (opts->max_reply_prealloc_size_mb > 0) {
        out->max_reply_prealloc_size_mb = opts->max_reply_prealloc_size_mb;
    }
    if (opts->str_buf_max_cap_reserve_mb > 0) {
        out->str_buf_max_cap_reserve_mb = opts->str_buf_max_cap_reserve_mb;
    }
}

static char* normalize_endpoint_host(const char* endpoint)
{
    if (endpoint == NULL || *endpoint == '\0') {
        return NULL;
    }

    const char* host = endpoint;
    const char* https_prefix = "https://";
    size_t pref_len = strlen(https_prefix);

    if (strncmp(host, https_prefix, pref_len) == 0) {
        host += pref_len;
    }

    while (*host == '/') {
        host += 1;
    }

    if (*host == '\0') {
        return NULL;
    }

    const char* end = host + strlen(host);
    while (end > host && end[-1] == '/') {
        end -= 1;
    }

    ptrdiff_t host_len = end - host;
    if (host_len < 1) {
        return NULL;
    }

    char* out = calloc(host_len + 1, 1);
    memcpy(out, host, host_len);
    out[host_len] = '\0';

    return out;
}

s3cClient* s3c_client_new(const s3cKeys* keys,
                          const s3cClientOpts* opts,
                          s3cReply** out_err)
{
    if (out_err != NULL) {
        *out_err = NULL;
    }

    if (keys == NULL) {
        if (out_err != NULL) {
            *out_err = s3c_reply_alloc("provided arguments missing value for <keys>");
        }
        return NULL;
    }

    if (keys->access_key_id == NULL || *keys->access_key_id == '\0') {
        if (out_err != NULL) {
            *out_err = s3c_reply_alloc("provided keys no access key ID set");
        }
        return NULL;
    }

    if (keys->access_key_secret == NULL || *keys->access_key_secret == '\0') {
        if (out_err != NULL) {
            *out_err = s3c_reply_alloc("provided keys no access key secret set");
        }
        return NULL;
    }

    if (keys->region == NULL || *keys->region == '\0') {
        if (out_err != NULL) {
            *out_err = s3c_reply_alloc("provided keys no region set");
        }
        return NULL;
    }

    s3cClient* client = calloc(1, sizeof(s3cClient));
    if (client == NULL) {
        if (out_err != NULL) {
            *out_err = s3c_reply_alloc("failed to allocate s3 client");
        }
        return NULL;
    }

    set_runtime_confs(&client->confs, opts);

    client->keys.access_key_id = str_dup(keys->access_key_id);
    client->keys.access_key_secret = str_dup(keys->access_key_secret);
    client->keys.region = str_dup(keys->region);

    if (keys->endpoint != NULL && *keys->endpoint != '\0') {
        client->keys.endpoint = normalize_endpoint_host(keys->endpoint);
        if (client->keys.endpoint == NULL) {
            if (out_err != NULL) {
                *out_err = s3c_reply_alloc("provided endpoint is invalid");
            }
            s3c_client_free(client);
            return NULL;
        }
    }

    if (client->keys.access_key_id == NULL ||
        client->keys.access_key_secret == NULL ||
        client->keys.region == NULL) {

        if (out_err != NULL) {
            *out_err = s3c_reply_alloc("failed to allocate s3 client");
        }
        s3c_client_free(client);
        return NULL;
    }

    const char* err = ossl_ctx_init(&client->ssl_ctx);
    if (err != NULL) {
        if (out_err != NULL) {
            *out_err = s3c_reply_alloc(err);
        }
        s3c_client_free(client);
        return NULL;
    }

    return client;
}

static void secure_free(char* ptr)
{
    if (ptr == NULL) {
        return;
    }

    size_t len = strlen(ptr);
    OPENSSL_cleanse(ptr, len);
    free(ptr);
}

void s3c_client_free(s3cClient* client)
{
    if (client == NULL) {
        return;
    }

    ossl_free(client->conn);
    secure_free(client->keys.access_key_id);
    secure_free(client->keys.access_key_secret);
    free(client->keys.region);
    free(client->keys.endpoint);

    SSL_CTX_free(client->ssl_ctx);
    free(client);
}

static s3cReply* check_arg_str(const char* arg, const char* arg_name)
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

static s3cReply* check_arg_bucket_key(const char* bucket, const char* object_key)
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

static s3cReply* run_s3_op(s3cClient* client, const char* html_verb, OpArgs args)
{
    OpContext* op = calloc(1, sizeof(OpContext));
    s3cReply* reply = s3c_reply_alloc(NULL);

    op_context_init(op, args, client, reply);

    if (!op->ok) {
        goto cleanup_and_ret;
    }

    op_run_request(op, html_verb);

cleanup_and_ret:
    op_context_free(op);

    return reply;
}

static const char* fn_stream_write_str_buf(const char* bytes, size_t num_bytes,
                                           StreamContext* c)
{
    StrBuf* str_buf = c->opaque;
    const RuntimeConfs* confs = c->confs != NULL
        ? c->confs
        : &S3C_DEFAULT_CONFS;

    if (str_buf->cap < 1 && c->total_size > 0) {

        size_t max_mem_prealloc_size =
            confs->max_reply_prealloc_size_mb * 1024 * 1024;

        if (c->total_size < max_mem_prealloc_size) {
            str_set_cap(str_buf, c->total_size);
        }
    }

    size_t num_pushed = str_push(str_buf, bytes, num_bytes);

    if (num_pushed < num_bytes) {
        return "failed to allocate mem";
    }

    return NULL;
}

static const char* fn_stream_write_file(const char* bytes, size_t num_bytes,
                                        StreamContext* c)
{
    FILE* fp = c->opaque;
    size_t bytes_written = fwrite(bytes, 1, num_bytes, fp);

    if (bytes_written < num_bytes) {
        return "write to file failed";
    }

    return NULL;
}

static const char* fn_stream_read_mem(size_t read_num_bytes, StreamContext* c,
                                      const char** out_ptr, size_t* out_num_bytes)
{
    const char* mem = c->opaque;

    *out_num_bytes = c->cursor + read_num_bytes < c->total_size
        ? read_num_bytes
        : c->total_size - c->cursor;

    if (c->cursor >= c->total_size) {
        c->cursor = 0;
        *out_ptr = NULL;
    } else {
        *out_ptr = mem + c->cursor;
    }

    c->cursor += *out_num_bytes;

    return NULL;
}


static const char* fn_stream_read_file(size_t read_num_bytes, StreamContext* c,
                                       const char** out_ptr, size_t* out_num_bytes)
{
    BufferedFile* bf = c->opaque;

    size_t bytes_to_read = c->cursor + read_num_bytes < c->total_size
        ? read_num_bytes
        : c->total_size - c->cursor;

    size_t cap_set = str_set_cap(bf->buf, bytes_to_read);

    if (cap_set < bytes_to_read) {
        return "failed to allocate mem for read file";
    }

    if (c->cursor >= c->total_size) {
        c->cursor = 0;
        fseek(bf->fp, 0, SEEK_SET);
        *out_ptr = NULL;

    } else {
        size_t bytes_read = fread(bf->buf->ptr, 1, bytes_to_read, bf->fp);

        if (bytes_read < bytes_to_read) {
            return "failed to read file";
        }

        *out_ptr = bf->buf->ptr;
    }

    *out_num_bytes = bytes_to_read;
    c->cursor += bytes_to_read;

    return NULL;
}

static const char* fn_stream_reset_mem(StreamContext* c)
{
    c->cursor = 0;
    return NULL;
}

static const char* fn_stream_reset_file(StreamContext* c)
{
    BufferedFile* bf = c->opaque;
    c->cursor = 0;
    if (fseek(bf->fp, 0, SEEK_SET) != 0) {
        return "failed to seek file to start";
    }
    return NULL;
}

static StreamRead make_stream_rd_mem(StreamContext ctx)
{
    StreamRead stream = {
        .fn_read = &fn_stream_read_mem,
        .fn_reset = &fn_stream_reset_mem,
        .ctx = ctx,
    };
    return stream;
}

static StreamRead make_stream_rd_file(StreamContext ctx)
{
    StreamRead stream = {
        .fn_read = &fn_stream_read_file,
        .fn_reset = &fn_stream_reset_file,
        .ctx = ctx,
    };
    return stream;
}

StreamRead make_stream_rd_from_str_buf(StrBuf* buf)
{
    return make_stream_rd_mem((StreamContext){
        .total_size = buf->len,
        .opaque = buf->ptr,
    });
}

static StreamWrite make_stream_wr_to_str_buf(StrBuf* buf, const RuntimeConfs* confs)
{
    StreamWrite stream = {
        .fn_write = &fn_stream_write_str_buf,
        .ctx = {
            .opaque = buf,
            .confs = confs,
        }
    };

    return stream;
}

s3cReply* s3c_get_object(s3cClient* client,
                            const char* bucket, const char* object_key)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    StrBuf res_buf = str_init_conf(0, client->confs.str_buf_max_cap_reserve_mb);
    StreamWrite stream_wr = make_stream_wr_to_str_buf(&res_buf, &client->confs);

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .stream_wr = &stream_wr,
    };

    s3cReply* reply = run_s3_op(client, "GET", args);

    if (reply->error == NULL) {
        reply->data = (uint8_t*)res_buf.ptr;
        reply->data_size = res_buf.len;
    } else {
        str_destroy(&res_buf);
    }

    return reply;
}

s3cReply* s3c_get_object_to_file(s3cClient* client,
                                    const char* bucket, const char* object_key,
                                    const char* file)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    if ((err = check_arg_str(file, "file")) != NULL) {
        return err;
    }

    bool file_is_new = true;
    FILE* fp = fopen(file, "r");

    if (fp != NULL) {
        file_is_new = false;
        fclose(fp);
    }

    fp = fopen(file, "w");

    if (fp == NULL) {
        err = s3c_reply_alloc("failed to open file for write");
        return err;
    }

    StreamWrite stream_wr = {
        .fn_write = &fn_stream_write_file,
        .ctx = {
            .opaque = fp,
            .confs = &client->confs,
        }
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .stream_wr = &stream_wr
    };

    s3cReply* res = run_s3_op(client, "GET", args);

    if (res->error != NULL && file_is_new) {
        remove(file);
    }

    fclose(fp);

    return res;
}

typedef struct {
    s3cStreamCb cb;
    void*       user_ctx;
    s3cReply*   reply;
} StreamCbAdapter;

static const char* fn_stream_write_cb(const char* bytes, size_t num_bytes,
                                       StreamContext* c)
{
    StreamCbAdapter* adapter = c->opaque;
    return adapter->cb(bytes, (uint64_t)num_bytes, adapter->reply->headers, adapter->user_ctx);
}

s3cReply* s3c_get_object_stream(s3cClient* client,
                                const char* bucket, const char* object_key,
                                const s3cKVL* headers,
                                s3cStreamCb cb, void* ctx)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    if (cb == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <cb>");
    }

    s3cReply* reply = s3c_reply_alloc(NULL);
    OpContext* op = calloc(1, sizeof(OpContext));

    StreamCbAdapter adapter = { .cb = cb, .user_ctx = ctx, .reply = reply };

    StreamWrite stream_wr = {
        .fn_write = &fn_stream_write_cb,
        .ctx = {
            .opaque = &adapter,
            .confs = &client->confs,
        }
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .headers = headers,
        .stream_wr = &stream_wr,
    };

    op_context_init(op, args, client, reply);

    if (op->ok) {
        op_run_request(op, "GET");
    }

    op_context_free(op);

    return reply;
}

s3cReply* s3c_put_object(s3cClient* client,
                         const char* bucket, const char* object_key,
                         const uint8_t* data, uint64_t data_size,
                         const s3cKVL* headers)
{
    s3cReply* err = check_arg_bucket_key(bucket, object_key);

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if (err != NULL) {
        return err;
    }

    if (data == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <data>");
    }

    if (!data_size) {
        return s3c_reply_alloc("provided argument value for <data_size> is 0");
    }

    StreamRead stream_rd = make_stream_rd_mem((StreamContext){
        .total_size = data_size,
        .opaque = (void*)data,
        .confs = &client->confs,
    });

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .headers = headers,
        .stream_rd = &stream_rd,
    };

    s3cReply* reply = run_s3_op(client, "PUT", args);

    return reply;
}

static void parse_xml_tag(const char* xml, const char* tag_name, StrBuf* out_buf)
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

static s3cReply* s3c_multipart_upload_abort(s3cClient* client,
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

    return run_s3_op(client, "DELETE", args);
}

static s3cReply* s3c_multipart_upload_init(s3cClient* client,
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

    s3cReply* reply = run_s3_op(client, "POST", args);

    if (reply->error) {
        return reply;
    }

    if (reply->data == NULL) {
        reply->error = str_dup(
            "multipart init failed to parse reply upload id, no reply body"
        );
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

static s3cReply* s3c_multipart_upload_finish(s3cClient* client,
                                             const char* bucket, const char* object_key,
                                             const char* upload_id, s3cKVL* etags)
{
    StrBuf body = str_init_conf(512, client->confs.str_buf_max_cap_reserve_mb);
    StrBuf error_tag = str_init_conf(0, client->confs.str_buf_max_cap_reserve_mb);

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

    StreamRead stream_rd = make_stream_rd_from_str_buf(&body);

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .query_args = &query_args,
        .stream_rd = &stream_rd,
    };

    s3cReply* reply = run_s3_op(client, "POST", args);

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


struct s3cMultipart {
    s3cClient*  client;
    char*       bucket;
    char*       object_key;
    char*       upload_id;
    StrBuf      part_buf;
    s3cKVL*     etags;
    s3cKVL*     etags_tail;
    size_t      next_part_number;
    size_t      max_retries;
    size_t      part_size;
};


void s3c_multipart_free(s3cMultipart* mp)
{
    if (mp == NULL) {
        return;
    }

    free(mp->bucket);
    free(mp->object_key);
    free(mp->upload_id);
    str_destroy(&mp->part_buf);
    s3c_kvl_free(mp->etags);
    free(mp);
}

s3cReply* s3c_multipart_init(s3cClient* client,
                             const char* bucket, const char* object_key,
                             const s3cKVL* headers,
                             const s3cMultipartOpts* opts,
                             s3cMultipart** out)
{
    *out = NULL;
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    StrBuf upload_id = str_init(128);

    s3cReply* reply = s3c_multipart_upload_init(
        client, bucket, object_key, headers, &upload_id
    );

    if (reply->error != NULL) {
        str_destroy(&upload_id);
        return reply;
    }

    s3cMultipart* mp = calloc(1, sizeof(s3cMultipart));
    mp->client = client;
    mp->bucket = str_dup(bucket);
    mp->object_key = str_dup(object_key);
    mp->upload_id = str_extract(&upload_id);
    mp->next_part_number = 1;

    mp->max_retries = opts != NULL
        ? opts->max_send_retries
        : 3;

    mp->part_size = opts != NULL && opts->part_size >= S3C_MULTIPART_MIN_PART_SIZE
        ? opts->part_size
        : S3C_MULTIPART_MIN_PART_SIZE;

    mp->part_buf = str_init_conf(0, client->confs.str_buf_max_cap_reserve_mb);

    *out = mp;
    return reply;
}

static s3cReply* s3c_multipart_upload_perform(s3cMultipart* mp,
                                              const uint8_t* data, uint64_t data_size)
{
    if (mp->next_part_number < 1 || mp->next_part_number > 10000) {
        return s3c_reply_alloc("multipart supports at most 10000 parts");
    }

    char part_num_str[21];
    snprintf(part_num_str, sizeof(part_num_str), "%" PRIu64, mp->next_part_number);

    s3cKVL q_upload_id = {
        .key = "uploadId",
        .value = mp->upload_id,
    };

    s3cKVL q_part_num = {
        .key = "partNumber",
        .value = part_num_str,
        .next = &q_upload_id,
    };

    StreamRead stream_rd = make_stream_rd_mem((StreamContext){
        .opaque = (void*)data,
        .total_size = data_size,
        .confs = &mp->client->confs,
    });

    OpArgs args = {
        .bucket = mp->bucket,
        .object_key = mp->object_key,
        .query_args = &q_part_num,
        .stream_rd = &stream_rd,
    };

    s3cReply* reply = NULL;
    unsigned num_retries = 0;

    while (1) {
        stream_rd.ctx.cursor = 0;
        reply = run_s3_op(mp->client, "PUT", args);

        if (reply->error == NULL) {
            break;
        }

        bool server_err = reply->http_resp_code == 500 ||
                          reply->http_resp_code == 502 ||
                          reply->http_resp_code == 503 ||
                          reply->http_resp_code == 504;

        if (!server_err || num_retries >= mp->max_retries) {
            return reply;
        }

        s3c_reply_free(reply);
        num_retries += 1;
    }

    // collect etag for complete call
    s3cKVL* etag = s3c_kvl_find(reply->headers, "ETag");

    if (etag == NULL) {
        free(reply->error);
        reply->error = str_dup("S3 reply missing header ETag");
        return reply;
    }

    s3cKVL* etag_copy = malloc(sizeof(s3cKVL));
    etag_copy->key = str_dup(etag->key);
    etag_copy->value = str_dup(etag->value);
    etag_copy->next = NULL;

    if (mp->etags == NULL) {
        mp->etags = etag_copy;
    } else {
        mp->etags_tail->next = etag_copy;
    }
    mp->etags_tail = etag_copy;
    mp->next_part_number += 1;

    return reply;
}

s3cReply* s3c_multipart_upload_part(s3cMultipart* mp,
                                    const uint8_t* data, uint64_t data_size)
{
    if (mp == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <multipart>");
    }

    if (data == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <data>");
    }

    if (data_size < 1) {
        return s3c_reply_alloc("provided arguments missing value for <data_size>");
    }

    if (data_size > SIZE_MAX) {
        return s3c_reply_alloc("multipart part input too large");
    }

    if (str_push(&mp->part_buf, (const char*)data, data_size) < data_size) {
        return s3c_reply_alloc("multipart part buffer allocation failed");
    }

    s3cReply* last_reply = s3c_reply_alloc(NULL);

    while (mp->part_buf.len >= mp->part_size) {
        s3cReply* reply = s3c_multipart_upload_perform(
            mp, (const uint8_t*)mp->part_buf.ptr, mp->part_size
        );

        if (reply->error != NULL) {
            s3c_reply_free(last_reply);
            return reply;
        }

        s3c_reply_free(last_reply);
        last_reply = reply;

        size_t left = mp->part_buf.len - mp->part_size;
        memmove(mp->part_buf.ptr, mp->part_buf.ptr + mp->part_size, left);
        mp->part_buf.len = left;
    }

    return last_reply;
}

s3cReply* s3c_multipart_complete(s3cMultipart* mp)
{
    if (mp == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <multipart>");
    }

    if (mp->part_buf.len > 0) {
        s3cReply* flush_reply = s3c_multipart_upload_perform(
            mp, (const uint8_t*)mp->part_buf.ptr, mp->part_buf.len
        );

        if (flush_reply->error != NULL) {
            return flush_reply;
        }

        s3c_reply_free(flush_reply);
        mp->part_buf.len = 0;
    }

    return s3c_multipart_upload_finish(
        mp->client, mp->bucket, mp->object_key,
        mp->upload_id, mp->etags
    );
}

s3cReply* s3c_multipart_abort(s3cMultipart* mp)
{
    if (mp == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <multipart>");
    }

    return s3c_multipart_upload_abort(
        mp->client, mp->bucket, mp->object_key,
        mp->upload_id
    );
}

s3cReply* s3c_put_object_from_file(s3cClient* client,
                                      const char* bucket, const char* object_key,
                                      const char* file, const s3cKVL* headers)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    err = check_arg_bucket_key(bucket, object_key);

    if (err != NULL) {
        return err;
    }

    if ((err = check_arg_str(file, "file")) != NULL) {
        return err;
    }

    s3cReply* reply = NULL;
    StrBuf read_buf = str_init_conf(0, client->confs.str_buf_max_cap_reserve_mb);

    FILE* fp = fopen(file, "r");

    if (fp == NULL) {
        reply = s3c_reply_alloc("failed to open file for read");
        goto cleanup_and_ret;
    }

    BufferedFile bf = {
        .buf = &read_buf,
        .fp = fp,
    };

    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    StreamRead stream_rd = make_stream_rd_file((StreamContext){
        .total_size = file_size,
        .opaque = &bf,
        .confs = &client->confs,
    });

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .headers = headers,
        .stream_rd = &stream_rd,
    };

    reply = run_s3_op(client, "PUT", args);
    goto cleanup_and_ret;

cleanup_and_ret:
    if (fp != NULL) {
        fclose(fp);
    }

    str_destroy(&read_buf);

    return reply;
}

s3cReply* s3c_put_object_from_file_multipart(s3cClient* client,
                                             const char* bucket, const char* object_key,
                                             const char* file,
                                             const s3cKVL* headers,
                                             const s3cMultipartOpts* opts)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    if ((err = check_arg_str(file, "file")) != NULL) {
        return err;
    }

    FILE* fp = fopen(file, "r");

    if (fp == NULL) {
        return s3c_reply_alloc("failed to open file for read");
    }

    s3cMultipart* mp = NULL;
    s3cReply* reply = s3c_multipart_init(client, bucket, object_key, headers, opts, &mp);

    if (reply->error != NULL) {
        fclose(fp);
        return reply;
    }

    s3c_reply_free(reply);

    uint8_t* chunk_buf = malloc(mp->part_size);

    while (1) {
        size_t bytes_read = fread(chunk_buf, 1, mp->part_size, fp);

        if (bytes_read < 1) {
            break;
        }

        reply = s3c_multipart_upload_part(mp, chunk_buf, bytes_read);

        if (reply->error != NULL) {
            s3cReply* abort_reply = s3c_multipart_abort(mp);
            s3c_reply_free(abort_reply);
            goto cleanup_and_ret;
        }

        s3c_reply_free(reply);
    }

    reply = s3c_multipart_complete(mp);

cleanup_and_ret:
    free(chunk_buf);
    fclose(fp);
    s3c_multipart_free(mp);

    return reply;
}

s3cReply* s3c_head_object(s3cClient* client,
                             const char* bucket, const char* object_key)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
    };

    return run_s3_op(client, "HEAD", args);
}

s3cReply* s3c_copy_object(s3cClient* client,
                          const char* src_bucket, const char* src_key,
                          const char* dst_bucket, const char* dst_key)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_str(src_bucket, "src_bucket")) != NULL) {
        return err;
    }

    if ((err = check_arg_str(src_key, "src_key")) != NULL) {
        return err;
    }

    if ((err = check_arg_bucket_key(dst_bucket, dst_key)) != NULL) {
        return err;
    }

    StrBuf copy_source = str_init(strlen(src_bucket) + strlen(src_key) + 2);
    str_push_many(&copy_source, "/", src_bucket, "/", src_key, NULL);

    s3cKVL copy_header = {
        .key = "x-amz-copy-source",
        .value = copy_source.ptr,
    };

    OpArgs args = {
        .bucket = dst_bucket,
        .object_key = dst_key,
        .headers = &copy_header,
    };

    s3cReply* reply = run_s3_op(client, "PUT", args);

    str_destroy(&copy_source);

    return reply;
}

s3cReply* s3c_delete_object(s3cClient* client,
                               const char* bucket, const char* object_key)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
    };

    return run_s3_op(client, "DELETE", args);
}

s3cReply* s3c_create_bucket(s3cClient* client,
                               const char* bucket, const s3cKVL* headers)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_str(bucket, "bucket")) != NULL) {
        return err;
    }

    StrBuf req_body = str_init_conf(256, client->confs.str_buf_max_cap_reserve_mb);
    str_push_cstr(&req_body, "<CreateBucketConfiguration "
                             "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                             "<LocationConstraint>");
    str_push_cstr(&req_body, client->keys.region);
    str_push_cstr(&req_body, "</LocationConstraint>"
                             "</CreateBucketConfiguration>");

    StreamRead stream_rd = make_stream_rd_from_str_buf(&req_body);
    stream_rd.ctx.confs = &client->confs;

    OpArgs args = {
        .bucket = bucket,
        .headers = headers,
        .stream_rd = &stream_rd,
    };

    s3cReply* reply = run_s3_op(client, "PUT", args);
    str_destroy(&req_body);

    return reply;
}

s3cReply* s3c_delete_bucket(s3cClient* client, const char* bucket)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_str(bucket, "bucket")) != NULL) {
        return err;
    }

    OpArgs args = {
        .bucket = bucket
    };

    return run_s3_op(client, "DELETE", args);
}

s3cReply* s3c_get_bucket_config(s3cClient* client,
                                const char* bucket,
                                const char* config_name)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_str(bucket, "bucket")) != NULL) {
        return err;
    }

    if ((err = check_arg_str(config_name, "config_name")) != NULL) {
        return err;
    }

    s3cKVL query_args = {
        .key = (char*)config_name,
        .value = "",
    };

    StrBuf res_buf = str_init_conf(0, client->confs.str_buf_max_cap_reserve_mb);
    StreamWrite stream_wr = make_stream_wr_to_str_buf(&res_buf, &client->confs);

    OpArgs args = {
        .bucket = bucket,
        .query_args = &query_args,
        .stream_wr = &stream_wr,
    };

    s3cReply* reply = run_s3_op(client, "GET", args);

    if (reply->error == NULL) {
        reply->data = (uint8_t*)res_buf.ptr;
        reply->data_size = res_buf.len;
    } else {
        str_destroy(&res_buf);
    }

    return reply;
}

s3cReply* s3c_set_bucket_config(s3cClient* client,
                                const char* bucket,
                                const char* config_name,
                                const char* body)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_str(bucket, "bucket")) != NULL) {
        return err;
    }

    if ((err = check_arg_str(config_name, "config_name")) != NULL) {
        return err;
    }

    if ((err = check_arg_str(body, "body")) != NULL) {
        return err;
    }

    s3cKVL query_args = {
        .key = (char*)config_name,
        .value = "",
    };

    StrBuf body_buf = str_init(strlen(body));
    str_push_cstr(&body_buf, body);

    StreamRead stream_rd = make_stream_rd_from_str_buf(&body_buf);

    OpArgs args = {
        .bucket = bucket,
        .query_args = &query_args,
        .stream_rd = &stream_rd,
    };

    s3cReply* reply = run_s3_op(client, "PUT", args);

    str_destroy(&body_buf);

    return reply;
}

static void parse_list_objects_xml(const char* xml, s3cListResult* out)
{
    StrBuf tag_buf = str_init(256);

    parse_xml_tag(xml, "IsTruncated", &tag_buf);
    out->is_truncated = tag_buf.len > 0 && strcmp(tag_buf.ptr, "true") == 0;

    parse_xml_tag(xml, "NextContinuationToken", &tag_buf);
    out->continuation_token = tag_buf.len > 0 ? str_dup(tag_buf.ptr) : NULL;

    s3cListEntry* tail = NULL;
    const char* cursor = xml;
    StrBuf field = str_init(128);

    while ((cursor = strstr(cursor, "<Contents>")) != NULL) {
        const char* block_start = cursor + strlen("<Contents>");
        const char* block_end = strstr(block_start, "</Contents>");

        if (block_end == NULL) {
            break;
        }

        size_t block_len = (size_t)(block_end - cursor) + strlen("</Contents>");
        str_set(&tag_buf, "");
        str_push(&tag_buf, cursor, block_len);

        s3cListEntry* entry = calloc(1, sizeof(s3cListEntry));

        parse_xml_tag(tag_buf.ptr, "Key", &field);
        entry->key = field.len > 0 ? str_dup(field.ptr) : NULL;

        parse_xml_tag(tag_buf.ptr, "ETag", &field);
        entry->etag = field.len > 0 ? str_dup(field.ptr) : NULL;

        parse_xml_tag(tag_buf.ptr, "LastModified", &field);
        entry->last_modified = field.len > 0 ? str_dup(field.ptr) : NULL;

        parse_xml_tag(tag_buf.ptr, "Size", &field);
        entry->size = field.len > 0 ? (uint64_t)strtoull(field.ptr, NULL, 10) : 0;

        if (tail == NULL) {
            out->entries = entry;
        } else {
            tail->next = entry;
        }
        tail = entry;

        cursor = block_end + strlen("</Contents>");
    }

    str_destroy(&field);
    str_destroy(&tag_buf);
}

static s3cReply* list_objects_page(s3cClient* client,
                                   const char* bucket,
                                   const s3cListObjectsOpts* opts,
                                   const char* continuation_token)
{
    s3cKVL* query_args = NULL;

    if (continuation_token != NULL && *continuation_token != '\0') {
        s3c_kvl_ins(&query_args, "continuation-token", continuation_token);
    } else if (opts != NULL && opts->continuation_token != NULL && *opts->continuation_token != '\0') {
        s3c_kvl_ins(&query_args, "continuation-token", opts->continuation_token);
    }

    if (opts != NULL && opts->delimiter != NULL && *opts->delimiter != '\0') {
        s3c_kvl_ins(&query_args, "delimiter", opts->delimiter);
    }

    s3c_kvl_ins(&query_args, "list-type", "2");

    if (opts != NULL && opts->max_keys > 0) {
        char max_keys_str[21];
        snprintf(max_keys_str, sizeof(max_keys_str), "%" PRIu64, opts->max_keys);
        s3c_kvl_ins(&query_args, "max-keys", max_keys_str);
    }

    if (opts != NULL && opts->prefix != NULL && *opts->prefix != '\0') {
        s3c_kvl_ins(&query_args, "prefix", opts->prefix);
    }

    if (opts != NULL && opts->start_after != NULL && *opts->start_after != '\0') {
        s3c_kvl_ins(&query_args, "start-after", opts->start_after);
    }

    StrBuf res_buf = str_init_conf(0, client->confs.str_buf_max_cap_reserve_mb);
    StreamWrite stream_wr = make_stream_wr_to_str_buf(&res_buf, &client->confs);

    OpArgs args = {
        .bucket = bucket,
        .query_args = query_args,
        .stream_wr = &stream_wr,
    };

    s3cReply* reply = run_s3_op(client, "GET", args);

    if (reply->error == NULL) {
        reply->result_kind = S3C_RESULT_LIST;
        parse_list_objects_xml(res_buf.ptr, &reply->result.list);
    }

    str_destroy(&res_buf);
    s3c_kvl_free(query_args);

    return reply;
}

s3cReply* s3c_list_objects(s3cClient* client,
                           const char* bucket,
                           const s3cListObjectsOpts* opts)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_str(bucket, "bucket")) != NULL) {
        return err;
    }

    s3cReply* reply = list_objects_page(client, bucket, opts, NULL);

    if (reply->error != NULL || opts == NULL || !opts->fetch_all) {
        return reply;
    }

    // auto-paginate: append entries from subsequent pages
    s3cListEntry* tail = reply->result.list.entries;
    while (tail != NULL && tail->next != NULL) {
        tail = tail->next;
    }

    while (reply->result.list.is_truncated &&
           reply->result.list.continuation_token != NULL) {

        s3cReply* page = list_objects_page(
            client, bucket, opts,
            reply->result.list.continuation_token
        );

        if (page->error != NULL) {
            // return the error page, discard accumulated results
            s3c_reply_free(reply);
            return page;
        }

        // steal entries from page and append to reply
        if (page->result.list.entries != NULL) {
            if (tail == NULL) {
                reply->result.list.entries = page->result.list.entries;
            } else {
                tail->next = page->result.list.entries;
            }
            // advance tail to end of new entries
            while (tail != NULL && tail->next != NULL) {
                tail = tail->next;
            }
            page->result.list.entries = NULL;
        }

        // update continuation state from latest page
        free(reply->result.list.continuation_token);
        reply->result.list.continuation_token = page->result.list.continuation_token;
        reply->result.list.is_truncated = page->result.list.is_truncated;
        page->result.list.continuation_token = NULL;

        s3c_reply_free(page);
    }

    return reply;
}

static void parse_list_multipart_uploads_xml(const char* xml, s3cMpListResult* out)
{
    s3cMpEntry* tail = NULL;
    const char* cursor = xml;
    StrBuf field = str_init(128);
    StrBuf block_buf = str_init(512);

    while ((cursor = strstr(cursor, "<Upload>")) != NULL) {
        const char* block_start = cursor + strlen("<Upload>");
        const char* block_end = strstr(block_start, "</Upload>");

        if (block_end == NULL) {
            break;
        }

        size_t block_len = (size_t)(block_end - cursor) + strlen("</Upload>");
        str_set(&block_buf, "");
        str_push(&block_buf, cursor, block_len);

        s3cMpEntry* entry = calloc(1, sizeof(s3cMpEntry));

        parse_xml_tag(block_buf.ptr, "Key", &field);
        entry->key = field.len > 0 ? str_dup(field.ptr) : NULL;

        parse_xml_tag(block_buf.ptr, "UploadId", &field);
        entry->upload_id = field.len > 0 ? str_dup(field.ptr) : NULL;

        parse_xml_tag(block_buf.ptr, "Initiated", &field);
        entry->initiated = field.len > 0 ? str_dup(field.ptr) : NULL;

        if (tail == NULL) {
            out->entries = entry;
        } else {
            tail->next = entry;
        }
        tail = entry;

        cursor = block_end + strlen("</Upload>");
    }

    str_destroy(&field);
    str_destroy(&block_buf);
}

s3cReply* s3c_list_multipart_uploads(s3cClient* client, const char* bucket)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_str(bucket, "bucket")) != NULL) {
        return err;
    }

    s3cKVL query_args = {
        .key = "uploads",
        .value = "",
    };

    OpArgs args = {
        .bucket = bucket,
        .query_args = &query_args,
    };

    s3cReply* reply = run_s3_op(client, "GET", args);

    if (reply->error == NULL && reply->data != NULL) {
        reply->result_kind = S3C_RESULT_UPLOADS;
        parse_list_multipart_uploads_xml((const char*)reply->data, &reply->result.uploads);
    }

    return reply;
}

s3cReply* s3c_abort_multipart_upload(s3cClient* client,
                                      const char* bucket, const char* object_key,
                                      const char* upload_id)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    if ((err = check_arg_str(upload_id, "upload_id")) != NULL) {
        return err;
    }

    return s3c_multipart_upload_abort(client, bucket, object_key, upload_id);
}

static void set_date_stamps(DateStamps* dates)
{
    time_t unix_now;
    time(&unix_now);

    struct tm cal_now;
    gmtime_r(&unix_now, &cal_now);

    size_t fmt_res = strftime(dates->date_time, S3C_DATE_TIME_STAMP_SIZE,
                              "%Y%m%dT%H%M%SZ",
                              &cal_now);
    assert(fmt_res == 16);

    memcpy(dates->date, dates->date_time, S3C_DATE_STAMP_SIZE - 1);
    dates->date[S3C_DATE_STAMP_SIZE - 1] = '\0';
}

static StrBuf get_req_host(const s3cClient* client)
{
    StrBuf endpoint = str_init_conf(128, client->confs.str_buf_max_cap_reserve_mb);

    const char* conf_endpoint = client->keys.endpoint;

    if (conf_endpoint == NULL || *conf_endpoint == '\0') {
        str_set      (&endpoint, "s3.");
        str_push_cstr(&endpoint, client->keys.region);
        str_push_cstr(&endpoint, ".amazonaws.com");

        return endpoint;
    }

    str_set(&endpoint, conf_endpoint);

    return endpoint;
}

static void op_context_init(OpContext* op, OpArgs args, s3cClient* client, s3cReply* reply)
{
    op->ok = false;
    op->reply = reply;
    op->client = client;
    op->args = args;

    if (client == NULL) {
        op_set_error(op, "provided arguments missing value for <client>");
        return;
    }

    if (client->keys.access_key_id == NULL ||
        strlen(client->keys.access_key_id) < 1) {

        op_set_error(op, "provided keys no access key ID set");
        return;
    }

    if (client->keys.access_key_secret == NULL ||
        strlen(client->keys.access_key_secret) < 1) {

        op_set_error(op, "provided keys no access key secret set");
        return;
    }

    if (client->keys.region == NULL || strlen(client->keys.region) < 1) {
        op_set_error(op, "provided keys no region set");
        return;
    }

    op->ok = true;
}

static void op_context_free(OpContext* op)
{
    free(op);
}

static void op_set_error(OpContext* op, const char* error)
{
    op->ok = false;

    free(op->reply->error);
    op->reply->error = NULL;

    char* copy = str_dup(error);

    op->reply->error = copy;
}

static void op_set_error_fmt(OpContext* op, const char* fmt, ...)
{
    char mbuf[256];

    va_list arg_ptr;
    va_start(arg_ptr, fmt);

    vsnprintf(mbuf, sizeof(mbuf), fmt, arg_ptr);
    va_end(arg_ptr);

    op_set_error(op, mbuf);
}

static StrBuf gen_scope_string(const char* date, const char* s3_region)
{
    StrBuf scope = str_init(128);

    str_push_many(
        &scope,
        date, "/", s3_region, "/s3/", S3_REQUEST_TYPE,
        NULL
    );

    return scope;
}

static void gen_sig_header_entries(s3cKVL* headers_in,
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

static void append_pct_encoded(StrBuf* str_buf, const char* str,
                               const char* legal_chars, size_t legal_len)
{
    const char* hex_lk = "0123456789ABCDEF";

    for (size_t i = 0; i < strlen(str); i++) {
        char c = str[i];
        bool do_escape = (c < '0' || c > '9') &&
                         (c < 'A' || c > 'Z') &&
                         (c < 'a' || c > 'z');
        // except legal chars
        for (size_t j = 0; do_escape && j < legal_len; j++) {
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

static void append_s3_escaped_string(StrBuf* str_buf, const char* str)
{
    const char legal_chars[] = "/-_.";
    append_pct_encoded(str_buf, str, legal_chars, sizeof(legal_chars) - 1);
}

static void append_uri_query_value(StrBuf* str_buf, const char* str)
{
    const char legal_chars[] = "-._~";
    append_pct_encoded(str_buf, str, legal_chars, sizeof(legal_chars) - 1);
}

static void bytes_to_hex(const uint8_t* bytes, size_t num_bytes, char* hex_out)
{
    const char* hex_lk = "0123456789abcdef";

    for (size_t in_idx = 0, out_idx = 0; in_idx < num_bytes;
                in_idx += 1, out_idx += 2) {

        hex_out[out_idx]     = hex_lk[(bytes[in_idx] >> 4) & 0x0F];
        hex_out[out_idx + 1] = hex_lk[bytes[in_idx] & 0x0F];
    }
}

static bool sha256_hex_from_bytes(const uint8_t* data, uint64_t data_size,
                                  char out_buf[S3C_SHA256_HEX_SIZE])
{
    uint8_t sha_hash[SHA256_DIGEST_LENGTH];

    if (SHA256(data, data_size, sha_hash) == NULL) {
        return false;
    }

    bytes_to_hex(sha_hash, S3C_SHA256_BIN_SIZE, out_buf);

    return true;
}


static const char* sha256_hex_from_stream(StreamRead* stream_rd,
                                          char out_buf[S3C_SHA256_HEX_SIZE])
{
    size_t READ_CHUNK_SZ = 1024 * 1024;
    const char* err = NULL;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_sha256();

    uint8_t sha_hash[EVP_MAX_MD_SIZE];

    if (mdctx == NULL || md == NULL) {
        err = "failed to allocate sha256 context";
        goto cleanup_and_ret;
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        err = "failed to init sha256 context";
        goto cleanup_and_ret;
    }

    while (1) {

        size_t bytes_read;
        const char* bytes_ptr;

        err = stream_rd->fn_read(
            READ_CHUNK_SZ, &stream_rd->ctx, &bytes_ptr, &bytes_read
        );

        if (err != NULL) {
            goto cleanup_and_ret;
        }

        if (bytes_read < 1) {
            break;
        }

        int update_res = EVP_DigestUpdate(mdctx, bytes_ptr, bytes_read);

        if (update_res != 1) {
            err = "failed to hash content";
            goto cleanup_and_ret;
        }
    }

    unsigned int sha_hash_len;

    if (EVP_DigestFinal_ex(mdctx, sha_hash, &sha_hash_len) != 1) {
        err = "failed to hash content";
        goto cleanup_and_ret;
    }

    assert(sha_hash_len == S3C_SHA256_BIN_SIZE);

    bytes_to_hex(sha_hash, S3C_SHA256_BIN_SIZE, out_buf);


cleanup_and_ret:
    if (mdctx) {
        EVP_MD_CTX_destroy(mdctx);
    }

    return err;
}

static bool hmac_sha256_from_bytes(const uint8_t* key, size_t key_size,
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

static bool gen_signing_key(const s3cKeys* keys, const char* date_stamp,
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

static bool gen_string_to_sign(const StrBuf* request_sig, const StrBuf* scope_string,
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

static bool gen_auth_header(const s3cKeys* keys,
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

s3cReply* s3c_generate_presigned_url(s3cClient* client,
                                     const char* bucket, const char* object_key,
                                     const char* method, uint64_t expires_sec)
{
    s3cReply* err = NULL;

    if (client == NULL) {
        return s3c_reply_alloc("provided arguments missing value for <client>");
    }

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    if ((err = check_arg_str(method, "method")) != NULL) {
        return err;
    }

    if (expires_sec < 1 || expires_sec > 604800) {
        return s3c_reply_alloc("presigned url <expires_sec> must be between 1 and 604800");
    }

    DateStamps dates;
    set_date_stamps(&dates);

    StrBuf endpoint    = get_req_host(client);
    StrBuf scope       = gen_scope_string(dates.date, client->keys.region);
    StrBuf sig_url     = str_init(128);
    StrBuf query_str   = str_init(256);
    StrBuf request_sig = str_init(256);
    StrBuf sts         = str_init(256);

    // build canonical URI: /<bucket>/<key>
    str_push_char(&sig_url, '/');
    append_s3_escaped_string(&sig_url, bucket);
    str_push_char(&sig_url, '/');
    append_s3_escaped_string(&sig_url, object_key);

    // build credential
    StrBuf credential = str_init(128);
    str_push_many(&credential,
        client->keys.access_key_id, "/", scope.ptr,
        NULL
    );

    // build canonical query string (params must be sorted)
    StrBuf encoded_cred = str_init(128);
    append_uri_query_value(&encoded_cred, credential.ptr);

    char expires_str[21];
    snprintf(expires_str, sizeof(expires_str), "%" PRIu64, expires_sec);

    str_push_many(&query_str,
        "X-Amz-Algorithm=", S3_SIGNATURE_ALGO,
        "&X-Amz-Credential=", encoded_cred.ptr,
        "&X-Amz-Date=", dates.date_time,
        "&X-Amz-Expires=", expires_str,
        "&X-Amz-SignedHeaders=host",
        NULL
    );

    // canonical request
    str_push_many(&request_sig,
        method, "\n",
        sig_url.ptr, "\n",
        query_str.ptr, "\n",
        "host:", endpoint.ptr, "\n",
        "\n",
        "host\n",
        "UNSIGNED-PAYLOAD",
        NULL
    );

    // string to sign
    bool gen_ok = gen_string_to_sign(&request_sig, &scope, dates.date_time, &sts);

    uint8_t signing_key[S3C_SHA256_BIN_SIZE];
    gen_ok = gen_ok && gen_signing_key(&client->keys, dates.date, signing_key);

    uint8_t signature_bin[S3C_SHA256_BIN_SIZE];
    gen_ok = gen_ok && hmac_sha256_from_bytes(
        signing_key, S3C_SHA256_BIN_SIZE,
        (const uint8_t*)sts.ptr, sts.len,
        signature_bin
    );

    s3cReply* reply = NULL;

    if (!gen_ok) {
        reply = s3c_reply_alloc("presigned url signature generation failed");
        goto cleanup_and_ret;
    }

    char signature_hex[S3C_SHA256_HEX_SIZE + 1] = {'\0'};
    bytes_to_hex(signature_bin, S3C_SHA256_BIN_SIZE, signature_hex);

    // build final URL
    StrBuf url = str_init(512);
    str_push_many(&url,
        "https://", endpoint.ptr,
        sig_url.ptr,
        "?", query_str.ptr,
        "&X-Amz-Signature=", signature_hex,
        NULL
    );

    reply = s3c_reply_alloc(NULL);
    reply->data = (uint8_t*)str_extract(&url);
    reply->data_size = strlen((char*)reply->data);

cleanup_and_ret:
    str_destroy(&endpoint);
    str_destroy(&scope);
    str_destroy(&sig_url);
    str_destroy(&query_str);
    str_destroy(&request_sig);
    str_destroy(&sts);
    str_destroy(&credential);
    str_destroy(&encoded_cred);

    return reply;
}

static void op_run_request(OpContext* op, const char* html_verb)
{
    uint64_t max_cap_reserve_mb = op->client->confs.str_buf_max_cap_reserve_mb;
    StrBuf request = str_init_conf(128, max_cap_reserve_mb),
           request_sig = str_init_conf(128, max_cap_reserve_mb),
           sig_headers = str_init_conf(128, max_cap_reserve_mb),
           sig_header_names = str_init_conf(128, max_cap_reserve_mb),
           auth_header = str_init_conf(128, max_cap_reserve_mb),
           sig_url = str_init_conf(128, max_cap_reserve_mb),
           req_url = str_init_conf(128, max_cap_reserve_mb),
           query_str = str_init_conf(128, max_cap_reserve_mb),
           endpoint = get_req_host(op->client);

    s3cKVL* headers = NULL;

    DateStamps dates;
    set_date_stamps(&dates);

    // copy and sort headers
    for (const s3cKVL* h = op->args.headers; h; h = h->next) {
        s3c_kvl_ins(&headers, h->key, h->value);
    }

    // asserting query args are sorted
    for (const s3cKVL* h = op->args.query_args; h; h = h->next) {
        append_uri_query_value(&query_str, h->key);
        str_push_char(&query_str, '=');
        append_uri_query_value(&query_str, h->value);
        if (h->next) {
            str_push_char(&query_str, '&');
        }
    }

    s3c_kvl_upsert(&headers, "host", endpoint.ptr);
    s3c_kvl_upsert(&headers, "x-amz-date", dates.date_time);

    char content_sha_hex[] =
    // sha256 hash for empty string
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    if (op->args.stream_rd != NULL) {
        const char* hash_err = sha256_hex_from_stream(
            op->args.stream_rd, content_sha_hex
        );

        if (hash_err != NULL) {
            op_set_error(op, hash_err);
            goto cleanup_and_ret;
        }

        s3c_kvl_remove(&headers, "content-length");
        s3c_kvl_ins_int(
            &headers, "content-length", op->args.stream_rd->ctx.total_size
        );
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
        &op->client->keys, &dates,
        &request_sig, &sig_header_names,
        &auth_header
    );

    if (!sig_ok) {
        op_set_error(op, "AWS4 signature generation failed => "
                         "hmac sha256 hash gen unsuccessful");
        goto cleanup_and_ret;
    }

    s3c_kvl_upsert(&headers, "authorization", auth_header.ptr);
    if (op->client->confs.client_idle_sec_max > 0) {
        s3c_kvl_upsert(&headers, "connection", "keep-alive");
    } else {
        s3c_kvl_upsert(&headers, "connection", "close");
    }

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

    op_send_request(op, html_verb, &request);

    if (!op->ok && op->should_retry) {
        // conection stale / transient net io error, reset state and try again
        const char* reset_err = op->args.stream_rd != NULL
            ? op->args.stream_rd->fn_reset(&op->args.stream_rd->ctx)
            : NULL;

        if (reset_err != NULL) {
            op_set_error_fmt(op,
                            "http send retry failed: %s, net io error: %s",
                            reset_err, op->reply->error);
            goto cleanup_and_ret;
        }


        s3c_reply_reset(op->reply);
        op->ok = true;
        op->should_retry = false;

        op_send_request(op, html_verb, &request);
    }

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

static const char* ossl_ctx_init(SSL_CTX** out_ctx)
{
    *out_ctx = NULL;

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());

    if (ssl_ctx == NULL) {
        return "openssl failed to allocate ssl context";
    }

    // Configure CTX before SSL_new: SSL_new copies verify_mode from the CTX
    // at creation time, so these must be set before the SSL object is created.
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    if (!SSL_CTX_set_default_verify_paths(ssl_ctx)) {
        SSL_CTX_free(ssl_ctx);
        return "openssl failed to set the default trusted certificate store";
    }

    if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION)) {
        SSL_CTX_free(ssl_ctx);
        return "openssl failed to set the minimum TLS protocol version";
    }

    *out_ctx = ssl_ctx;
    return NULL;
}

static const char* ossl_init(OsslContext* octx, SSL_CTX* ssl_ctx)
{
    octx->ssl = SSL_new(ssl_ctx);

    if (octx->ssl == NULL) {
        return "openssl failed to allocate ssl object";
    }

    SSL_set_mode(octx->ssl, SSL_MODE_AUTO_RETRY);

    return NULL;
}

static void ossl_disconnect(OsslContext* octx)
{
    if (octx == NULL || octx->ssl == NULL) {
        return;
    }

    SSL_set_shutdown(octx->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    SSL_free(octx->ssl);
    octx->ssl = NULL;
}

static void ossl_free(OsslContext* octx)
{
    if (octx == NULL) {
        return;
    }

    ossl_disconnect(octx);
    free(octx);
}

static bool errno_is_timeout()
{
    return errno == EAGAIN || errno == EWOULDBLOCK;
}

static const char* ossl_proc_io_res(OsslContext* octx, int io_res)
{
    if (io_res == 1) {
        return NULL;
    }

    int ssl_err = SSL_get_error(octx->ssl, io_res);

    if (ssl_err == SSL_ERROR_ZERO_RETURN) {
        return NULL;
    }

    if (errno_is_timeout()) {
        return "net timeout";
    }

    if (errno == ECONNRESET) {
        SSL_set_shutdown(octx->ssl, SSL_RECEIVED_SHUTDOWN);
        return "connection was reset by peer";
    }

    return "unknown net error occured";
}

static BIO* create_socket_bio(const char *host, const char *proto, uint64_t net_timeout_sec)
{
    BIO_ADDRINFO* bio_addr_info;

    int lk_res = BIO_lookup_ex(
        host, proto, BIO_LOOKUP_CLIENT,
        AF_UNSPEC, SOCK_STREAM, 0,
        &bio_addr_info
    );

    if (lk_res == 0 || bio_addr_info == NULL) {
        return NULL;
    }

    int sock = -1;
    const BIO_ADDRINFO *ai = NULL;

    struct timeval timeout;
    timeout.tv_sec = (time_t)net_timeout_sec;
    timeout.tv_usec = 0;

    for (ai = bio_addr_info; sock == -1 && ai != NULL; ai = BIO_ADDRINFO_next(ai)) {

        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);

        if (sock == -1) {
            continue;
        }

        if (net_timeout_sec > 0) {

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

static const char* ossl_connect(OsslContext* octx, const char* host, uint64_t net_timeout_sec)
{
    BIO* bio = create_socket_bio(host, "https", net_timeout_sec);

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

static char* trim_string(char* s, size_t len)
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

static int parse_http_resp_code(char* header_line)
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

static void parse_header_line(s3cKVL** headers, char* header_string)
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

static const char* parse_header_block(char* header_block, size_t header_block_len,
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
            bool http_proto_ok =
                memcmp(S3_HTTP_VERSION, str_ptr, strlen(S3_HTTP_VERSION)) == 0;

            if (!http_proto_ok || resp_code < 0) {
                return "wrong http protocol";
            }

            *out_resp_code = (unsigned)resp_code;

            first_line_parsed = true;
        }

        str_ptr += line_len + 1;
        len_left -= line_len + 1;
    }

    if (!first_line_parsed) {
        return "failed to parse http headers";
    }

    return NULL;
}

static bool http_resp_code_is_ok(unsigned http_resp_code)
{
    return http_resp_code < 300 && http_resp_code > 199;
}

static bool op_ossl_io_read(OpContext* op,
                            StrBuf* recv_buf, size_t max_bytes_to_read,
                            size_t* out_bytes_recv)
{
    *out_bytes_recv = 0;
    OsslContext* octx = op->client->conn;

    size_t min_cap = recv_buf->len + max_bytes_to_read + 1;
    size_t set_cap = str_set_cap(recv_buf, min_cap);

    if (set_cap < min_cap) {
        op_set_error(op, "http reply allocation failed");
        return false;
    }

    char* wptr = recv_buf->ptr + recv_buf->len;

    errno = 0;
    int io_res = SSL_read_ex(
        octx->ssl, wptr, max_bytes_to_read,
        out_bytes_recv
    );

    const char* err = ossl_proc_io_res(octx, io_res);

    if (err) {
        op->should_retry = !errno_is_timeout();
        op_set_error_fmt(op, "failed to read http reply: %s", err);
        return false;
    }

    if (*out_bytes_recv == 0 &&
        SSL_get_error(octx->ssl, 0) != SSL_ERROR_ZERO_RETURN) {

        op->should_retry = true;
        op_set_error(op, "failed to read http reply: host hang up");
        return false;
    }

    recv_buf->len += *out_bytes_recv;
    recv_buf->ptr[recv_buf->len] = '\0';

    return true;
}

static bool op_ossl_io_write(OpContext* op, const char* data, size_t data_size)
{
    OsslContext* octx = op->client->conn;
    size_t bytes_sent = 0;

    errno = 0;
    int io_res = SSL_write_ex(
        octx->ssl, data, data_size,
        &bytes_sent
    );

    const char* err = ossl_proc_io_res(octx, io_res);

    if (err) {
        op->should_retry = !errno_is_timeout();
        op_set_error_fmt(op, "failed to send http request: %s", err);
        return false;
    }

    if (bytes_sent < data_size) {
        op->should_retry = true;
        op_set_error(op, "failed to send http request: SSL transmission error");
        return false;
    }

    return true;
}

static bool parse_reply_content_length(s3cKVL* rep_headers, int64_t* out_len)
{
    *out_len = 0;

    s3cKVL* ct_len = s3c_kvl_find(rep_headers, "content-length");
    if (ct_len == NULL) {
        return false;
    }

    errno = 0;
    char* p_end = NULL;
    int64_t res = strtol(ct_len->value, &p_end, 10);

    if (errno != 0 || p_end == NULL ||
        *p_end != '\0' || p_end == ct_len->value) {
        return false;
    }

    *out_len = res;
    return true;
}

static bool header_has_token(s3cKVL* headers, const char* name, const char* token)
{
    s3cKVL* hdr = s3c_kvl_find(headers, name);
    if (hdr == NULL || hdr->value == NULL) {
        return false;
    }

    const char* p = hdr->value;
    size_t tok_len = strlen(token);

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p += 1;
        }

        const char* start = p;
        while (*p != '\0' && *p != ',') {
            p += 1;
        }

        const char* end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end -= 1;
        }

        if ((size_t)(end - start) == tok_len) {
            bool match = true;
            for (size_t i = 0; i < tok_len; i++) {
                char a = (char)tolower((unsigned char)start[i]);
                char b = (char)tolower((unsigned char)token[i]);
                if (a != b) {
                    match = false;
                    break;
                }
            }

            if (match) {
                return true;
            }
        }
    }

    return false;
}

static const char* emit_reply_body(OpContext* op,
                                   bool http_resp_code_ok,
                                   const char* bytes, size_t num_bytes,
                                   StrBuf* body_buf)
{
    if (num_bytes == 0) {
        return NULL;
    }

    if (op->args.stream_wr != NULL && http_resp_code_ok) {
        return op->args.stream_wr->fn_write(bytes, num_bytes, &op->args.stream_wr->ctx);
    }

    if (str_push(body_buf, bytes, num_bytes) < num_bytes) {
        return "http reply allocation failed";
    }

    return NULL;
}

static const char* parse_chunk_size_line(const char* line, size_t line_len, size_t* out_chunk_size)
{
    size_t end = 0;

    while (end < line_len && line[end] != ';') {
        end += 1;
    }

    if (end < 1) {
        return "http chunked reply invalid chunk size";
    }

    uint64_t chunk_size = 0;
    for (size_t i = 0; i < end; i++) {
        char c = line[i];
        uint8_t hex;

        if (c >= '0' && c <= '9') {
            hex = (uint8_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            hex = (uint8_t)(10 + c - 'a');
        } else if (c >= 'A' && c <= 'F') {
            hex = (uint8_t)(10 + c - 'A');
        } else {
            return "http chunked reply invalid chunk size";
        }

        chunk_size = chunk_size * 16 + hex;
    }

    *out_chunk_size = (size_t)chunk_size;
    return NULL;
}

typedef struct {
    int64_t body_received;
    int64_t chunk_bytes_left;
    size_t chunk_parse_pos;
    bool done;
} ChunkedState;

static void parse_chunked_body(OpContext* op,
                               bool http_resp_code_ok,
                               StrBuf* recv_buf,
                               StrBuf* body_buf,
                               ChunkedState* st)
{
    const char* proc_err = NULL;

    while (1) {
        if (st->chunk_bytes_left < 0) {
            const char* lstart = recv_buf->ptr + st->chunk_parse_pos;
            size_t lspace = recv_buf->len - st->chunk_parse_pos;
            char* lbreak = memchr(lstart, '\n', lspace);

            if (lbreak == NULL) {
                break;
            }

            if (lbreak == lstart || lbreak[-1] != '\r') {
                op_set_error(op, "http chunked reply malformed line ending");
                return;
            }

            size_t line_len = (size_t)(lbreak - lstart - 1);
            size_t chunk_size = 0;
            const char* chunk_err = parse_chunk_size_line(
                lstart, line_len, &chunk_size
            );

            if (chunk_err != NULL) {
                op_set_error(op, chunk_err);
                return;
            }

            st->chunk_parse_pos = (size_t)(lbreak - recv_buf->ptr + 1);

            if (chunk_size == 0) {
                // after "0\r\n", expect either empty trailer "\r\n"
                // or trailer headers ending with "\r\n\r\n"
                size_t left = recv_buf->len - st->chunk_parse_pos;

                if (left >= 2 &&
                    recv_buf->ptr[st->chunk_parse_pos] == '\r' &&
                    recv_buf->ptr[st->chunk_parse_pos + 1] == '\n') {
                    // empty trailers — done
                    st->chunk_parse_pos += 2;
                    st->done = true;
                    break;
                }

                // non-empty trailers: scan for "\r\n\r\n"
                if (left >= 4) {
                    const char* trailers = recv_buf->ptr + st->chunk_parse_pos;
                    char* trailers_end = strstr(trailers, "\r\n\r\n");
                    if (trailers_end != NULL) {
                        st->chunk_parse_pos = (size_t)(trailers_end - recv_buf->ptr + 4);
                        st->done = true;
                        break;
                    }
                }

                break;
            }

            st->chunk_bytes_left = (int64_t)chunk_size;
        }

        if (st->chunk_bytes_left > 0) {
            size_t avail = recv_buf->len - st->chunk_parse_pos;
            if (avail < 1) {
                break;
            }

            size_t to_emit = avail;
            if ((int64_t)to_emit > st->chunk_bytes_left) {
                to_emit = (size_t)st->chunk_bytes_left;
            }

            proc_err = emit_reply_body(
                op, http_resp_code_ok,
                recv_buf->ptr + st->chunk_parse_pos, to_emit, body_buf
            );

            if (proc_err != NULL) {
                op_set_error_fmt(op, "http reply recv failed: %s", proc_err);
                return;
            }

            st->body_received += (int64_t)to_emit;
            st->chunk_parse_pos += to_emit;
            st->chunk_bytes_left -= (int64_t)to_emit;

            if (st->chunk_bytes_left > 0) {
                break;
            }

            if (recv_buf->len - st->chunk_parse_pos < 2) {
                break;
            }

            if (recv_buf->ptr[st->chunk_parse_pos] != '\r' ||
                recv_buf->ptr[st->chunk_parse_pos + 1] != '\n') {
                op_set_error(op, "http chunked reply malformed chunk terminator");
                return;
            }

            st->chunk_parse_pos += 2;
            st->chunk_bytes_left = -1;
        }
    }

    if (st->chunk_parse_pos > 0) {
        size_t left = recv_buf->len - st->chunk_parse_pos;
        memmove(recv_buf->ptr, recv_buf->ptr + st->chunk_parse_pos, left);
        recv_buf->len = left;
        recv_buf->ptr[recv_buf->len] = '\0';
        st->chunk_parse_pos = 0;
    }
}

static void op_read_reply(OpContext* op, const char* html_verb)
{
    const size_t RECV_CAP = 1024 * 1024;
    StrBuf recv_buf = str_init_conf(0, op->client->confs.str_buf_max_cap_reserve_mb);
    StrBuf body_buf = str_init_conf(0, op->client->confs.str_buf_max_cap_reserve_mb);

    enum {
        BODY_NONE = 0,
        BODY_CONTENT_LENGTH,
        BODY_CHUNKED,
        BODY_UNTIL_CLOSE,
    } body_mode = BODY_NONE;

    bool headers_parsed = false;
    bool body_done = false;
    unsigned http_resp_code = 0;
    bool http_resp_code_ok = false;
    int64_t content_length = 0;
    int64_t body_received = 0;

    ChunkedState chunk_st = {
        .body_received = 0,
        .chunk_bytes_left = -1,
        .chunk_parse_pos = 0,
        .done = false,
    };

    op->can_reuse_conn = false;

    for (;;) {
        if (headers_parsed) {
            const char* proc_err = NULL;

            if (body_mode == BODY_NONE) {
                if (recv_buf.len == 0) {
                    body_done = true;
                } else {
                    body_mode = BODY_UNTIL_CLOSE;
                }
            }

            if (body_mode == BODY_CONTENT_LENGTH && recv_buf.len > 0) {
                int64_t bytes_left = content_length - body_received;
                if (bytes_left < 0) {
                    op_set_error(op, "http reply internal parse error");
                    goto cleanup_and_ret;
                }

                size_t to_emit = recv_buf.len;
                if ((int64_t)to_emit > bytes_left) {
                    to_emit = (size_t)bytes_left;
                }

                proc_err = emit_reply_body(
                    op, http_resp_code_ok,
                    recv_buf.ptr, to_emit, &body_buf
                );

                if (proc_err != NULL) {
                    op_set_error_fmt(op, "http reply recv failed: %s", proc_err);
                    goto cleanup_and_ret;
                }

                body_received += (int64_t)to_emit;

                if (to_emit < recv_buf.len) {
                    op_set_error(op, "http reply body larger than content-length");
                    goto cleanup_and_ret;
                }

                recv_buf.len = 0;
                if (recv_buf.ptr != NULL) {
                    recv_buf.ptr[0] = '\0';
                }

                if (body_received >= content_length) {
                    body_done = true;
                }
            }

            if (body_mode == BODY_UNTIL_CLOSE && recv_buf.len > 0) {
                proc_err = emit_reply_body(
                    op, http_resp_code_ok,
                    recv_buf.ptr, recv_buf.len, &body_buf
                );

                if (proc_err != NULL) {
                    op_set_error_fmt(op, "http reply recv failed: %s", proc_err);
                    goto cleanup_and_ret;
                }

                body_received += (int64_t)recv_buf.len;
                recv_buf.len = 0;
                if (recv_buf.ptr != NULL) {
                    recv_buf.ptr[0] = '\0';
                }
            }

            if (body_mode == BODY_CHUNKED) {
                parse_chunked_body(op, http_resp_code_ok, &recv_buf, &body_buf, &chunk_st);
                if (!op->ok) {
                    goto cleanup_and_ret;
                }
                if (chunk_st.done) {
                    body_done = true;
                }
            }

            if (body_done) {
                break;
            }
        }

        size_t bytes_recv = 0;

        if (!op_ossl_io_read(op, &recv_buf, RECV_CAP, &bytes_recv)) {
            goto cleanup_and_ret;
        }

        if (bytes_recv == 0) {
            if (!headers_parsed) {
                // server closed connection, most probably becasue client idled too long
                op->should_retry = true;
                op_set_error(op, "failed to read http reply headers");
                goto cleanup_and_ret;
            }

            if (body_mode == BODY_UNTIL_CLOSE || body_mode == BODY_NONE) {
                body_done = true;
                break;
            }
            op_set_error(op, "http reply ended before body was fully received");
            goto cleanup_and_ret;
        }

        if (!headers_parsed) {
            const char* delim = strstr(recv_buf.ptr, "\r\n\r\n");
            if (delim == NULL || delim == recv_buf.ptr) {
                continue;
            }

            ptrdiff_t block_len = delim - recv_buf.ptr;
            if (block_len < 4) {
                op_set_error(op, "http reply internal parse error");
                goto cleanup_and_ret;
            }

            const char* parse_err = parse_header_block(
                recv_buf.ptr, (size_t)block_len,
                &op->reply->headers,
                &http_resp_code
            );

            if (parse_err != NULL) {
                op_set_error(op, parse_err);
                goto cleanup_and_ret;
            }

            http_resp_code_ok = http_resp_code_is_ok(http_resp_code);

            for (s3cKVL* h = op->reply->headers; h != NULL; h = h->next) {
            }
            size_t body_start = (size_t)block_len + 4;
            size_t body_bytes = recv_buf.len - body_start;

            memmove(recv_buf.ptr, recv_buf.ptr + body_start, body_bytes);
            recv_buf.len = body_bytes;
            recv_buf.ptr[recv_buf.len] = '\0';

            headers_parsed = true;

            bool is_head_req = strcmp(html_verb, "HEAD") == 0;
            bool no_body_resp = is_head_req ||
                                http_resp_code == 204 ||
                                http_resp_code == 304;

            bool is_chunked = header_has_token(
                op->reply->headers, "transfer-encoding", "chunked"
            );
            bool conn_close = header_has_token(
                op->reply->headers, "connection", "close"
            );
            bool conn_keep_alive = header_has_token(
                op->reply->headers, "connection", "keep-alive"
            );

            bool has_content_length = parse_reply_content_length(op->reply->headers,
                                                                 &content_length);

            if (no_body_resp) {
                body_mode = BODY_NONE;

            } else if (is_chunked) {
                body_mode = BODY_CHUNKED;

            } else if (has_content_length) {
                // some servers set content-length: -1 for body-less replies
                if (content_length <= 0) {
                    body_mode = BODY_NONE;

                } else {
                    body_mode = BODY_CONTENT_LENGTH;
                    if (op->args.stream_wr != NULL && http_resp_code_ok) {
                        op->args.stream_wr->ctx.total_size = (size_t)content_length;
                    }
                }
            } else {
                body_mode = BODY_UNTIL_CLOSE;
            }

            op->can_reuse_conn = !conn_close && body_mode != BODY_UNTIL_CLOSE
                                && (conn_keep_alive || has_content_length);
        }
    }

    op_proc_reply(op, &body_buf, http_resp_code);

cleanup_and_ret:
    if (!op->ok) {
        op->can_reuse_conn = false;
    }

    str_destroy(&recv_buf);
    str_destroy(&body_buf);
}

static const char* client_ensure_conn(s3cClient* client, const char* host)
{
    if (client->conn == NULL) {
        client->conn = calloc(1, sizeof(OsslContext));
        if (client->conn == NULL) {
            return "failed to allocate connection context";
        }
    }
    if (client->conn->ssl != NULL) {

        time_t idle_sec = time(NULL) - client->last_used;

        if (client->last_used > 0 && idle_sec >= (time_t)client->confs.client_idle_sec_max) {
            ossl_disconnect(client->conn);

        } else {
            return NULL;
        }
    } else {
    }

    const char* err = ossl_init(client->conn, client->ssl_ctx);
    if (err != NULL) {
        return err;
    }

    err = ossl_connect(client->conn, host, client->confs.net_io_timeout_sec);
    if (err != NULL) {
        ossl_disconnect(client->conn);
        return err;
    }

    return NULL;
}

static void op_send_request(OpContext* op, const char* html_verb, StrBuf* rq_head)
{
    StrBuf endpoint = get_req_host(op->client);

    const char* conn_err = client_ensure_conn(op->client, endpoint.ptr);
    if (conn_err != NULL) {
        op->should_retry = true;
        op_set_error(op, conn_err);
        goto cleanup_and_ret;
    }

    if (!op_ossl_io_write(op, rq_head->ptr, rq_head->len)) {
        goto cleanup_and_ret;
    }

    if (op->args.stream_rd != NULL) {
        const size_t SEND_CHUNK_SZ = 1024 * 1024;

        while (1) {
            size_t bytes_to_send = 0;
            const char* bytes_ptr = NULL;

            const char* rd_err = op->args.stream_rd->fn_read(
                SEND_CHUNK_SZ, &op->args.stream_rd->ctx,
                &bytes_ptr, &bytes_to_send
            );

            if (rd_err != NULL) {
                op_set_error_fmt(op, "failed to read request body: %s", rd_err);
                goto cleanup_and_ret;
            }

            if (bytes_to_send < 1) {
                break;
            }

            if (!op_ossl_io_write(op, bytes_ptr, bytes_to_send)) {
                goto cleanup_and_ret;
            }
        }
    }

    op_read_reply(op, html_verb);

cleanup_and_ret:
    if (!op->ok || !op->can_reuse_conn) {
        ossl_disconnect(op->client->conn);
    } else {
        op->client->last_used = time(NULL);
    }

    str_destroy(&endpoint);
}

static void op_proc_reply(OpContext* op, StrBuf* reply, unsigned http_resp_code)
{
    if (!op->ok) {
        return;
    }

    op->reply->http_resp_code = http_resp_code;

    bool rep_code_ok = http_resp_code_is_ok(http_resp_code);

    if (!rep_code_ok || op->args.stream_wr == NULL) {
        op->reply->data_size = reply->len;
        op->reply->data = (uint8_t*)str_extract(reply);
    }

    if (rep_code_ok) {
        return;
    }

    StrBuf err_buf = str_init(0);

    str_set(&err_buf, "S3 endpoint replied with HTTP response code ");
    str_push_int(&err_buf, http_resp_code);

    if (op->reply->data_size > 0) {
        str_push_cstr(&err_buf, ": ");
        parse_xml_tag((const char*)op->reply->data, "Message", &err_buf);
    }

    op_set_error(op, err_buf.ptr);

    str_destroy(&err_buf);
}

static int cmp_no_case(char const *a, char const *b)
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

void s3c_kvl_ins_int(s3cKVL** head_ref, const char* name, int64_t int_value)
{
    StrBuf sbuf = str_init(20);
    str_push_int(&sbuf, int_value);

    s3c_kvl_ins(head_ref, name, sbuf.ptr);

    str_destroy(&sbuf);
}

void s3c_kvl_ins(s3cKVL** head_ref, const char* name, const char* value)
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

    // append value to existing header
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

s3cKVL* s3c_kvl_find(s3cKVL* head_ref, const char* name)
{
    for (; head_ref != NULL; head_ref = head_ref->next) {
        if (cmp_no_case(name, head_ref->key) == 0) {
            return head_ref;
        }
    }
    return NULL;
}

void s3c_kvl_remove(s3cKVL** head_ref, const char* name)
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

static void s3c_kvl_upsert(s3cKVL** head, const char* name, const char* value)
{
    s3cKVL* h = s3c_kvl_find(*head, name);

    if (h != NULL) {
        free(h->value);
        h->value = str_dup(value);
    } else {
        s3c_kvl_ins(head, name, value);
    }
}

void s3c_kvl_free(s3cKVL* head)
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

static StrBuf str_init(size_t cap)
{
    return str_init_conf(cap, S3C_DEF_STR_BUF_MAX_CAP_RESERVE_MB);
}

static StrBuf str_init_conf(size_t cap, uint64_t max_cap_reserve_mb)
{
    char* ptr = cap > 0 ? calloc(1, cap + 1) : NULL;

    StrBuf res = {
        .ptr = ptr,
        .len = 0,
        .cap = cap,
        .max_cap_reserve_mb = max_cap_reserve_mb,
    };

    return res;
}

static void str_destroy(StrBuf* s)
{
    free(s->ptr);
    *s = str_init_conf(0, s->max_cap_reserve_mb);
}

static char* str_extract(StrBuf* s)
{
    char* ret = s->ptr;
    *s = str_init_conf(0, s->max_cap_reserve_mb);

    return ret;
}

static size_t str_set_cap(StrBuf* s, size_t cap)
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

static size_t str_push(StrBuf* s, const char* a, size_t a_len)
{
    if (s->ptr != NULL && a_len < 1) {
        return 0;
    }

    if (s->cap < 1 || s->len + a_len > s->cap) {

        if (s->cap < 1) {
            s->cap = 64;
        }

        uint64_t max_cap_reserve_mb = s->max_cap_reserve_mb > 0
            ? s->max_cap_reserve_mb
            : S3C_DEF_STR_BUF_MAX_CAP_RESERVE_MB;

        size_t max_reserve_size = max_cap_reserve_mb * 1024 * 1024;

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

static size_t str_push_char(StrBuf* s, char c)
{
    return str_push(s, &c, 1);
}

static size_t str_push_str(StrBuf* s, const StrBuf* a)
{
    return str_push(s, a->ptr, a->len);
}

static size_t str_push_cstr(StrBuf* s, const char* a)
{
    return str_push(s, a, strlen(a));
}

static size_t str_push_many(StrBuf* s, ...)
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

static size_t str_set(StrBuf* s, const char* a)
{
    s->len = 0;
    return str_push_cstr(s, a);
}

static size_t str_push_int(StrBuf* s, int64_t i)
{
    char buf [20 + 1];
    size_t len = snprintf(buf, sizeof(buf), "%" PRId64 , i);

    return str_push(s, buf, len);
}
