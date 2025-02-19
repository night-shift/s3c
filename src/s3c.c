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

} S3C_GLOBAL_CONFS = {
    .net_io_timeout_sec           = 15,
    .max_reply_prealloc_size_mb   = 128,
    .str_buf_max_cap_reserve_mb   = 10,
};

typedef struct {
    SSL*     ssl;
    SSL_CTX* ssl_ctx;
} OsslContext;

static const char* ossl_init(OsslContext*);
static void        ossl_free(OsslContext*);
static const char* ossl_connect(OsslContext*, const char* host);


typedef struct {
    size_t total_size;
    size_t cursor;
    void* opaque;
} StreamContext;

typedef struct {
    const char* (*fn_write)(const char*, size_t, StreamContext*);
    StreamContext ctx;
} StreamWrite;

typedef struct {
    const char* (*fn_read)(size_t, StreamContext*, const char**, size_t*);
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
    FILE* fp;
    StrBuf* buf;
} BufferedFile;

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

uint64_t s3c_set_global_config(uint64_t opt, int64_t value)
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

void s3c_reply_free(s3cReply* reply)
{
    if (reply == NULL) {
        return;
    }

    s3c_kvl_free(reply->headers);

    free(reply->error);
    free(reply->data);

    free(reply);
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

static s3cReply* run_s3_op(const s3cKeys* keys, const char* html_verb, OpArgs args)
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

static const char* fn_stream_write_str_buf(const char* bytes, size_t num_bytes,
                                           StreamContext* c)
{
    StrBuf* str_buf = c->opaque;

    if (str_buf->cap < 1 && c->total_size > 0) {

        size_t max_mem_prealloc_size =
            S3C_GLOBAL_CONFS.max_reply_prealloc_size_mb * 1024 * 1024;

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

StreamRead make_stream_rd_from_str_buf(StrBuf* buf)
{
    StreamRead stream = {
        .fn_read = &fn_stream_read_mem,
        .ctx = {
            .total_size = buf->len,
            .cursor = 0,
            .opaque = buf->ptr,
        }
    };

    return stream;
}

s3cReply* s3c_get_object(const s3cKeys* keys,
                         const char* bucket, const char* object_key)
{
    s3cReply* err = NULL;

    if ((err = check_arg_bucket_key(bucket, object_key)) != NULL) {
        return err;
    }

    StrBuf res_buf = {0};

    StreamWrite stream_wr = {
        .fn_write = &fn_stream_write_str_buf,
        .ctx = {
            .opaque = &res_buf,
        }
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .stream_wr = &stream_wr,
    };

    s3cReply* reply = run_s3_op(keys, "GET", args);

    if (reply->error == NULL) {
        reply->data = (uint8_t*)res_buf.ptr;
        reply->data_size = res_buf.len;
    } else {
        str_destroy(&res_buf);
    }

    return reply;
}

s3cReply* s3c_get_object_to_file(const s3cKeys* keys,
                                 const char* bucket, const char* object_key,
                                 const char* file)
{
    s3cReply* err = NULL;

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
        }
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .stream_wr = &stream_wr
    };

    s3cReply* res = run_s3_op(keys, "GET", args);

    if (res->error != NULL && file_is_new) {
        remove(file);
    }

    fclose(fp);

    return res;
}

s3cReply* s3c_put_object(const s3cKeys* keys,
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

    StreamRead stream_rd = {
        .fn_read = &fn_stream_read_mem,
        .ctx = {
            .total_size = data_size,
            .cursor = 0,
            .opaque = (void*)data,
        }
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .headers = headers,
        .stream_rd = &stream_rd,
    };

    s3cReply* reply = run_s3_op(keys, "PUT", args);

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

static s3cReply* s3c_multipart_upload_abort(const s3cKeys* keys,
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

static s3cReply* s3c_multipart_upload_init(const s3cKeys* keys,
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

static s3cReply* s3c_multipart_upload_finish(const s3cKeys* keys,
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

    StreamRead stream_rd = make_stream_rd_from_str_buf(&body);

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .query_args = &query_args,
        .stream_rd = &stream_rd,
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

static s3cReply* s3c_multipart_upload_run(const s3cKeys* keys,
                                          const char* bucket, const char* obj_key,
                                          FILE* fp, const char* upload_id,
                                          const s3cMultipartOpts* opts)
{
    uint8_t* chunk_buf = malloc(opts->part_size);
    s3cReply* reply = NULL;
    s3cKVL* etags_head = NULL;
    s3cKVL* etags_tail = NULL;
    StrBuf iota_buf = {0};

    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
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

    StreamRead stream_rd = {
        .fn_read = &fn_stream_read_mem,
        .ctx = {
            .opaque = chunk_buf,
        }
    };

    OpArgs op_args = {
        .bucket = bucket,
        .object_key = obj_key,
        .query_args = &q_arg_part_num,
        .stream_rd = &stream_rd,
    };

    int part_number = 0;

    while (left_to_send > 0) {
        size_t send_now = left_to_send > opts->part_size
            ? opts->part_size
            : left_to_send;

        size_t bytes_read = fread(chunk_buf, 1, send_now, fp);

        if (bytes_read < send_now) {
            reply = s3c_reply_alloc("failed to read file");
            goto cleanup_and_ret;
        }

        iota_buf.len = 0;
        str_push_int(&iota_buf, part_number + 1);
        q_arg_part_num.value = iota_buf.ptr;

        stream_rd.ctx.total_size = send_now;

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

            if (!server_err || num_retries >= opts->max_send_retries) {
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

s3cReply* s3c_put_object_from_file(const s3cKeys* keys,
                                   const char* bucket, const char* object_key,
                                   const char* file, const s3cKVL* headers)
{
    s3cReply* err = check_arg_bucket_key(bucket, object_key);

    if (err != NULL) {
        return err;
    }

    if ((err = check_arg_str(file, "file")) != NULL) {
        return err;
    }

    s3cReply* reply = NULL;

    FILE* fp = fopen(file, "r");

    if (fp == NULL) {
        reply = s3c_reply_alloc("failed to open file for read");
        goto cleanup_and_ret;
    }

    StrBuf read_buf = {0};

    BufferedFile bf = {
        .buf = &read_buf,
        .fp = fp,
    };

    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    StreamRead stream_rd = {
        .fn_read = &fn_stream_read_file,
        .ctx = {
            .total_size = file_size,
            .cursor = 0,
            .opaque = &bf,
        }
    };

    OpArgs args = {
        .bucket = bucket,
        .object_key = object_key,
        .headers = headers,
        .stream_rd = &stream_rd,
    };

    reply = run_s3_op(keys, "PUT", args);
    goto cleanup_and_ret;

cleanup_and_ret:
    if (fp != NULL) {
        fclose(fp);
    }

    str_destroy(&read_buf);

    return reply;
}

s3cReply* s3c_put_object_from_file_multipart(const s3cKeys* keys,
                                             const char* bucket, const char* object_key,
                                             const char* file,
                                             const s3cKVL* headers,
                                             const s3cMultipartOpts* opts)
{
    s3cMultipartOpts default_opts = {
        .part_size = 6 * 1024 * 1024,
        .max_send_retries = 2,
    };

    if (opts == NULL) {
        opts = &default_opts;
    }

    s3cReply* err = check_arg_bucket_key(bucket, object_key);

    if (err != NULL) {
        return err;
    }

    if ((err = check_arg_str(file, "file")) != NULL) {
        return err;
    }

    s3cReply* reply = NULL;
    StrBuf upload_id = {0};

    FILE* fp = fopen(file, "r");

    if (fp == NULL) {
        reply = s3c_reply_alloc("failed to open file for read");
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
        keys, bucket, object_key, fp, upload_id.ptr, opts
    );

    if (reply->error) {
        s3cReply* rep_abort = s3c_multipart_upload_abort(
            keys, bucket, object_key, upload_id.ptr
        );

        s3c_reply_free(rep_abort);
        goto cleanup_and_ret;
    }


cleanup_and_ret:
    if (fp != NULL) {
        fclose(fp);
    }
    str_destroy(&upload_id);

    return reply;
}

s3cReply* s3c_delete_object(const s3cKeys* keys, const char* bucket, const char* object_key)
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

s3cReply* s3c_create_bucket(const s3cKeys* keys, const char* bucket, const s3cKVL* headers)
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

    StreamRead stream_rd = make_stream_rd_from_str_buf(&req_body);

    OpArgs args = {
        .bucket = bucket,
        .headers = headers,
        .stream_rd = &stream_rd,
    };

    s3cReply* reply = run_s3_op(keys, "PUT", args);
    str_destroy(&req_body);

    return reply;
}

s3cReply* s3c_delete_bucket(const s3cKeys* keys, const char* bucket)
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

static void set_date_stamps(DateStamps* dates)
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

static StrBuf get_req_host(const s3cKeys* keys)
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

static void op_context_init(OpContext* op, OpArgs args, const s3cKeys* keys, s3cReply* reply)
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

static void op_context_free(OpContext* op)
{
    ossl_free(op->ossl_ctx);
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

static void append_s3_escaped_string(StrBuf* str_buf, const char* str)
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

static void op_run_request(OpContext* op, const char* html_verb)
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

static const char* ossl_init(OsslContext* octx)
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

static void ossl_free(OsslContext* octx)
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

static const char* ossl_proc_io_res(OsslContext* octx, int io_res)
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

    if (errno == ECONNRESET) {
        SSL_set_shutdown(octx->ssl, SSL_RECEIVED_SHUTDOWN);
        return "connection was reset by peer";
    }

    return  "unknown net error occured";
}

static BIO* create_socket_bio(const char *host, const char *proto)
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

static const char* ossl_connect(OsslContext* octx, const char* host)
{
    BIO* bio = create_socket_bio(host, "https");

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
        len_left -= line_len;
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

static const char* ossl_io_read(OsslContext* octx,
                                StrBuf* recv_buf, size_t max_bytes_to_read,
                                size_t* out_bytes_recv)
{
    *out_bytes_recv = 0;
    int io_res = 0;

    size_t min_cap = recv_buf->len + max_bytes_to_read + 1;
    size_t set_cap = str_set_cap(recv_buf, min_cap);

    if (set_cap < min_cap) {
        return "http reply allocation failed";
    }

    char* wptr = recv_buf->ptr + recv_buf->len;

    errno = 0;
    io_res = SSL_read_ex(
        octx->ssl, wptr, max_bytes_to_read,
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

    recv_buf->len += *out_bytes_recv;
    recv_buf->ptr[recv_buf->len] = '\0';

    return NULL;
}

static const char* ossl_io_write(OsslContext* octx, const char* data, size_t data_size)
{
    size_t bytes_sent = 0;
    int io_res = 0;

    errno = 0;
    io_res = SSL_write_ex(
        octx->ssl, data, data_size,
        &bytes_sent
    );

    const char* err = ossl_proc_io_res(octx, io_res);

    if (err) {
        return err;
    }

    if (bytes_sent < data_size) {
        return "SSL transmission error";
    }

    return NULL;
}

static int64_t parse_reply_content_length(s3cKVL* rep_headers)
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

static void op_read_reply(OpContext* op)
{
    const size_t RECV_CAP = 1024 * 1024;
    StrBuf recv_buf = {0};

    bool headers_parsed = false;
    unsigned http_resp_code = 0;
    bool http_resp_code_ok = false;
    int ssl_shtudown_state = 0;

    for (;;) {

        if (op->args.stream_wr != NULL && recv_buf.len > 0 && http_resp_code_ok) {

            const char* write_err = op->args.stream_wr->fn_write(
                recv_buf.ptr, recv_buf.len, &op->args.stream_wr->ctx
            );

            if (write_err != NULL) {
                op_set_error_fmt(op, "http reply recv failed: %s", write_err);
                goto cleanup_and_ret;
            }

            recv_buf.len = 0;
        }

        size_t bytes_recv = 0;

        const char* err = ossl_io_read(
            op->ossl_ctx,
            &recv_buf, RECV_CAP,
            &bytes_recv
        );

        if (err != NULL) {
            op_set_error_fmt(op, "failed to read http reply: %s", err);
            goto cleanup_and_ret;
        }

        if (bytes_recv == 0) {
            break;
        }

        if (headers_parsed) {
            continue;
        }

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
            recv_buf.ptr, block_len,
            &op->reply->headers,
            &http_resp_code
        );

        if (parse_err != NULL) {
            op_set_error(op, parse_err);
            goto cleanup_and_ret;
        }

        http_resp_code_ok = http_resp_code_is_ok(http_resp_code);

        assert(recv_buf.len >= (unsigned)block_len + 4);

        size_t to_copy = recv_buf.len - block_len - 4;

        memmove(recv_buf.ptr, recv_buf.ptr + block_len + 4, to_copy);
        recv_buf.len = to_copy;
        recv_buf.ptr[recv_buf.len] = '\0';

        headers_parsed = true;

        if (op->args.stream_wr != NULL) {
            int64_t rep_len = parse_reply_content_length(op->reply->headers);
            if (rep_len > 0) {
                op->args.stream_wr->ctx.total_size = rep_len;
            }
        }
    }

    op_proc_reply(op, &recv_buf, http_resp_code);

cleanup_and_ret:
    ssl_shtudown_state = SSL_get_shutdown(op->ossl_ctx->ssl);

    if (ssl_shtudown_state != SSL_RECEIVED_SHUTDOWN) {
        SSL_shutdown(op->ossl_ctx->ssl);
    }

    str_destroy(&recv_buf);
}

static void op_send_request(OpContext* op, StrBuf* rq_head)
{
    StrBuf endpoint = get_req_host(op->keys);

    const char* conn_err = ossl_connect(op->ossl_ctx, endpoint.ptr);

    if (conn_err) {
        op_set_error(op, conn_err);
        goto cleanup_and_ret;
    }

    const char* io_err = ossl_io_write(
        op->ossl_ctx, rq_head->ptr, rq_head->len
    );

    if (io_err != NULL) {
        op_set_error_fmt(op, "failed to send http request: %s", io_err);
        goto cleanup_and_ret;
    }

    if (op->args.stream_rd == NULL) {
        op_read_reply(op);
        goto cleanup_and_ret;
    }

    const size_t SEND_CHUNK_SZ = 1024 * 1024;

    while (1) {
        size_t bytes_to_send;
        const char* bytes_ptr;

        const char* io_err = op->args.stream_rd->fn_read(
            SEND_CHUNK_SZ, &op->args.stream_rd->ctx,
            &bytes_ptr, &bytes_to_send
        );

        if (io_err != NULL) {
            op_set_error_fmt(op, "failed to send http request: %s", io_err);
            goto cleanup_and_ret;
        }

        if (bytes_to_send < 1) {
            break;
        }

        io_err = ossl_io_write(
            op->ossl_ctx, bytes_ptr, bytes_to_send
        );

        if (io_err != NULL) {
            op_set_error_fmt(op, "failed to send http request: %s", io_err);
            goto cleanup_and_ret;
        }
    }

    op_read_reply(op);

cleanup_and_ret:
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
    char* ptr = cap > 0 ? calloc(1, cap + 1) : NULL;

    StrBuf res = {
        .ptr = ptr,
        .len = 0,
        .cap = cap
    };

    return res;
}

static void str_destroy(StrBuf* s)
{
    free(s->ptr);
    *s = str_init(0);
}

static char* str_extract(StrBuf* s)
{
    char* ret = s->ptr;
    *s = str_init(0);

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







