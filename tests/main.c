#define _POSIX_C_SOURCE 200809L

#include "../src/s3c.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

const char* TEST_BUCKET = "s3c-tests";
const char* TEST_BUCKET_CONFIG = "s3c-tests-config";
const char* LOCAL_OBJ_FILE = "tests/obj_file";

typedef struct {
    char*  buf;
    size_t len;
    size_t cap;
    bool   has_headers;
} TestCbBuf;

static const char* test_stream_cb(const char* bytes, uint64_t num_bytes,
                                   s3cKVL* headers, void* ctx)
{
    TestCbBuf* b = ctx;
    if (headers != NULL && s3c_kvl_find(headers, "content-type") != NULL) {
        b->has_headers = true;
    }
    if (b->len + num_bytes > b->cap) {
        return "buffer overflow";
    }
    memcpy(b->buf + b->len, bytes, num_bytes);
    b->len += num_bytes;
    return NULL;
}

static const char* test_stream_cb_abort(const char* bytes, uint64_t num_bytes,
                                         s3cKVL* headers, void* ctx)
{
    (void)bytes;
    (void)num_bytes;
    (void)headers;
    (void)ctx;
    return "aborted by user";
}


static struct timespec log_timer;
static bool log_timer_active = false;

static void log_flush_timer(void)
{
    if (!log_timer_active) return;
    log_timer_active = false;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double ms = (now.tv_sec - log_timer.tv_sec) * 1000.0
              + (now.tv_nsec - log_timer.tv_nsec) / 1e6;

    if (ms < 1000.0) {
        printf(" [%.0fms]", ms);
    } else {
        printf(" [%.1fs]", ms / 1000.0);
    }
}

void log_info(const char* fmt_str, ...)
{
    size_t len = strlen(fmt_str);
    bool ends_with_newline = len > 0 && fmt_str[len - 1] == '\n';

    if (ends_with_newline) {
        // print everything except the trailing \n
        char tmp[2048];
        va_list args;
        va_start(args, fmt_str);
        vsnprintf(tmp, sizeof(tmp), fmt_str, args);
        va_end(args);

        size_t tlen = strlen(tmp);
        if (tlen > 0 && tmp[tlen - 1] == '\n') {
            tmp[tlen - 1] = '\0';
        }
        printf("%s", tmp);
        log_flush_timer();
        printf("\n");
    } else {
        va_list args;
        va_start(args, fmt_str);
        vprintf(fmt_str, args);
        va_end(args);
    }

    // start timer for lines ending with "..."
    if (len >= 3 && fmt_str[len - 1] == '.' && fmt_str[len - 2] == '.' && fmt_str[len - 3] == '.') {
        clock_gettime(CLOCK_MONOTONIC, &log_timer);
        log_timer_active = true;
    }

    fflush(stdout);
}

void log_err(const char* fmt_str, ...)
{
    printf("\033[31m");

    va_list args;
    va_start(args, fmt_str);

    vprintf(fmt_str, args);

    va_end(args);

    printf("\033[0m");
    fflush(stdout);
}

void read_file(const char* filename, char** out_filebuf, size_t* out_file_size)

{
    FILE* fp = fopen(filename, "r");

    if (fp == NULL) {
        *out_filebuf = NULL;
        *out_file_size = 0;
        return;
    }

    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* filebuf = calloc(file_size + 1, 1);
    *out_filebuf = filebuf;

    size_t read_res = fread(filebuf, 1, file_size, fp);

    if (read_res < 1) {
        *out_file_size = 0;
    } else {
        *out_file_size = file_size;
    }

    fclose(fp);
}

const char* read_s3c_keys_file(const char* filename, s3cKeys* keys)
{
    const char* err = NULL;

    char* filebuf = NULL;
    size_t file_size;

    read_file(filename, &filebuf, &file_size);

    if (file_size < 1) {
        err = "failed to read s3c keys file";
        goto cleanup_and_ret;
    }

    unsigned rc = 0, wc = 0;
    while (rc < file_size) {
        int c = filebuf[rc];
        if (!isspace(c) || c == '\n') {
            filebuf[wc] = c;
            wc += 1;
        }
        rc += 1;
    }
    filebuf[wc] = '\0';

    char* ts_line, *ts_kv;
    char* line = strtok_r(filebuf, "\n", &ts_line);

    while (line) {

        char* key = strtok_r(line, "=", &ts_kv);
        char* value = strtok_r(NULL, "=", &ts_kv);

        if (key == NULL || (strcmp(key, "endpoint") != 0 && value == NULL)) {
            err = "failed to parse s3c keys file, invalid format";
            goto cleanup_and_ret;
        }

        if (strcmp(key, "access_key_id") == 0) {
            keys->access_key_id = strdup(value);

        } else if (strcmp(key, "access_key_secret") == 0) {
            keys->access_key_secret = strdup(value);

        } else if (strcmp(key, "region") == 0) {
            keys->region = strdup(value);

        } else if (strcmp(key, "endpoint") == 0 && value != NULL) {
            keys->endpoint = strdup(value);
        }

        line = strtok_r(NULL, "\n", &ts_line);
    }

    if (keys->access_key_id == NULL || keys->access_key_secret == NULL ||
        keys->region == NULL) {

        err = "missing required fields in s3c_keys file";
    }

cleanup_and_ret:
    free(filebuf);

    return err;
}

bool expect_error_reply(const char* test_name, s3cReply* reply, const char* error_substr)
{
    bool ok = true;

    if (reply == NULL) {
        log_err("error: %s - reply is NULL\n", test_name);
        return false;
    }

    if (reply->error == NULL) {
        log_err("error: %s - expected reply->error\n", test_name);
        ok = false;
        goto cleanup_and_ret;
    }

    if (error_substr != NULL && strstr(reply->error, error_substr) == NULL) {
        log_err("error: %s - reply error '%s' missing expected token '%s'\n",
                test_name, reply->error, error_substr);
        ok = false;
    }

cleanup_and_ret:
    s3c_reply_free(reply);
    return ok;
}

bool test_config_api(void)
{
    bool ok = true;

    if (!s3c_set_global_config(S3C_CONF_NET_IO_TIMEOUT_SEC, 3)) {
        log_err("error: failed to set net timeout config\n");
        ok = false;
    }

    if (!s3c_set_global_config(S3C_CONF_MAX_REPLY_PREALLOC_SIZE_MB, 4)) {
        log_err("error: failed to set max reply prealloc config\n");
        ok = false;
    }

    if (s3c_set_global_config(999, 1)) {
        log_err("error: expected unknown config id set to fail\n");
        ok = false;
    }

    // reset to defaults for integration tests
    s3c_set_global_config(S3C_CONF_NET_IO_TIMEOUT_SEC, 15);
    s3c_set_global_config(S3C_CONF_MAX_REPLY_PREALLOC_SIZE_MB, 128);

    return ok;
}

bool test_kvl_helpers(void)
{
    bool ok = true;
    s3cKVL* headers = NULL;

    s3c_kvl_ins(&headers, "z-key", "a");
    s3c_kvl_ins(&headers, "A-Key", "b");
    s3c_kvl_ins(&headers, "a-key", "c");
    s3c_kvl_ins_int(&headers, "x-int", 42);

    if (headers == NULL || strcmp(headers->key, "A-Key") != 0) {
        log_err("error: kvl insert ordering failed\n");
        ok = false;
    }

    s3cKVL* a_key = s3c_kvl_find(headers, "a-key");
    if (a_key == NULL || strcmp(a_key->value, "b, c") != 0) {
        log_err("error: kvl duplicate merge failed\n");
        ok = false;
    }

    s3cKVL* x_int = s3c_kvl_find(headers, "X-INT");
    if (x_int == NULL || strcmp(x_int->value, "42") != 0) {
        log_err("error: kvl integer insert/find failed\n");
        ok = false;
    }

    s3c_kvl_remove(&headers, "A-KEY");
    if (s3c_kvl_find(headers, "a-key") != NULL) {
        log_err("error: kvl remove failed\n");
        ok = false;
    }

    s3c_kvl_free(headers);
    return ok;
}

bool test_client_constructor_validation(void)
{
    bool ok = true;
    s3cReply* err = NULL;
    s3cClient* client = NULL;

    s3cKeys valid_keys = {
        .access_key_id = "dummy-key-id",
        .access_key_secret = "dummy-key-secret",
        .region = "eu-central-1",
        .endpoint = NULL,
    };

    client = s3c_client_new(&valid_keys, NULL, &err);
    if (client == NULL || err != NULL) {
        log_err("error: expected valid client constructor to succeed\n");
        ok = false;
    }
    s3c_client_free(client);
    s3c_reply_free(err);
    client = NULL;
    err = NULL;

    client = s3c_client_new(NULL, NULL, &err);
    if (client != NULL || err == NULL || strstr(err->error, "<keys>") == NULL) {
        log_err("error: expected NULL keys constructor to fail\n");
        ok = false;
    }
    s3c_client_free(client);
    s3c_reply_free(err);
    client = NULL;
    err = NULL;

    s3cKeys no_id = valid_keys;
    no_id.access_key_id = "";

    client = s3c_client_new(&no_id, NULL, &err);
    if (client != NULL || err == NULL || strstr(err->error, "access key ID") == NULL) {
        log_err("error: expected missing access key ID constructor to fail\n");
        ok = false;
    }
    s3c_client_free(client);
    s3c_reply_free(err);
    client = NULL;
    err = NULL;

    s3cKeys no_secret = valid_keys;
    no_secret.access_key_secret = "";

    client = s3c_client_new(&no_secret, NULL, &err);
    if (client != NULL || err == NULL || strstr(err->error, "access key secret") == NULL) {
        log_err("error: expected missing access key secret constructor to fail\n");
        ok = false;
    }
    s3c_client_free(client);
    s3c_reply_free(err);
    client = NULL;
    err = NULL;

    s3cKeys no_region = valid_keys;
    no_region.region = "";

    client = s3c_client_new(&no_region, NULL, &err);
    if (client != NULL || err == NULL || strstr(err->error, "no region") == NULL) {
        log_err("error: expected missing region constructor to fail\n");
        ok = false;
    }
    s3c_client_free(client);
    s3c_reply_free(err);
    client = NULL;
    err = NULL;

    s3cKeys bad_endpoint = valid_keys;
    bad_endpoint.endpoint = "https://";

    client = s3c_client_new(&bad_endpoint, NULL, &err);
    if (client != NULL || err == NULL || strstr(err->error, "endpoint") == NULL) {
        log_err("error: expected invalid endpoint constructor to fail\n");
        ok = false;
    }
    s3c_client_free(client);
    s3c_reply_free(err);
    client = NULL;
    err = NULL;

    if (s3c_client_new(NULL, NULL, NULL) != NULL) {
        log_err("error: expected constructor NULL keys to fail when out_err is NULL\n");
        ok = false;
    }

    return ok;
}

bool test_api_argument_validation(void)
{
    bool ok = true;
    s3cReply* err = NULL;
    s3cClient* client = NULL;

    s3cKeys keys = {
        .access_key_id = "dummy-key-id",
        .access_key_secret = "dummy-key-secret",
        .region = "eu-central-1",
        .endpoint = NULL,
    };

    client = s3c_client_new(&keys, NULL, &err);
    if (client == NULL || err != NULL) {
        log_err("error: failed to initialize client for argument validation tests\n");
        s3c_client_free(client);
        s3c_reply_free(err);
        return false;
    }

    uint8_t payload = 1;

    ok = expect_error_reply("get_object null client",
            s3c_get_object(NULL, "b", "k"), "<client>") && ok;
    ok = expect_error_reply("get_object null bucket",
            s3c_get_object(client, NULL, "k"), "<bucket>") && ok;
    ok = expect_error_reply("get_object null object_key",
            s3c_get_object(client, "b", NULL), "<object_key>") && ok;

    ok = expect_error_reply("get_object_to_file null file",
            s3c_get_object_to_file(client, "b", "k", NULL), "<file>") && ok;
    ok = expect_error_reply("get_object_cb null client",
            s3c_get_object_stream(NULL, "b", "k", NULL, (s3cStreamCb)1, NULL), "<client>") && ok;
    ok = expect_error_reply("get_object_cb null bucket",
            s3c_get_object_stream(client, NULL, "k", NULL, (s3cStreamCb)1, NULL), "<bucket>") && ok;
    ok = expect_error_reply("get_object_cb null cb",
            s3c_get_object_stream(client, "b", "k", NULL, NULL, NULL), "<cb>") && ok;
    ok = expect_error_reply("put_object null data",
            s3c_put_object(client, "b", "k", NULL, 1, NULL), "<data>") && ok;
    ok = expect_error_reply("put_object zero size",
            s3c_put_object(client, "b", "k", &payload, 0, NULL), "<data_size>") && ok;

    ok = expect_error_reply("put_object_from_file null file",
            s3c_put_object_from_file(client, "b", "k", NULL, NULL), "<file>") && ok;
    ok = expect_error_reply("put_object_from_file_multipart null file",
            s3c_put_object_from_file_multipart(client, "b", "k", NULL, NULL, NULL), "<file>") && ok;

    ok = expect_error_reply("head_object null client",
            s3c_head_object(NULL, "b", "k"), "<client>") && ok;
    ok = expect_error_reply("head_object null bucket",
            s3c_head_object(client, NULL, "k"), "<bucket>") && ok;
    ok = expect_error_reply("head_object null object_key",
            s3c_head_object(client, "b", NULL), "<object_key>") && ok;

    ok = expect_error_reply("copy_object null client",
            s3c_copy_object(NULL, "b", "k", "b", "k"), "<client>") && ok;
    ok = expect_error_reply("copy_object null src_bucket",
            s3c_copy_object(client, NULL, "k", "b", "k"), "<src_bucket>") && ok;
    ok = expect_error_reply("copy_object null src_key",
            s3c_copy_object(client, "b", NULL, "b", "k"), "<src_key>") && ok;
    ok = expect_error_reply("copy_object null dst_bucket",
            s3c_copy_object(client, "b", "k", NULL, "k"), "<bucket>") && ok;
    ok = expect_error_reply("copy_object null dst_key",
            s3c_copy_object(client, "b", "k", "b", NULL), "<object_key>") && ok;

    ok = expect_error_reply("delete_object null bucket",
            s3c_delete_object(client, NULL, "k"), "<bucket>") && ok;
    ok = expect_error_reply("create_bucket null bucket",
            s3c_create_bucket(client, NULL, NULL), "<bucket>") && ok;
    ok = expect_error_reply("delete_bucket null bucket",
            s3c_delete_bucket(client, NULL), "<bucket>") && ok;

    ok = expect_error_reply("get_bucket_config null client",
            s3c_get_bucket_config(NULL, "b", "lifecycle"), "<client>") && ok;
    ok = expect_error_reply("get_bucket_config null bucket",
            s3c_get_bucket_config(client, NULL, "lifecycle"), "<bucket>") && ok;
    ok = expect_error_reply("get_bucket_config null config_name",
            s3c_get_bucket_config(client, "b", NULL), "<config_name>") && ok;

    ok = expect_error_reply("set_bucket_config null client",
            s3c_set_bucket_config(NULL, "b", "lifecycle", "<xml/>"), "<client>") && ok;
    ok = expect_error_reply("set_bucket_config null bucket",
            s3c_set_bucket_config(client, NULL, "lifecycle", "<xml/>"), "<bucket>") && ok;
    ok = expect_error_reply("set_bucket_config null config_name",
            s3c_set_bucket_config(client, "b", NULL, "<xml/>"), "<config_name>") && ok;
    ok = expect_error_reply("set_bucket_config null body",
            s3c_set_bucket_config(client, "b", "lifecycle", NULL), "<body>") && ok;

    ok = expect_error_reply("list_objects null client",
            s3c_list_objects(NULL, "b", NULL), "<client>") && ok;
    ok = expect_error_reply("list_objects null bucket",
            s3c_list_objects(client, NULL, NULL), "<bucket>") && ok;

    ok = expect_error_reply("presigned_url null client",
            s3c_generate_presigned_url(NULL, "b", "k", "GET", 3600), "<client>") && ok;
    ok = expect_error_reply("presigned_url null bucket",
            s3c_generate_presigned_url(client, NULL, "k", "GET", 3600), "<bucket>") && ok;
    ok = expect_error_reply("presigned_url null key",
            s3c_generate_presigned_url(client, "b", NULL, "GET", 3600), "<object_key>") && ok;
    ok = expect_error_reply("presigned_url null method",
            s3c_generate_presigned_url(client, "b", "k", NULL, 3600), "<method>") && ok;
    ok = expect_error_reply("presigned_url zero expires",
            s3c_generate_presigned_url(client, "b", "k", "GET", 0), "<expires_sec>") && ok;
    ok = expect_error_reply("presigned_url expires too large",
            s3c_generate_presigned_url(client, "b", "k", "GET", 604801), "<expires_sec>") && ok;

    s3cMultipart* mp_dummy = NULL;
    ok = expect_error_reply("multipart_init null client",
            s3c_multipart_init(NULL, "b", "k", NULL, NULL, &mp_dummy), "<client>") && ok;
    ok = expect_error_reply("multipart_init null bucket",
            s3c_multipart_init(client, NULL, "k", NULL, NULL, &mp_dummy), "<bucket>") && ok;

    uint8_t mp_byte = 1;
    ok = expect_error_reply("multipart_upload_part null mp",
            s3c_multipart_upload_part(NULL, &mp_byte, 1), "<multipart>") && ok;
    ok = expect_error_reply("multipart_upload_part null data",
            s3c_multipart_upload_part((s3cMultipart*)&mp_byte, NULL, 1), "<data>") && ok;

    ok = expect_error_reply("multipart_complete null mp",
            s3c_multipart_complete(NULL), "<multipart>") && ok;
    ok = expect_error_reply("multipart_abort null mp",
            s3c_multipart_abort(NULL), "<multipart>") && ok;

    s3c_client_free(client);
    return ok;
}

bool test_unreachable_endpoint(void)
{
    bool ok = true;

    log_info("unreachable endpoint tests...\n");

    s3cKeys keys = {
        .access_key_id     = "test_key",
        .access_key_secret = "test_secret",
        .region            = "us-east-1",
        .endpoint          = "https://bogus.invalid.endpoint.test",
    };

    s3cReply* err = NULL;
    s3cClient* client = s3c_client_new(&keys, NULL, &err);

    if (client == NULL) {
        log_err("error: client_new failed for unreachable endpoint: %s\n",
                err ? err->error : "unknown");
        s3c_reply_free(err);
        return false;
    }

    uint8_t data[] = "test";

    ok = expect_error_reply("put_object unreachable",
            s3c_put_object(client, "bucket", "key", data, sizeof(data), NULL),
            NULL) && ok;

    ok = expect_error_reply("get_object unreachable",
            s3c_get_object(client, "bucket", "key"),
            NULL) && ok;

    ok = expect_error_reply("head_object unreachable",
            s3c_head_object(client, "bucket", "key"),
            NULL) && ok;

    ok = expect_error_reply("list_objects unreachable",
            s3c_list_objects(client, "bucket", NULL),
            NULL) && ok;

    ok = expect_error_reply("delete_object unreachable",
            s3c_delete_object(client, "bucket", "key"),
            NULL) && ok;

    s3c_client_free(client);
    return ok;
}

typedef struct {
    s3cKeys  keys;
    int      thread_id;
    bool     ok;
} ThreadTestArg;

static void* thread_unreachable_worker(void* arg)
{
    ThreadTestArg* ta = arg;
    ta->ok = true;

    s3cReply* err = NULL;
    s3cClient* client = s3c_client_new(&ta->keys, NULL, &err);

    if (client == NULL) {
        ta->ok = false;
        s3c_reply_free(err);
        return NULL;
    }

    uint8_t data[] = "test";

    s3cReply* reply = s3c_put_object(client, "bucket", "key", data, sizeof(data), NULL);
    if (reply == NULL || reply->error == NULL) {
        ta->ok = false;
    }
    s3c_reply_free(reply);

    reply = s3c_get_object(client, "bucket", "key");
    if (reply == NULL || reply->error == NULL) {
        ta->ok = false;
    }
    s3c_reply_free(reply);

    reply = s3c_list_objects(client, "bucket", NULL);
    if (reply == NULL || reply->error == NULL) {
        ta->ok = false;
    }
    s3c_reply_free(reply);

    s3c_client_free(client);
    return NULL;
}

bool test_unreachable_endpoint_threaded(void)
{
    log_info("unreachable endpoint threaded (20 threads)...\n");

    const int N = 20;
    pthread_t threads[N];
    ThreadTestArg args[N];

    for (int i = 0; i < N; i++) {
        args[i].keys = (s3cKeys){
            .access_key_id     = "test_key",
            .access_key_secret = "test_secret",
            .region            = "us-east-1",
            .endpoint          = "https://bogus.invalid.endpoint.test",
        };
        args[i].thread_id = i;
        args[i].ok = false;

        pthread_create(&threads[i], NULL, thread_unreachable_worker, &args[i]);
    }

    bool ok = true;
    for (int i = 0; i < N; i++) {
        pthread_join(threads[i], NULL);
        if (!args[i].ok) {
            log_err("error: thread %d failed\n", i);
            ok = false;
        }
    }

    return ok;
}

typedef struct {
    s3cKeys* keys;
    const char* bucket;
    int thread_id;
    bool ok;
} ThreadRemoteArg;

static void* thread_put_delete_worker(void* arg)
{
    ThreadRemoteArg* ta = arg;
    ta->ok = false;

    s3cReply* err = NULL;
    s3cClient* client = s3c_client_new(ta->keys, NULL, &err);

    if (client == NULL) {
        s3c_reply_free(err);
        return NULL;
    }

    char key[128];
    snprintf(key, sizeof(key), "_s3c_test/thread_%d_%ld", ta->thread_id, (long)time(NULL));

    uint8_t data[64];
    memset(data, (uint8_t)ta->thread_id, sizeof(data));

    s3cReply* reply = s3c_put_object(client, ta->bucket, key, data, sizeof(data), NULL);
    if (reply->error != NULL) {
        s3c_reply_free(reply);
        s3c_client_free(client);
        return NULL;
    }
    s3c_reply_free(reply);

    reply = s3c_get_object(client, ta->bucket, key);
    if (reply->error != NULL || reply->data_size != sizeof(data)) {
        s3c_reply_free(reply);
        s3c_client_free(client);
        return NULL;
    }
    s3c_reply_free(reply);

    reply = s3c_delete_object(client, ta->bucket, key);
    if (reply->error != NULL) {
        s3c_reply_free(reply);
        s3c_client_free(client);
        return NULL;
    }
    s3c_reply_free(reply);

    s3c_client_free(client);
    ta->ok = true;
    return NULL;
}

bool test_threaded_put_delete(s3cKeys* keys)
{
    const int N = 20;

    log_info("threaded put/get/delete (%d threads)...", N);

    pthread_t threads[N];
    ThreadRemoteArg args[N];

    for (int i = 0; i < N; i++) {
        args[i].keys = keys;
        args[i].bucket = TEST_BUCKET;
        args[i].thread_id = i;
        args[i].ok = false;
        pthread_create(&threads[i], NULL, thread_put_delete_worker, &args[i]);
    }

    bool ok = true;
    for (int i = 0; i < N; i++) {
        pthread_join(threads[i], NULL);
        if (!args[i].ok) {
            log_err("error: thread %d failed\n", i);
            ok = false;
        }
    }

    if (ok) {
        log_info("ok\n");
    }

    return ok;
}

static void* thread_put_nonexistent_worker(void* arg)
{
    ThreadRemoteArg* ta = arg;
    ta->ok = false;

    s3cReply* err = NULL;
    s3cClient* client = s3c_client_new(ta->keys, NULL, &err);

    if (client == NULL) {
        s3c_reply_free(err);
        return NULL;
    }

    uint8_t data[] = "fail";

    s3cReply* reply = s3c_put_object(client, "nonexistent-bucket-s3c-test-999",
                                      "key", data, sizeof(data), NULL);
    if (reply == NULL) {
        s3c_client_free(client);
        return NULL;
    }

    if (reply->error != NULL) {
        ta->ok = true;  // expected to fail
    }

    s3c_reply_free(reply);
    s3c_client_free(client);
    return NULL;
}

bool test_threaded_put_nonexistent_bucket(s3cKeys* keys)
{
    const int N = 20;

    log_info("threaded put nonexistent bucket (%d threads)...", N);

    pthread_t threads[N];
    ThreadRemoteArg args[N];

    for (int i = 0; i < N; i++) {
        args[i].keys = keys;
        args[i].bucket = NULL;
        args[i].thread_id = i;
        args[i].ok = false;
        pthread_create(&threads[i], NULL, thread_put_nonexistent_worker, &args[i]);
    }

    bool ok = true;
    for (int i = 0; i < N; i++) {
        pthread_join(threads[i], NULL);
        if (!args[i].ok) {
            log_err("error: thread %d did not get expected error\n", i);
            ok = false;
        }
    }

    if (ok) {
        log_info("ok\n");
    }

    return ok;
}

bool run_local_tests(void)
{
    bool ok = true;

    log_info("running local validation tests...\n");

    ok = test_config_api() && ok;
    ok = test_kvl_helpers() && ok;
    ok = test_client_constructor_validation() && ok;
    ok = test_api_argument_validation() && ok;
    ok = test_unreachable_endpoint() && ok;
    ok = test_unreachable_endpoint_threaded() && ok;

    if (ok) {
        log_info("local validation tests passed\n");
    } else {
        log_err("local validation tests failed\n");
    }

    return ok;
}



bool fetch_and_compare_file(s3cClient* client,
                            const char* obj_key,
                            const char* source, size_t source_sz,
                            const char* source_ct)
{
    bool ok = false;
    char* fetched_bytes = NULL;

    remove(LOCAL_OBJ_FILE);

    s3cReply* reply = s3c_get_object_to_file(
        client, TEST_BUCKET, obj_key, LOCAL_OBJ_FILE
    );

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    size_t fetched_bytes_sz = 0;
    read_file(LOCAL_OBJ_FILE, &fetched_bytes, &fetched_bytes_sz);

    if (fetched_bytes == NULL) {
        log_err("error: failed to read file %s\n",
            LOCAL_OBJ_FILE
        );
    }

    if (fetched_bytes_sz != source_sz) {
        log_err("error: source size [%zu] does not match fetched file size [%zu]\n",
            source_sz, fetched_bytes_sz
        );
        goto cleanup_and_ret;
    }

    if (memcmp(source, fetched_bytes, source_sz) != 0) {
        log_err("error: source / fetched file content do not match\n");
        goto cleanup_and_ret;
    }

    if (source_ct != NULL) {

        s3cKVL* fetched_bytes_ct_header = s3c_kvl_find(reply->headers, "content-type");

        if (fetched_bytes_ct_header == NULL) {
            log_err("error: fetched file has no content type header\n");
            goto cleanup_and_ret;
        }

        if (strcmp(fetched_bytes_ct_header->value, source_ct)) {
            log_err("error: fetched file has wrong content header\n");
            goto cleanup_and_ret;
        }
    }

    ok = true;

cleanup_and_ret:
    s3c_reply_free(reply);
    free(fetched_bytes);

    return ok;
}

bool test_big_object(s3cClient* client)
{
    size_t rt_data_size = 1024 * 1024 * 15;
    const char* object_key = "big-file";
    const char* rt_content_type = "application/binary";
    char* filebuf = NULL;

    s3cKVL ct_header = {
        .key = "content-type",
        .value = (char*)rt_content_type,
        .next = NULL
    };

    bool all_good = false;
    char* rt_data = calloc(rt_data_size, 1);

    for (unsigned i = 0; i < rt_data_size; i++) {
        rt_data[i] = i % 256;
    }

    log_info("put big object...");

    s3cReply* reply = s3c_put_object(
        client, TEST_BUCKET, object_key,
        (const uint8_t*)rt_data, rt_data_size, &ct_header
    );

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    s3c_reply_free(reply);
    log_info("get big object...");

    reply = s3c_get_object(client, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->data_size != rt_data_size ||
        memcmp(rt_data, reply->data, reply->data_size) != 0) {
        log_err(
            "error: reply payload did not match original payload, sizes [%zu] / [%zu]\n",
            reply->data_size, rt_data_size
        );
        goto cleanup_and_ret;
    }

    log_info("ok\n");

    log_info("get big object to file...");

    bool fetch_cmp_ok = fetch_and_compare_file(
        client, object_key,
        rt_data, rt_data_size,
        rt_content_type
    );

    if (!fetch_cmp_ok) {
        goto cleanup_and_ret;
    };

    log_info("ok\n");

    log_info("put big object from file...");

    s3c_reply_free(reply);

    reply = s3c_put_object_from_file(
        client, TEST_BUCKET, object_key, LOCAL_OBJ_FILE, &ct_header
    );

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("fetch and compare big object...");
    fetch_cmp_ok = fetch_and_compare_file(
        client, object_key,
        rt_data, rt_data_size,
        rt_content_type
    );

    if (!fetch_cmp_ok) {
        goto cleanup_and_ret;
    };

    log_info("ok\n");

    log_info("put big object from file multipart...");

    s3c_reply_free(reply);

    reply = s3c_put_object_from_file_multipart(
        client, TEST_BUCKET, object_key, LOCAL_OBJ_FILE,
        &ct_header, NULL
    );

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("fetch and compare big object after multipart...");

    fetch_cmp_ok = fetch_and_compare_file(
        client, object_key,
        rt_data, rt_data_size,
        rt_content_type
    );

    if (!fetch_cmp_ok) {
        goto cleanup_and_ret;
    };

    log_info("ok\n");

    log_info("get object stream abort (15MB)...");
    s3c_reply_free(reply);

    reply = s3c_get_object_stream(client, TEST_BUCKET, object_key,
                                   NULL, test_stream_cb_abort, NULL);

    if (reply->error == NULL) {
        log_err("error: expected error from aborted callback\n");
        goto cleanup_and_ret;
    }

    if (strstr(reply->error, "aborted by user") == NULL) {
        log_err("error: expected 'aborted by user' in error, got: %s\n",
                reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok\n");

    log_info("get object stream with range header...");
    s3c_reply_free(reply);

    char range_data[100];
    TestCbBuf range_buf = { .buf = range_data, .len = 0, .cap = 100 };
    s3cKVL* range_headers = NULL;
    s3c_kvl_ins(&range_headers, "Range", "bytes=0-99");

    reply = s3c_get_object_stream(client, TEST_BUCKET, object_key,
                                   range_headers, test_stream_cb, &range_buf);

    s3c_kvl_free(range_headers);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->http_resp_code != 206) {
        log_err("error: expected 206, got %d\n", (int)reply->http_resp_code);
        goto cleanup_and_ret;
    }

    if (range_buf.len != 100) {
        log_err("error: expected 100 bytes, got %" PRIu64 "\n",
                (uint64_t)range_buf.len);
        goto cleanup_and_ret;
    }

    if (memcmp(range_buf.buf, rt_data, 100) != 0) {
        log_err("error: range data mismatch\n");
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    all_good = true;

cleanup_and_ret:
    s3c_reply_free(reply);
    reply = s3c_delete_object(client, TEST_BUCKET, object_key);
    s3c_reply_free(reply);

    free(rt_data);
    free(filebuf);

    remove(LOCAL_OBJ_FILE);

    return all_good;
}

bool test_multipart_api(s3cClient* client)
{
    bool all_good = false;
    s3cReply* reply = NULL;
    s3cMultipart* mp = NULL;

    const char* object_key = "mp-test/file.bin";

    // S3 minimum part size is 5MB (except last part)
    size_t min_part_size = 1024 * 1024 * 5;
    size_t input_chunk_size = 1024 * 1024; // intentionally < 5MB to test accumulation
    size_t total_size = min_part_size * 2 + 1024; // 2 full parts + small last part

    char* data = calloc(total_size, 1);
    for (size_t i = 0; i < total_size; i++) {
        data[i] = (char)(i % 251);
    }

    log_info("multipart api: init...");

    reply = s3c_multipart_init(client, TEST_BUCKET, object_key, NULL, NULL, &mp);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (mp == NULL) {
        log_err("error: multipart context is NULL\n");
        goto cleanup_and_ret;
    }

    s3c_reply_free(reply);
    reply = NULL;

    log_info("ok\n");

    log_info("multipart api: upload parts...");

    size_t offset = 0;
    uint64_t call_num = 1;

    while (offset < total_size) {
        size_t chunk = total_size - offset;
        if (chunk > input_chunk_size) {
            chunk = input_chunk_size;
        }

        reply = s3c_multipart_upload_part(mp, (const uint8_t*)data + offset, chunk);

        if (reply->error != NULL) {
            log_err("error: upload call %" PRIu64 ": %s\n", call_num, reply->error);
            goto cleanup_and_ret;
        }

        s3c_reply_free(reply);
        reply = NULL;

        offset += chunk;
        call_num++;
    }

    log_info("ok (%d calls)\n", (int)(call_num - 1));

    log_info("multipart api: complete...");

    reply = s3c_multipart_complete(mp);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    s3c_reply_free(reply);
    reply = NULL;

    log_info("ok\n");

    log_info("multipart api: verify...");

    reply = s3c_get_object(client, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->data_size != total_size ||
        memcmp(data, reply->data, total_size) != 0) {
        log_err("error: multipart uploaded content does not match, "
                "sizes [%zu] / [%zu]\n",
                (size_t)reply->data_size, total_size);
        goto cleanup_and_ret;
    }

    log_info("ok\n");

    s3c_reply_free(reply);
    reply = NULL;
    s3c_multipart_free(mp);
    mp = NULL;

    // test abort: init a new upload, send one part, then abort
    log_info("multipart api: abort...");

    const char* abort_key = "mp-test/abort.bin";

    reply = s3c_multipart_init(client, TEST_BUCKET, abort_key, NULL, NULL, &mp);

    if (reply->error != NULL) {
        log_err("error: abort init: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    s3c_reply_free(reply);

    reply = s3c_multipart_upload_part(mp, (const uint8_t*)data, min_part_size);

    if (reply->error != NULL) {
        log_err("error: abort upload part: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    s3c_reply_free(reply);

    reply = s3c_multipart_abort(mp);

    if (reply->error != NULL) {
        log_err("error: abort: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    s3c_reply_free(reply);
    reply = NULL;

    // verify the object doesn't exist after abort
    reply = s3c_head_object(client, TEST_BUCKET, abort_key);

    if (reply->error == NULL) {
        log_err("error: expected object to not exist after abort\n");
        goto cleanup_and_ret;
    }

    log_info("ok\n");

    all_good = true;

cleanup_and_ret:
    s3c_reply_free(reply);
    s3c_multipart_free(mp);

    s3cReply* del = s3c_delete_object(client, TEST_BUCKET, object_key);
    s3c_reply_free(del);

    free(data);

    return all_good;
}

bool test_list_abort_multipart(s3cClient* client)
{
    bool all_good = false;
    s3cReply* reply = NULL;
    s3cMultipart* mp = NULL;
    char* found_upload_id = NULL;

    const char* object_key = "mp-list-test/pending.bin";

    // start a multipart upload but don't complete it
    log_info("list/abort mp: init...");

    reply = s3c_multipart_init(client, TEST_BUCKET, object_key, NULL, NULL, &mp);

    if (reply->error != NULL) {
        log_err("error: init: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    s3c_reply_free(reply);
    reply = NULL;

    log_info("ok\n");

    // list multipart uploads — our pending upload should appear
    log_info("list/abort mp: list uploads...");

    reply = s3c_list_multipart_uploads(client, TEST_BUCKET);

    if (reply->error != NULL) {
        log_err("error: list: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->result_kind != S3C_RESULT_UPLOADS) {
        log_err("error: expected result_kind UPLOADS, got %d\n", reply->result_kind);
        goto cleanup_and_ret;
    }

    {
        bool found = false;

        for (s3cMpEntry* e = reply->result.uploads.entries; e != NULL; e = e->next) {
            if (e->key != NULL && strcmp(e->key, object_key) == 0) {
                found = true;
                found_upload_id = strdup(e->upload_id);
                break;
            }
        }

        s3c_reply_free(reply);
        reply = NULL;

        if (!found || found_upload_id == NULL) {
            log_err("error: pending upload not found in list\n");
            goto cleanup_and_ret;
        }

        log_info("ok (found upload_id=%.40s...)\n", found_upload_id);

        // abort via the public s3c_abort_multipart_upload
        log_info("list/abort mp: abort upload...");

        reply = s3c_abort_multipart_upload(client, TEST_BUCKET, object_key,
                                            found_upload_id);

        if (reply->error != NULL) {
            log_err("error: abort: %s\n", reply->error);
            goto cleanup_and_ret;
        }
    }

    s3c_reply_free(reply);
    reply = NULL;

    log_info("ok\n");

    // verify the specific upload no longer appears in the list
    log_info("list/abort mp: verify cleanup...");

    reply = s3c_list_multipart_uploads(client, TEST_BUCKET);

    if (reply->error != NULL) {
        log_err("error: list after abort: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    {
        bool still_there = false;

        for (s3cMpEntry* e = reply->result.uploads.entries; e != NULL; e = e->next) {
            if (e->upload_id != NULL && strcmp(e->upload_id, found_upload_id) == 0) {
                still_there = true;
                break;
            }
        }

        if (still_there) {
            log_err("error: aborted upload still present in list\n");
            goto cleanup_and_ret;
        }
    }

    log_info("ok\n");

    all_good = true;

cleanup_and_ret:
    free(found_upload_id);
    s3c_reply_free(reply);
    s3c_multipart_free(mp);

    return all_good;
}

bool test_bucket_config(s3cClient* client)
{
    bool all_good = false;
    s3cReply* reply = NULL;

    // set a valid lifecycle config
    log_info("bucket config: set lifecycle...");

    const char* lifecycle_xml =
        "<LifecycleConfiguration>"
        "<Rule>"
        "<ID>test-rule</ID>"
        "<Status>Enabled</Status>"
        "<Filter><Prefix>tmp/</Prefix></Filter>"
        "<Expiration><Days>1</Days></Expiration>"
        "</Rule>"
        "</LifecycleConfiguration>";

    reply = s3c_set_bucket_config(client, TEST_BUCKET_CONFIG, "lifecycle", lifecycle_xml);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);
    s3c_reply_free(reply);
    reply = NULL;

    // get the lifecycle config back
    log_info("bucket config: get lifecycle...");

    reply = s3c_get_bucket_config(client, TEST_BUCKET_CONFIG, "lifecycle");

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->data == NULL || reply->data_size == 0) {
        log_err("error: empty lifecycle config response\n");
        goto cleanup_and_ret;
    }

    if (strstr((char*)reply->data, "test-rule") == NULL) {
        log_err("error: lifecycle response missing rule ID 'test-rule'\n");
        goto cleanup_and_ret;
    }

    if (strstr((char*)reply->data, "tmp/") == NULL) {
        log_err("error: lifecycle response missing prefix 'tmp/'\n");
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);
    s3c_reply_free(reply);
    reply = NULL;

    // send garbled xml — expect S3 to reject it
    log_info("bucket config: set garbled xml...");

    reply = s3c_set_bucket_config(client, TEST_BUCKET_CONFIG, "lifecycle",
                                   "<LifecycleConfiguration><not closed");

    if (reply->error == NULL) {
        log_err("error: expected S3 to reject garbled XML\n");
        goto cleanup_and_ret;
    }

    log_info("ok rejected, resp code => %d\n", (int)reply->http_resp_code);
    s3c_reply_free(reply);
    reply = NULL;

    // send valid xml with bogus fields — expect S3 to reject it
    log_info("bucket config: set bogus fields...");

    reply = s3c_set_bucket_config(client, TEST_BUCKET_CONFIG, "lifecycle",
                                   "<LifecycleConfiguration>"
                                   "<Rule>"
                                   "<BogusField>nonsense</BogusField>"
                                   "</Rule>"
                                   "</LifecycleConfiguration>");

    if (reply->error == NULL) {
        log_err("error: expected S3 to reject bogus fields\n");
        goto cleanup_and_ret;
    }

    log_info("ok rejected, resp code => %d\n", (int)reply->http_resp_code);

    all_good = true;

cleanup_and_ret:
    s3c_reply_free(reply);

    return all_good;
}

bool test_list_objects(s3cClient* client)
{
    bool all_good = false;
    s3cReply* reply = NULL;

    const char* keys[] = {
        "list-test/a.txt",
        "list-test/b.txt",
        "list-test/c.txt",
    };
    const int nkeys = 3;
    const char* payload = "x";

    log_info("list objects: setup...");

    for (int i = 0; i < nkeys; i++) {
        reply = s3c_put_object(client, TEST_BUCKET, keys[i],
                               (const uint8_t*)payload, 1, NULL);
        if (reply->error != NULL) {
            log_err("error: failed to put object '%s': %s\n", keys[i], reply->error);
            s3c_reply_free(reply);
            reply = NULL;
            goto cleanup_and_ret;
        }
        s3c_reply_free(reply);
        reply = NULL;
    }

    log_info("ok\n");

    log_info("list objects: no opts...");

    reply = s3c_list_objects(client, TEST_BUCKET, NULL);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    for (int i = 0; i < nkeys; i++) {
        bool found = false;
        for (s3cListEntry* e = reply->result.list.entries; e != NULL; e = e->next) {
            if (strcmp(e->key, keys[i]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            log_err("error: key '%s' not found in list response\n", keys[i]);
            goto cleanup_and_ret;
        }
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);
    s3c_reply_free(reply);
    reply = NULL;

    log_info("list objects: prefix filter...");

    s3cListObjectsOpts prefix_opts = { .prefix = "list-test/", .max_keys = 10 };
    reply = s3c_list_objects(client, TEST_BUCKET, &prefix_opts);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    for (int i = 0; i < nkeys; i++) {
        bool found = false;
        for (s3cListEntry* e = reply->result.list.entries; e != NULL; e = e->next) {
            if (strcmp(e->key, keys[i]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            log_err("error: key '%s' not found in prefix-filtered response\n", keys[i]);
            goto cleanup_and_ret;
        }
    }

    log_info("ok\n");
    s3c_reply_free(reply);
    reply = NULL;

    log_info("list objects: max_keys=0 (default)...");

    s3cListObjectsOpts default_opts = { .prefix = "list-test/", .max_keys = 0 };
    reply = s3c_list_objects(client, TEST_BUCKET, &default_opts);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->result.list.entries == NULL) {
        log_err("error: max_keys=0 should use S3 default, got no entries\n");
        goto cleanup_and_ret;
    }

    log_info("ok\n");
    s3c_reply_free(reply);
    reply = NULL;

    log_info("list objects: max_keys=1...");

    s3cListObjectsOpts max_keys_opts = { .max_keys = 1 };
    reply = s3c_list_objects(client, TEST_BUCKET, &max_keys_opts);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    s3cListEntry* entries = reply->result.list.entries;

    if (entries == NULL) {
        log_err("error: expected at least one entry with max_keys=1\n");
        goto cleanup_and_ret;
    }

    if (entries->next != NULL) {
        log_err("error: expected only one entry with max_keys=1 but got more\n");
        goto cleanup_and_ret;
    }

    log_info("ok\n");

    log_info("list objects: continuation token...");

    if (!reply->result.list.is_truncated || reply->result.list.continuation_token == NULL) {
        log_err("error: expected truncated response with continuation token\n");
        goto cleanup_and_ret;
    }

    const char* first_key = entries->key;

    s3cListObjectsOpts cont_opts = {
        .max_keys = 1,
        .continuation_token = reply->result.list.continuation_token,
    };

    s3cReply* cont_reply = s3c_list_objects(client, TEST_BUCKET, &cont_opts);

    if (cont_reply->error != NULL) {
        log_err("error: %s\n", cont_reply->error);
        s3c_reply_free(cont_reply);
        goto cleanup_and_ret;
    }

    s3cListEntry* cont_entries = cont_reply->result.list.entries;

    if (cont_entries == NULL) {
        log_err("error: no entries in continuation page\n");
        s3c_reply_free(cont_reply);
        goto cleanup_and_ret;
    }

    if (cont_entries->next != NULL) {
        log_err("error: expected one entry in continuation page but got more\n");
        s3c_reply_free(cont_reply);
        goto cleanup_and_ret;
    }

    if (strcmp(first_key, cont_entries->key) == 0) {
        log_err("error: continuation page returned same key as first page\n");
        s3c_reply_free(cont_reply);
        goto cleanup_and_ret;
    }

    s3c_reply_free(cont_reply);
    log_info("ok\n");

    s3c_reply_free(reply);
    reply = NULL;

    log_info("list objects: fetch_all...");

    s3cListObjectsOpts fetch_all_opts = {
        .prefix = "list-test/",
        .max_keys = 1,
        .fetch_all = true,
    };
    reply = s3c_list_objects(client, TEST_BUCKET, &fetch_all_opts);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    int entry_count = 0;
    for (s3cListEntry* e = reply->result.list.entries; e != NULL; e = e->next) {
        entry_count++;
    }

    if (entry_count != nkeys) {
        log_err("error: fetch_all returned %d entries, expected %d\n", entry_count, nkeys);
        goto cleanup_and_ret;
    }

    for (int i = 0; i < nkeys; i++) {
        bool found = false;
        for (s3cListEntry* e = reply->result.list.entries; e != NULL; e = e->next) {
            if (strcmp(e->key, keys[i]) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            log_err("error: key '%s' not found in fetch_all response\n", keys[i]);
            goto cleanup_and_ret;
        }
    }

    log_info("ok\n");

    all_good = true;

cleanup_and_ret:
    s3c_reply_free(reply);

    for (int i = 0; i < nkeys; i++) {
        s3cReply* del = s3c_delete_object(client, TEST_BUCKET, keys[i]);
        s3c_reply_free(del);
    }

    return all_good;
}

bool run_basic_tests(s3cClient* client)
{
    s3cReply* reply = NULL;
    s3cKVL* headers = NULL;
    char* filebuf = NULL;
    bool all_good = false;

    const char* object_key = "test/file.bin";
    const char* rt_data = "test payload";
    size_t rt_data_size = strlen(rt_data);
    const char* rt_content_type = "text/plain;charset=UTF-8";

    log_info("put object...");
    s3c_kvl_ins(&headers, "content-type", rt_content_type);

    s3c_reply_free(reply);

    reply = s3c_put_object(
        client, TEST_BUCKET, object_key,
        (const uint8_t*)rt_data, rt_data_size,
        headers
    );

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);


    log_info("fetching object...");
    s3c_reply_free(reply);
    reply = s3c_get_object(client, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->data_size != rt_data_size ||
        memcmp(rt_data, reply->data, reply->data_size) != 0) {
        log_err(
            "error: reply payload [%s][%zu] did not match original payload [%s][%zu]\n"
            "resp code: %zu\n",
            reply->data, reply->data_size, rt_data, rt_data_size,
            reply->http_resp_code
        );

        goto cleanup_and_ret;
    }

    s3cKVL* ct_req_header = s3c_kvl_find(headers, "content-type");
    s3cKVL* ct_resp_header = s3c_kvl_find(reply->headers, "content-type");

    if (ct_resp_header == NULL ||
        strcmp(ct_resp_header->value, ct_req_header->value) != 0) {

        log_err("error: returned content type header does not match original\n");
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("get object via callback...");
    s3c_reply_free(reply);

    TestCbBuf cb_buf = {
        .buf = calloc(rt_data_size + 1, 1),
        .len = 0,
        .cap = rt_data_size + 1,
    };

    reply = s3c_get_object_stream(client, TEST_BUCKET, object_key,
                               NULL, test_stream_cb, &cb_buf);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        free(cb_buf.buf);
        goto cleanup_and_ret;
    }

    if (cb_buf.len != rt_data_size ||
        memcmp(cb_buf.buf, rt_data, rt_data_size) != 0) {
        log_err("error: callback data does not match original\n");
        free(cb_buf.buf);
        goto cleanup_and_ret;
    }

    if (!cb_buf.has_headers) {
        log_err("error: callback did not receive response headers\n");
        free(cb_buf.buf);
        goto cleanup_and_ret;
    }

    free(cb_buf.buf);
    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("head object...");
    s3c_reply_free(reply);
    reply = s3c_head_object(client, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    s3cKVL* head_ct = s3c_kvl_find(reply->headers, "content-type");
    if (head_ct == NULL || strcmp(head_ct->value, rt_content_type) != 0) {
        log_err("error: head object content-type does not match\n");
        goto cleanup_and_ret;
    }

    s3cKVL* head_cl = s3c_kvl_find(reply->headers, "content-length");
    if (head_cl == NULL) {
        log_err("error: head object missing content-length\n");
        goto cleanup_and_ret;
    }

    if (reply->data_size != 0) {
        log_err("error: head object should have no body, got %zu bytes\n",
                (size_t)reply->data_size);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    const char* copy_key = "test/file-copy.bin";

    log_info("copy object...");
    s3c_reply_free(reply);
    reply = s3c_copy_object(client, TEST_BUCKET, object_key,
                            TEST_BUCKET, copy_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("verify copy...");
    s3c_reply_free(reply);
    reply = s3c_get_object(client, TEST_BUCKET, copy_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->data_size != rt_data_size ||
        memcmp(rt_data, reply->data, reply->data_size) != 0) {
        log_err("error: copied object content does not match original\n");
        goto cleanup_and_ret;
    }

    log_info("ok\n");

    log_info("delete copy...");
    s3c_reply_free(reply);
    reply = s3c_delete_object(client, TEST_BUCKET, copy_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("presigned url...");
    s3c_reply_free(reply);
    reply = s3c_generate_presigned_url(client, TEST_BUCKET, object_key, "GET", 3600);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->data == NULL || reply->data_size == 0) {
        log_err("error: presigned url is empty\n");
        goto cleanup_and_ret;
    }

    if (strstr((char*)reply->data, "https://") != (char*)reply->data) {
        log_err("error: presigned url does not start with https://\n");
        goto cleanup_and_ret;
    }

    if (strstr((char*)reply->data, "X-Amz-Signature=") == NULL) {
        log_err("error: presigned url missing X-Amz-Signature\n");
        goto cleanup_and_ret;
    }

    log_info("ok\n");

    log_info("presigned url: curl fetch...");
    {
        char cmd[2048];
        snprintf(cmd, sizeof(cmd),
                 "curl -sf -o tests/obj_file '%s'", (char*)reply->data);

        int curl_ret = system(cmd);
        if (curl_ret != 0) {
            log_err("error: curl fetch failed with exit code %d\n", curl_ret);
            goto cleanup_and_ret;
        }

        char* fetched = NULL;
        size_t fetched_sz = 0;
        read_file(LOCAL_OBJ_FILE, &fetched, &fetched_sz);

        if (fetched_sz != rt_data_size ||
            memcmp(fetched, rt_data, rt_data_size) != 0) {
            log_err("error: presigned url fetched content does not match original\n");
            free(fetched);
            goto cleanup_and_ret;
        }

        free(fetched);
        remove(LOCAL_OBJ_FILE);
    }

    log_info("ok\n");

    log_info("fetching object to file...");

    bool fetch_cmp_ok = fetch_and_compare_file(
        client, object_key,
        rt_data, rt_data_size,
        rt_content_type
    );

    if (!fetch_cmp_ok) {
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);


    log_info("put object from file...");
    s3c_reply_free(reply);

    reply = s3c_put_object_from_file(
       client, TEST_BUCKET, object_key, LOCAL_OBJ_FILE,
       headers
    );

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("delete object...");
    s3c_reply_free(reply);

    reply = s3c_delete_object(client, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }
    log_info("ok resp code => %d\n", (int)reply->http_resp_code);


    log_info("confirm object was deleted...");

    s3c_reply_free(reply);
    reply = s3c_get_object(client, TEST_BUCKET, object_key);

    if (reply->error == NULL) {
        log_err("error: expected error in reply but no error is set\n");
        goto cleanup_and_ret;
    }
    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    all_good = true;

cleanup_and_ret:
    s3c_reply_free(reply);
    s3c_kvl_free(headers);

    free(filebuf);
    remove(LOCAL_OBJ_FILE);

    return all_good;
}

bool test_idle(s3cClient* client, int sleep_sec)
{
    log_info("idle test: request 1...");

    s3cReply* r = s3c_list_objects(client, TEST_BUCKET, NULL);
    if (r->error != NULL) {
        log_err("error: %s\n", r->error);
        s3c_reply_free(r);
        return false;
    }
    log_info("ok resp code => %d\n", (int)r->http_resp_code);
    s3c_reply_free(r);

    log_info("idle test: sleeping %ds...\n", sleep_sec);
    sleep(sleep_sec);

    log_info("idle test: request 2...");
    r = s3c_list_objects(client, TEST_BUCKET, NULL);
    if (r->error != NULL) {
        log_err("error: %s\n", r->error);
        s3c_reply_free(r);
        return false;
    }
    log_info("ok resp code => %d\n", (int)r->http_resp_code);
    s3c_reply_free(r);

    return true;
}

int main(int argc, const char** argv)
{
    const char* keys_file = "tests/s3c_keys";
    int ret_code = 0;
    bool run_idle_test = false;
    int idle_sleep_sec = 10;

    s3cKeys keys = {0};
    s3cClient* client = NULL;
    s3cReply* client_err = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--test-idle", 11) == 0) {
            run_idle_test = true;
            if (argv[i][11] == '=' && argv[i][12] != '\0') {
                idle_sleep_sec = atoi(&argv[i][12]);
            }
        } else if (strncmp(argv[i], "--keys=", 7) == 0 && argv[i][7] != '\0') {
            keys_file = &argv[i][7];
            log_info("using keys file '%s'\n", keys_file);
        } else {
            log_err("unknown argument: %s\n", argv[i]);
            log_err("usage: tests [--keys=<file>] [--test-idle[=seconds]]\n");
            return 1;
        }
    }

    bool ok = run_local_tests();
    if (!ok) {
        ret_code = 1;
    }

    const char* err = read_s3c_keys_file(keys_file, &keys);

    if (err != NULL) {
        log_info("failed to run tests: %s\n", err);
        ret_code = 1;
        goto cleanup_and_ret;
    }

    client = s3c_client_new(&keys, NULL, &client_err);
    if (client == NULL) {
        log_info("failed to run tests: %s\n",
                 client_err != NULL ? client_err->error : "failed to initialize s3 client");
        ret_code = 1;
        goto cleanup_and_ret;
    }

    if (run_idle_test) {
        ok = test_idle(client, idle_sleep_sec);
        if (!ok) ret_code = 1;
        goto cleanup_and_ret;
    }

    // create all test buckets
    log_info("creating test buckets...");
    {
        const char* buckets[] = { TEST_BUCKET, TEST_BUCKET_CONFIG };
        for (int i = 0; i < 2; i++) {
            s3cReply* r = s3c_create_bucket(client, buckets[i], NULL);
            if (r->error != NULL && r->http_resp_code != 409) {
                log_err("error: failed to create bucket '%s': %s\n", buckets[i], r->error);
                s3c_reply_free(r);
                ret_code = 1;
                goto cleanup_and_ret;
            }
            s3c_reply_free(r);
        }
    }
    log_info("ok\n");

    ok = run_basic_tests(client);
    if (!ok) {
        ret_code = 1;
    }

    ok = test_threaded_put_delete(&keys);
    if (!ok) {
        ret_code = 1;
    }

    ok = test_threaded_put_nonexistent_bucket(&keys);
    if (!ok) {
        ret_code = 1;
    }

    ok = test_big_object(client);
    if (!ok) {
        ret_code = 1;
    }

    ok = test_multipart_api(client);
    if (!ok) {
        ret_code = 1;
    }

    ok = test_list_abort_multipart(client);
    if (!ok) {
        ret_code = 1;
    }

    ok = test_bucket_config(client);
    if (!ok) {
        ret_code = 1;
    }

    ok = test_list_objects(client);
    if (!ok) {
        ret_code = 1;
    }

    // delete all test buckets
    log_info("deleting test buckets...");
    {
        const char* buckets[] = { TEST_BUCKET, TEST_BUCKET_CONFIG };
        for (int i = 0; i < 2; i++) {
            s3cReply* r = s3c_delete_bucket(client, buckets[i]);
            s3c_reply_free(r);
        }
    }
    log_info("ok\n");

cleanup_and_ret:
    if (ret_code == 0) {
        log_info("=> tests passed\n");
    } else {
        log_info("=> tests failed\n");
    }

    free(keys.access_key_id);
    free(keys.access_key_secret);
    free(keys.region);
    free(keys.endpoint);
    s3c_client_free(client);
    s3c_reply_free(client_err);

    return ret_code;
}
