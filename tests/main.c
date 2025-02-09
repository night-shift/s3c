#define _POSIX_C_SOURCE 200809L

#include "../src/s3c.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

const char* TEST_BUCKET = "s3c-tests";
const char* LOCAL_OBJ_FILE = "tests/obj_file";


void
log_info(const char* fmt_str, ...)
{
    va_list args;
    va_start(args, fmt_str);

    vprintf(fmt_str, args);
    fflush(stdout);

    va_end(args);
}

void
log_err(const char* fmt_str, ...)
{
    printf("\033[31m");

    va_list args;
    va_start(args, fmt_str);

    vprintf(fmt_str, args);

    va_end(args);

    printf("\033[0m");
    fflush(stdout);
}

void
read_file(const char* filename, char** out_filebuf, size_t* out_file_size)
{
    FILE* fp = fopen(filename, "rb");

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

const char*
read_s3c_keys_file(const char* filename, s3cKeys* keys)
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

bool
create_test_bucket(const s3cKeys* keys)
{
    bool ok = true;

    s3cReply* reply = s3c_create_bucket(keys, TEST_BUCKET, NULL);

    if (reply->error != NULL && reply->http_resp_code != 409) {
        ok = false;
    }

    s3c_reply_free(reply);

    return ok;
}

bool
delete_test_bucket(const s3cKeys* keys)
{
    s3cReply* reply = s3c_delete_bucket(keys, TEST_BUCKET);
    bool ok = reply->error != NULL;
    s3c_reply_free(reply);

    return ok;
}

bool
fetch_and_compare_file(const s3cKeys* keys,
                       const char* obj_key,
                       const char* source, size_t source_sz,
                       const char* source_ct)
{
    bool ok = false;
    char* fetched = NULL;

    remove(LOCAL_OBJ_FILE);

    s3cReply* reply = s3c_get_object_to_file(
        keys, TEST_BUCKET, obj_key, LOCAL_OBJ_FILE
    );

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    size_t fetched_sz = 0;
    read_file(LOCAL_OBJ_FILE, &fetched, &fetched_sz);

    if (fetched_sz != source_sz) {
        log_err("error: source size [%zu] does not match fetched file size [%zu]\n",
            fetched_sz, source_sz
        );
        goto cleanup_and_ret;
    }

    if (memcmp(source, fetched, source_sz) != 0) {
        log_err("error: source / fetched file content do not match\n");
        goto cleanup_and_ret;
    }

    if (source_ct != NULL) {

        s3cKVL* fetched_ct_header = s3c_kvl_find(reply->headers, "content-type");

        if (fetched_ct_header == NULL) {
            log_err("error: fetched file has no content type header\n");
            goto cleanup_and_ret;
        }

        if (strcmp(fetched_ct_header->value, source_ct)) {
            log_err("error: fetched file has wrong content header\n");
            goto cleanup_and_ret;
        }
    }

    ok = true;

cleanup_and_ret:
    s3c_reply_free(reply);
    free(fetched);

    return ok;
}

bool
put_big_object(const s3cKeys* keys)
{
    size_t rt_data_size = 1024 * 1024 * 25;
    const char* object_key = "big-file";
    const char* rt_content_type = "application/binary";
    char* filebuf = NULL;

    s3cKVL ct_header = {
        .key = "content-type",
        .value = (char*)rt_content_type,
        .next = NULL
    };

    create_test_bucket(keys);

    bool ok = false;
    char* rt_data = calloc(rt_data_size, 1);

    for (unsigned i = 0; i < rt_data_size; i++) {
        rt_data[i] = i % 256;
    }

    log_info("put big object...");

    s3cReply* reply = s3c_put_object(keys, TEST_BUCKET, object_key,
                                    (const uint8_t*)rt_data, rt_data_size,
                                    &ct_header);
    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("get big object to file...");

    bool fetch_cmp_ok = fetch_and_compare_file(
        keys, object_key,
        rt_data, rt_data_size,
        rt_content_type
    );

    if (!fetch_cmp_ok) {
        goto cleanup_and_ret;
    };

    log_info("ok\n");

    log_info("put big object from file multipart...");

    s3c_reply_free(reply);

    reply = s3c_put_object_from_file(keys, TEST_BUCKET, object_key,
                                     LOCAL_OBJ_FILE, &ct_header);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("fetch big object from file after multipart...");
    fetch_cmp_ok = fetch_and_compare_file(
        keys, object_key,
        rt_data, rt_data_size,
        rt_content_type
    );

    if (!fetch_cmp_ok) {
        goto cleanup_and_ret;
    };

    log_info("ok\n");

    ok = true;

cleanup_and_ret:

    s3c_reply_free(reply);
    reply = s3c_delete_object(keys, TEST_BUCKET, object_key);
    s3c_reply_free(reply);

    free(rt_data);
    free(filebuf);

    remove(LOCAL_OBJ_FILE);
    delete_test_bucket(keys);

    return ok;
}

bool
run_basic_tests(const s3cKeys* keys)
{
    s3cReply* reply = NULL;
    s3cKVL* headers = NULL;
    char* filebuf = NULL;
    bool all_good = false;

    log_info("create bucket...");

    reply = s3c_create_bucket(keys, TEST_BUCKET, NULL);
    if (reply->error != NULL && reply->http_resp_code != 409) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }
    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    const char* object_key = "test/file.bin";
    const char* rt_data = "test payload";
    size_t rt_data_size = strlen(rt_data);
    const char* rt_content_type = "text/plain;charset=UTF-8";

    log_info("put object...");
    s3c_kvl_ins(&headers, "content-type", rt_content_type);

    s3c_reply_free(reply);

    reply = s3c_put_object(
        keys,
        TEST_BUCKET, object_key,
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
    reply = s3c_get_object(keys, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    if (reply->data_size != rt_data_size ||
        memcmp(rt_data, reply->data, reply->data_size) != 0) {
        log_err("error: reply payload did not match original payload\n");
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

    log_info("fetching object to file...");

    bool fetch_cmp_ok = fetch_and_compare_file(
        keys, object_key,
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
       keys,
       TEST_BUCKET, object_key,
       LOCAL_OBJ_FILE,
       headers
    );

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("delete object...");
    s3c_reply_free(reply);
    reply = s3c_delete_object(keys, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }
    log_info("ok resp code => %d\n", (int)reply->http_resp_code);


    log_info("confirm object was deleted...");
    s3c_reply_free(reply);
    reply = s3c_get_object(keys, TEST_BUCKET, object_key);

    if (reply->error == NULL) {
        log_err("error: expected error in reply but no error is set\n");
        goto cleanup_and_ret;
    }
    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    log_info("delete bucket...");
    s3c_reply_free(reply);
    reply = s3c_delete_bucket(keys, TEST_BUCKET);

    if (reply->error != NULL) {
        log_err("error: %s\n", reply->error);
        goto cleanup_and_ret;
    }

    log_info("ok resp code => %d\n", (int)reply->http_resp_code);

    all_good = true;

cleanup_and_ret:
    s3c_reply_free(reply);
    s3c_kvl_free(headers);

    if (filebuf != NULL) {
        free(filebuf);
    }

    remove(LOCAL_OBJ_FILE);

    return all_good;
}

int main(int argc, const char** argv)
{
    const char* keys_file = "tests/s3c_keys";
    int ret_code = 0;

    s3cKeys keys = {0};

    if (argc > 1) {
        keys_file = argv[1];
        log_info("using arg supplied keys file '%s'\n", keys_file);
    }

    const char* err = read_s3c_keys_file(keys_file, &keys);

    if (err != NULL) {
        log_info("failed to run tests: %s\n", err);
        ret_code = 1;
        goto cleanup_and_ret;
    }

    bool ok = run_basic_tests(&keys);
    if (!ok) {
        ret_code = 1;
    }

    ok = put_big_object(&keys);
    if (!ok) {
        ret_code = 1;
    }

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

    return ret_code;
}
