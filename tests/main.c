#define _POSIX_C_SOURCE 200809L

#include "../src/s3c.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* TEST_BUCKET = "s3c-tests";
static const char* LOCAL_OBJ_FILE = "tests/obj_file";


static void
read_file(const char* filename, char** out_filebuf, size_t* out_filesize)
{
    FILE* fp = fopen(filename, "rb");

    if (fp == NULL) {
        *out_filebuf = NULL;
        *out_filesize = 0;
        return;
    }

    fseek(fp, 0, SEEK_END);
    size_t filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* filebuf = calloc(filesize + 1, 1);
    *out_filebuf = filebuf;

    size_t read_res = fread(filebuf, filesize, 1, fp);

    if (read_res < 1) {
        *out_filesize = 0;
    } else {
        *out_filesize = filesize;
    }

    fclose(fp);
}

static const char*
parse_s3c_keys(const char* filename, s3cKeys* keys)
{
    const char* err = NULL;

    char* filebuf;
    size_t filesize;

    read_file(filename, &filebuf, &filesize);

    if (filesize < 1) {
        err = "failed to read s3c keys file";
        goto cleanup_and_ret;
    }

    unsigned rc = 0, wc = 0;
    while (rc < filesize) {
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

static bool
create_test_bucket(const s3cKeys* keys)
{
    bool ok = true;

    s3cReply* reply = s3c_create_bucket(keys, TEST_BUCKET);

    if (reply->error != NULL && reply->http_resp_code != 409) {
        ok = false;
    }

    s3c_reply_free(reply);

    return ok;
}

static bool
delete_test_bucket(const s3cKeys* keys)
{
    bool ok = true;

    s3cReply* reply = s3c_delete_bucket(keys, TEST_BUCKET);

    if (reply->error != NULL) {
        ok = false;
    }

    s3c_reply_free(reply);

    return ok;
}

static bool
put_big_object(const s3cKeys* keys)
{
    size_t payload_size = 1024 * 1024 * 7;
    const char* object_key = "big-file";
    char* filebuf = NULL;

    create_test_bucket(keys);

    bool ok = true;
    uint8_t* payload = calloc(payload_size, 1);

    for (unsigned i = 0; i < payload_size; i++) {
        payload[i] = i % 256;
    }

    printf("put big object...");

    s3cReply* reply = s3c_put_object(keys, TEST_BUCKET, object_key,
                                    (const uint8_t*)payload, payload_size,
                                    NULL);
    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        ok = false;
    } else {
        printf(" ok resp code => %d\n", (int)reply->http_resp_code);
    }

    s3c_reply_free(reply);

    printf("get big object to file...");
    reply = s3c_get_object_to_file(keys, TEST_BUCKET, object_key,
                                   LOCAL_OBJ_FILE);
    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        ok = false;

    } else {

        size_t filesize = 0;
        read_file(LOCAL_OBJ_FILE, &filebuf, &filesize);

        if (filesize != payload_size) {
            printf(" error: payload size [%zu] does not match file size [%zu]\n",
                payload_size, filesize
            );
            ok = false;
        } else if (memcmp(filebuf, payload, payload_size) != 0) {
            puts(" error: payload data / returned file content do not match");
            ok = false;

        } else {
            printf(" ok resp code => %d\n", (int)reply->http_resp_code);
        }
    }

    s3c_reply_free(reply);

    reply = s3c_delete_object(keys, TEST_BUCKET, object_key);
    s3c_reply_free(reply);

    free(payload);
    if (filebuf) {
        free(filebuf);
    }

    remove(LOCAL_OBJ_FILE);

    delete_test_bucket(keys);

    return ok;
}

static bool
run_basic_tests(const s3cKeys* keys)
{
    s3cReply* reply = NULL;
    s3cHeader* headers = NULL;
    char* filebuf = NULL;
    bool all_good = true;

    printf("creating bucket...");

    reply = s3c_create_bucket(keys, TEST_BUCKET);
    if (reply->error != NULL && reply->http_resp_code != 409) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }
    printf(" ok resp code => %d\n", (int)reply->http_resp_code);

    const char* object_key = "test/file.bin";
    const char* data = "test payload";
    size_t data_size = strlen(data);

    printf("put object...");
    s3c_headers_add(&headers, "content-type", "text/plain;charset=UTF-8");

    s3c_reply_free(reply);
    reply = s3c_put_object(keys, TEST_BUCKET, object_key,
                                   (const uint8_t*)data, data_size,
                                   headers);
    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }

    printf(" ok resp code => %d\n", (int)reply->http_resp_code);


    printf("fetching object...");
    s3c_reply_free(reply);
    reply = s3c_get_object(keys, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }

    if (reply->data_size != data_size ||
        memcmp(data, reply->data, reply->data_size) != 0) {
        printf(" error: reply payload did not match original payload\n");
        all_good = false;
        goto cleanup_and_ret;
    }

    s3cHeader* ct_req_header = s3c_headers_find(headers, "content-type");
    s3cHeader* ct_resp_header = s3c_headers_find(reply->headers, "content-type");

    if (ct_resp_header == NULL ||
        strcmp(ct_resp_header->value, ct_req_header->value) != 0) {

        printf(" error: returned content type header does not match original\n");
        all_good = false;
        goto cleanup_and_ret;
    }
    printf(" ok resp code => %d\n", (int)reply->http_resp_code);


    printf("fetching object to file...");
    s3c_reply_free(reply);

    reply = s3c_get_object_to_file(keys, TEST_BUCKET, object_key, LOCAL_OBJ_FILE);

    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }

    size_t filesize = 0;
    read_file(LOCAL_OBJ_FILE, &filebuf, &filesize);

    if (filesize < 1) {
        printf(" error: failed to read reply file\n");
        all_good = false;
        goto cleanup_and_ret;
    }

    if (filesize != data_size ||
        memcmp(data, filebuf, filesize) != 0) {
        printf(" error: reply payload did not match original payload\n");
        all_good = false;
        goto cleanup_and_ret;
    }

    printf("deleting object...");
    s3c_reply_free(reply);
    reply = s3c_delete_object(keys, TEST_BUCKET, object_key);

    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }
    printf(" ok resp code => %d\n", (int)reply->http_resp_code);


    printf("confirm object was deleted...");
    s3c_reply_free(reply);
    reply = s3c_get_object(keys, TEST_BUCKET, object_key);

    if (reply->error == NULL) {
        printf(" error: expected error in reply but no error is set\n");
        all_good = false;
        goto cleanup_and_ret;
    }
    printf(" ok resp code => %d\n", (int)reply->http_resp_code);

    printf("deleting bucket...");
    s3c_reply_free(reply);
    reply = s3c_delete_bucket(keys, TEST_BUCKET);

    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }

    printf(" ok resp code => %d\n", (int)reply->http_resp_code);


cleanup_and_ret:
    s3c_reply_free(reply);
    s3c_headers_free(headers);

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
        printf("using arg supplied keys file '%s'\n", keys_file);
    }

    const char* err = parse_s3c_keys(keys_file, &keys);

    if (err != NULL) {
        fprintf(stderr, "failed to run tests: %s\n", err);
        ret_code = 1;
        goto cleanup_and_ret;
    }

    bool ok = run_basic_tests(&keys);
    if (!ok) {
        ret_code = 1;
        goto cleanup_and_ret;
    }

    ok = put_big_object(&keys);
    if (!ok) {
        ret_code = 1;
    }

cleanup_and_ret:

    if (ret_code == 0) {
        printf("=> tests passed\n");
    } else {
        fprintf(stderr, "=> tests failed\n");
    }

    free(keys.access_key_id);
    free(keys.access_key_secret);
    free(keys.region);
    free(keys.endpoint);

    return ret_code;
}
