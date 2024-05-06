#define _POSIX_C_SOURCE 200809L

#include "../src/s3c.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char*
parse_s3c_keys(const char* filename, s3cKeys* keys)
{
    const char* err = NULL;
    char* filebuf = NULL;
    FILE* fp = fopen(filename, "rb");

    if (fp == NULL) {
        err = "failed to open s3c keys file";
        goto cleanup_and_ret;
    }

    fseek(fp, 0, SEEK_END);
    size_t filesize = ftell(fp);

    if (filesize < 1) {
        err = "failed to read s3c keys file, file is empty";
        goto cleanup_and_ret;
    }

    fseek(fp, 0, SEEK_SET);

    filebuf = malloc(filesize + 1);
    size_t read_res = fread(filebuf, filesize, 1, fp);
    if (read_res < 1) {
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
    if (fp != NULL) {
        fclose(fp);
    }

    free(filebuf);
    return err;
}

static bool
run_basic_tests(const s3cKeys* keys)
{
    s3cReply* reply = NULL;
    s3cHeader* headers = NULL;
    bool all_good = true;

    printf("creating bucket...");
    const char* bucket = "s3c-tests";

    reply = s3c_create_bucket(keys, bucket);
    if (reply->error != NULL && reply->http_resp_code != 409) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }
    printf(" ok resp code => %d\n", (int)reply->http_resp_code);


    printf("creating object...");
    const char* object_key = "test/file.bin";
    const char* data = "test payload";
    size_t data_size = strlen(data) - 1;
    s3c_headers_add(&headers, "content-type", "text/plain;charset=UTF-8");

    s3c_reply_free(reply);
    reply = s3c_put_object(keys, bucket, object_key,
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
    reply = s3c_get_object(keys, bucket, object_key);

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

    printf("deleting object...");
    s3c_reply_free(reply);
    reply = s3c_delete_object(keys, bucket, object_key);

    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }
    printf(" ok resp code => %d\n", (int)reply->http_resp_code);

    printf("confirm object was deleted...");
    s3c_reply_free(reply);
    reply = s3c_get_object(keys, bucket, object_key);

    if (reply->error == NULL) {
        printf(" error: expected error in reply but no error is set\n");
        all_good = false;
        goto cleanup_and_ret;
    }
    printf(" ok resp code => %d\n", (int)reply->http_resp_code);

    printf("deleting bucket...");
    s3c_reply_free(reply);
    reply = s3c_delete_bucket(keys, bucket);

    if (reply->error != NULL) {
        printf(" error: %s\n", reply->error);
        all_good = false;
        goto cleanup_and_ret;
    }

    printf(" ok resp code => %d\n", (int)reply->http_resp_code);

cleanup_and_ret:
    s3c_reply_free(reply);
    s3c_headers_free(headers);

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
