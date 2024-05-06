#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define S3C_CONF_NET_IO_TIMEOUT_SEC         0  // default 15 seconds
#define S3C_CONF_MAX_REPLY_PREALLOC_SIZE_MB 1  // default 512 mb

uint32_t s3c_set_global_config(uint32_t conf_num, uint32_t value);

typedef struct {
    char* access_key_id;
    char* access_key_secret;
    char* region;
    char* endpoint;
} s3cKeys;

typedef struct s3cHeader {
    char* name;
    char* value;
    struct s3cHeader* next;
} s3cHeader;

typedef struct {
    char*      error;
    s3cHeader* headers;
    uint8_t*   data;
    uint64_t   data_size;
    uint64_t   http_resp_code;
} s3cReply;

s3cReply* s3c_put_object(const s3cKeys*,
                         const char* bucket, const char* object_key,
                         const uint8_t* data, uint64_t data_size,
                         const s3cHeader* headers);

s3cReply* s3c_get_object(const s3cKeys*,
                         const char* bucket, const char* object_key);

s3cReply* s3c_delete_object(const s3cKeys*,
                            const char* bucket, const char* object_key);

s3cReply* s3c_create_bucket(const s3cKeys*, const char* bucket);

s3cReply* s3c_delete_bucket(const s3cKeys*, const char* bucket);

void s3c_headers_add(s3cHeader** head,
                     const char* name, const char* value);

void s3c_headers_add_int(s3cHeader** head,
                         const char* name, int64_t int_value);

s3cHeader* s3c_headers_find(s3cHeader* head, const char* name);

void s3c_headers_remove(s3cHeader** head, const char* name);

void s3c_reply_free(s3cReply*);

void s3c_headers_free(s3cHeader*);


#ifdef __cplusplus
}
#endif








