#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define S3C_CONF_NET_IO_TIMEOUT_SEC         0  // default 15 seconds
#define S3C_CONF_MAX_REPLY_PREALLOC_SIZE_MB 1  // default 128 mb

uint64_t s3c_set_global_config(uint64_t conf_num, int64_t value);

typedef struct {
    char* access_key_id;
    char* access_key_secret;
    char* region;
    char* endpoint;
} s3cKeys;

typedef struct s3cKVL {
    char* key;
    char* value;
    struct s3cKVL* next;
} s3cKVL;

typedef struct {
    char*    error;
    s3cKVL*  headers;
    uint8_t* data;
    uint64_t data_size;
    uint64_t http_resp_code;
} s3cReply;


s3cReply* s3c_put_object(const s3cKeys* keys,
                         const char* bucket, const char* object_key,
                         const uint8_t* data, uint64_t data_size,
                         const s3cKVL* headers);

s3cReply* s3c_get_object(const s3cKeys* keys,
                         const char* bucket, const char* object_key);


s3cReply* s3c_get_object_to_file(const s3cKeys* keys,
                                 const char* bucket, const char* object_key,
                                 const char* file);


s3cReply* s3c_put_object_from_file(const s3cKeys* keys,
                                   const char* bucket, const char* object_key,
                                   const char* file,
                                   const s3cKVL* headers);

typedef struct {
    uint64_t part_size;
    uint64_t max_send_retries;
} s3cMultipartOpts;

s3cReply* s3c_put_object_from_file_multipart(const s3cKeys* keys,
                                             const char* bucket, const char* object_key,
                                             const char* file,
                                             const s3cKVL* headers,
                                             const s3cMultipartOpts* opts);


s3cReply* s3c_delete_object(const s3cKeys* keys, const char* bucket, const char* object_key);


s3cReply* s3c_create_bucket(const s3cKeys* keys, const char* bucket, const s3cKVL* headers);


s3cReply* s3c_delete_bucket(const s3cKeys* keys, const char* bucket);


void s3c_kvl_ins(s3cKVL** head_ref, const char* name, const char* value);


void s3c_kvl_ins_int(s3cKVL** head_ref, const char* name, int64_t int_value);


s3cKVL* s3c_kvl_find(s3cKVL* head, const char* name);


void s3c_kvl_remove(s3cKVL** head_ref, const char* name);


void s3c_reply_free(s3cReply*);


void s3c_kvl_free(s3cKVL*);


#ifdef __cplusplus
}
#endif








