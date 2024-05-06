#include "../src/s3c.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    if (argc < 3) {
        puts("usage: ./usage <access_key_id> <access_key_secret> <region>"
                             " [endpoint] [bucket]");

        return 0;
    }
    // Access keys and region configuration
    s3cKeys keys = {
        .access_key_id     = argv[1], // S3 Access Key ID
        .access_key_secret = argv[2], // S3 Secret Access Key
        .region            = argv[3], // Example: eu-west-1
        .endpoint          = NULL,    // Endpoint URL is optional and defaults to the
                                      // standard AWS form
    };
    // Set a sepcific endpoint if you want to use a custom S3-compatible service
    if (argc > 4) {
        keys.endpoint = argv[4]; // Example: <your-cf-id>.r2.cloudflarestorage.com
        printf("setting endpoint to %s\n", keys.endpoint);
    }

    char* s3_bucket = "s3c-usage-example";

    if (argc > 5) {
        s3_bucket = argv[5];
    }

    // First, create the bucket
    s3cReply* reply = s3c_create_bucket(&keys, s3_bucket);

    // An error will be returned if the bucket already exists
    if (reply->error != NULL) {
        printf("s3c_create_bucket failed with error => %s\n", reply->error);
    } else {
        printf("bucket %s created, http response code: %u\n",
                s3_bucket, (unsigned)reply->http_resp_code);
    }

    // Always free the reply to prevent memory leaks. Each API call generates a
    // new reply struct that must be managed
    s3c_reply_free(reply);

    const char* object_key = "fruits.txt";
    const char* content = "banana orange strawberry";

    // Put object with key "fruits.txt", any such object within the bucket will be overwritten
    reply = s3c_put_object(&keys, s3_bucket, object_key,
                          (const uint8_t*)content, strlen(content),
                           NULL);

    if (reply->error != NULL) {
        printf("s3c_put_object failed with error => %s\n", reply->error);
    } else {
        printf("object %s, http response code: %u\n",
                object_key, (unsigned)reply->http_resp_code);
    }

    s3c_reply_free(reply);

    // Headers like "content-type" can be passed via a list struct.
    // Passing headers is optional. "content-length" will be set automatically,
    // likewise "x-amzn-acl" will be set to "private" when no such header is provided.
    s3cHeader ct_header  = { "content-type", "text/plain", NULL };
    s3cHeader acl_header = { "x-amzn-acl", "bucket-owner-full-control", &ct_header };

    reply = s3c_put_object(&keys, s3_bucket, object_key,
                           (const uint8_t*)content, strlen(content),
                           &acl_header);

    if (reply->error != NULL) {
        printf("s3c_put_object with headers failed with error => %s\n", reply->error);
    }

    s3c_reply_free(reply);

    // Get fruits.txt
    reply = s3c_get_object(&keys, s3_bucket, object_key);

    if (reply->error != NULL) {
        printf("s3c_get_object failed with error => %s\n", reply->error);
    } else {
        // If successful (error == NULL) reply->data points to the content of the requested object
        // Note: reply->data is always terminated with an additional zero-byte
        printf("content for %s fetched, content size: %u content: %s\n",
               object_key, (unsigned)reply->data_size, (char*)reply->data);

        // Print reply headers
        puts("Reply headers:");
        for (s3cHeader* h = reply->headers; h != NULL; h = h->next) {
            printf("\t%s => %s\n", h->name, h->value);
        }
    }
    // Freeing the reply object also frees the reply data and headers
    s3c_reply_free(reply);

    // Delete fruits.txt
    reply = s3c_delete_object(&keys, s3_bucket, object_key);

    if (reply->error != NULL) {
        printf("s3c_delete_object failed with error => %s\n", reply->error);
    } else {
        printf("object %s deleted\n", object_key);
    }

    s3c_reply_free(reply);

    // Delete the bucket, this will fail if bucket is not empty
    reply = s3c_delete_bucket(&keys, s3_bucket);

    if (reply->error != NULL) {
        printf("s3c_delete_bucket failed with error => %s\n", reply->error);
    } else {
        printf("bucket %s deleted\n", s3_bucket);
    }

    s3c_reply_free(reply);

    return 0;
}
