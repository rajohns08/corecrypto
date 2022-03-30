/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccdict.h"
#include "testbyteBuffer.h"
#include "cctestvector_parser.h"
#include "cctest_driver.h"
#include "crypto_test_chacha20poly1305_runner.h"

#include <corecrypto/ccchacha20poly1305.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

bool
crypto_test_chacha20poly1305_runner(ccdict_t vector)
{
    bool result = true;

#define EXTRACT_PARAMETER(NAME) \
    if (NAME##_buffer != NULL && NAME##_len > 0) { \
        NAME##_string = malloc(NAME##_len + 1); \
        memset(NAME##_string, 0, NAME##_len + 1); \
        memcpy(NAME##_string, NAME##_buffer, NAME##_len); \
        NAME = hexStringToBytes((const char *)NAME##_string); \
    } \

#define VALUE_TO_BUFFER(NAME, KEY) \
    size_t NAME##_len = 0; \
    const uint8_t *NAME##_buffer = ccdict_get_value(vector, KEY, &NAME##_len); \
    char *NAME##_string = NULL; \
    byteBuffer NAME = NULL; \
    EXTRACT_PARAMETER(NAME);

    VALUE_TO_BUFFER(id, cctestvector_key_id);
    VALUE_TO_BUFFER(iv, cctestvector_key_iv);
    VALUE_TO_BUFFER(key, cctestvector_key_key);
    VALUE_TO_BUFFER(tag, cctestvector_key_tag);
    VALUE_TO_BUFFER(aad, cctestvector_key_aad);
    VALUE_TO_BUFFER(msg, cctestvector_key_msg);
    VALUE_TO_BUFFER(expected_ct, cctestvector_key_ct);
    byteBuffer actual_ct = NULL;
    if (msg != NULL) {
        actual_ct = mallocByteBuffer(msg->len);
    }

    uint64_t value = ccdict_get_uint64(vector, cctestvector_key_valid);
    bool expected_failure = value == cctestvector_result_invalid;

    const struct ccchacha20poly1305_info *info = ccchacha20poly1305_info();
    ccchacha20poly1305_ctx context;
    uint8_t actual_tag[16];

    if (id == NULL || iv == NULL) {
        result = true;
        goto cleanup;
    }

    if (iv->len != CCCHACHA20_NONCE_NBYTES) {
        result = expected_failure;
        goto cleanup;
    }

    if (key == NULL || tag == NULL) {
        result = expected_failure;
        goto cleanup;
    }

    if (ccchacha20poly1305_init(info, &context, key->bytes)) {
        result = false;
        goto cleanup;
    }
    if (ccchacha20poly1305_setnonce(info, &context, iv->bytes)) {
        result = false;
        goto cleanup;
    }
    if (aad != NULL) {
        if (ccchacha20poly1305_aad(info, &context, aad->len, aad->bytes)) {
            result = false;
            goto cleanup;
        }
    }
    if (msg != NULL) {
        if (ccchacha20poly1305_encrypt(info, &context, msg->len, msg->bytes, actual_ct->bytes)) {
            result = false;
            goto cleanup;
        }
    }
    if (ccchacha20poly1305_finalize(info, &context, actual_tag)) {
        result = false;
        goto cleanup;
    }

    if (tag != NULL && tag->len != sizeof(actual_tag)) {
        // if invalid, then expected_result = true
        if (!expected_failure) {
            fprintf(stderr, "Test ID %s failed\n", id_string);
        }
        result = expected_failure;
    }
    if (result && cc_cmp_safe(sizeof(actual_tag), actual_tag, tag->bytes) != 0) {
        if (!expected_failure) {
            fprintf(stderr, "Test ID %s failed\n", id_string);
        }
        result = expected_failure;
    }
    if (result && expected_ct != NULL && actual_ct != NULL && expected_ct->len != actual_ct->len) {
        if (!expected_failure) {
            fprintf(stderr, "Test ID %s failed\n", id_string);
        }
        result = expected_failure;
    }
    if (result && expected_ct != NULL && actual_ct != NULL && expected_ct->len != 0) {
        if (cc_cmp_safe(expected_ct->len, expected_ct->bytes, actual_ct->bytes) != 0) {
            if (!expected_failure) {
                fprintf(stderr, "Test ID %s failed\n", id_string);
            }
            result = expected_failure;
        }
    }

#define RELEASE_BUFFER(BUFFER) \
    if (BUFFER) { \
        free(BUFFER); \
    } \
    if (BUFFER##_string) { \
        free(BUFFER##_string); \
    }

cleanup:
    RELEASE_BUFFER(id);
    RELEASE_BUFFER(iv);
    RELEASE_BUFFER(key);
    RELEASE_BUFFER(tag);
    RELEASE_BUFFER(msg);
    RELEASE_BUFFER(aad);
    RELEASE_BUFFER(expected_ct);
    free(actual_ct);

#undef RELEASE_BUFFER
#undef VALUE_TO_BUFFER
#undef VALIDATE_PARAMETE

    return result;
}
