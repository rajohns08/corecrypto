/* Copyright (c) (2019) Apple Inc. All rights reserved.
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
#include "cctest_driver.h"
#include "cctestvector_parser.h"
#include "crypto_test_x25519_runner.h"
#include "cctest_utils.h"

#include <corecrypto/ccsha2.h>
#include <corecrypto/ccec25519.h>
#include "cced25519_priv.h"

bool crypto_test_x25519_runner(ccdict_t vector)
{
    bool result = true;

#define EXTRACT_HEX_STRING_PARAMETER(NAME)                    \
    if (NAME##_buffer != NULL && NAME##_len > 0) {            \
        NAME##_string = malloc(NAME##_len + 1);               \
        memset(NAME##_string, 0, NAME##_len + 1);             \
        memcpy(NAME##_string, NAME##_buffer, NAME##_len);     \
        NAME = hexStringToBytes((const char *)NAME##_string); \
    }

#define EXTRACT_STRING_PARAMETER(NAME)                    \
    if (NAME##_buffer != NULL && NAME##_len > 0) {        \
        NAME##_string = malloc(NAME##_len + 1);           \
        memset(NAME##_string, 0, NAME##_len + 1);         \
        memcpy(NAME##_string, NAME##_buffer, NAME##_len); \
        NAME = bytesToBytes(NAME##_buffer, NAME##_len);   \
    }

#define HEX_VALUE_TO_BUFFER(NAME, KEY)                                         \
    size_t NAME##_len = 0;                                                     \
    const uint8_t *NAME##_buffer = ccdict_get_value(vector, KEY, &NAME##_len); \
    char *NAME##_string = NULL;                                                \
    byteBuffer NAME = NULL;                                                    \
    EXTRACT_HEX_STRING_PARAMETER(NAME);

#define STRING_TO_BUFFER(NAME, KEY)                                            \
    size_t NAME##_len = 0;                                                     \
    const uint8_t *NAME##_buffer = ccdict_get_value(vector, KEY, &NAME##_len); \
    char *NAME##_string = NULL;                                                \
    byteBuffer NAME = NULL;                                                    \
    EXTRACT_STRING_PARAMETER(NAME);

#define HEX_VALUE_TO_BUFFER_REQUIRED(NAME, KEY) \
    HEX_VALUE_TO_BUFFER(NAME, KEY);             \
    if (NAME == NULL) {                         \
        return false;                           \
    }

#define RELEASE_BUFFER(BUFFER) \
    free(BUFFER);              \
    free(BUFFER##_string);

    STRING_TO_BUFFER(id, cctestvector_key_id);
    STRING_TO_BUFFER(curve, cctestvector_key_curve);
    HEX_VALUE_TO_BUFFER(public, cctestvector_key_public);
    HEX_VALUE_TO_BUFFER(private, cctestvector_key_private);
    HEX_VALUE_TO_BUFFER(shared, cctestvector_key_shared);

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);

    if (curve == NULL || public == NULL || private == NULL || shared == NULL) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(public);
        RELEASE_BUFFER(private);
        RELEASE_BUFFER(shared);
        return true;
    }

    if (strlen("curve25519") != curve->len || memcmp(curve->bytes, "curve25519", curve->len)) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(public);
        RELEASE_BUFFER(private);
        RELEASE_BUFFER(shared);
        return true;
    }

    uint8_t out[32];
    cccurve25519(out, private->bytes, public->bytes);

    int rc = memcmp(out, shared->bytes, sizeof(out));
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);

cleanup:
    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(curve);
    RELEASE_BUFFER(public);
    RELEASE_BUFFER(private);
    RELEASE_BUFFER(shared);

    return result;
}

