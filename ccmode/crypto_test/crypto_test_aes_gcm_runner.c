/* Copyright (c) (2018-2020) Apple Inc. All rights reserved.
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
#include "crypto_test_aes_gcm_runner.h"
#include "cctest_utils.h"

#include <corecrypto/ccmode.h>

bool
crypto_test_aes_gcm_runner(ccdict_t vector)
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

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);

    uint8_t actual_tag[16];
    const struct ccmode_gcm *mode = ccaes_gcm_encrypt_mode();
    ccgcm_ctx_decl(ccgcm_context_size(mode), context);

    if (id == NULL) {
        result = false;
        goto cleanup;
    }
    
    if (key == NULL || tag == NULL) {
        result = false;
        goto cleanup;
    }
    
    if (iv == NULL) {
        // Provide an IV of size zero in this case
        iv = hexStringToBytes(NULL);
    }
    
    int rc = ccgcm_init(mode, context, key->len, key->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);
    
    rc = ccgcm_set_iv(mode, context, iv->len, iv->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);
    
    if (aad != NULL) {
        rc = ccgcm_aad(mode, context, aad->len, aad->bytes);
        CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);
    }
    
    if (msg != NULL) {
        rc = ccgcm_update(mode, context, msg->len, msg->bytes, actual_ct->bytes);
        CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);
    }
    
    rc = ccgcm_finalize(mode, context, tag->len, actual_tag);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);
    
    CC_WYCHEPROOF_CHECK_OP_RESULT(cc_cmp_safe(tag->len, actual_tag, tag->bytes) == 0, result, cleanup);
    
    if (expected_ct != NULL && actual_ct != NULL) {
        CC_WYCHEPROOF_CHECK_OP_RESULT(expected_ct->len == actual_ct->len, result, cleanup);
        CC_WYCHEPROOF_CHECK_OP_RESULT(cc_cmp_safe(expected_ct->len, expected_ct->bytes, actual_ct->bytes) == 0, result, cleanup);
    }

#define RELEASE_BUFFER(BUFFER) \
    if (BUFFER) { \
        free(BUFFER); \
    } \
    if (BUFFER##_string) { \
        free(BUFFER##_string); \
    }

cleanup:
    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }
    
    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }
    
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
