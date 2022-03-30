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
#include "crypto_test_eddsa_runner.h"
#include "cctest_utils.h"

#include <corecrypto/ccsha2.h>
#include <corecrypto/ccec25519.h>
#include "cced25519_priv.h"

bool crypto_test_eddsa_runner(ccdict_t vector)
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

#define RELEASE_BUFFER(BUFFER) \
    free(BUFFER);              \
    free(BUFFER##_string);

    STRING_TO_BUFFER(id, cctestvector_key_id);
    STRING_TO_BUFFER(curve, cctestvector_key_curve);
    HEX_VALUE_TO_BUFFER(pk, cctestvector_key_pk);
    HEX_VALUE_TO_BUFFER(sk, cctestvector_key_sk);
    HEX_VALUE_TO_BUFFER(msg, cctestvector_key_msg);
    HEX_VALUE_TO_BUFFER(signature, cctestvector_key_signature);

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);

    if (curve == NULL || id == NULL || signature == NULL || signature->len != 64 || pk == NULL || sk == NULL) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(pk);
        RELEASE_BUFFER(sk);
        RELEASE_BUFFER(msg);
        RELEASE_BUFFER(signature);
        return true;
    }

    if (strlen("edwards25519") != curve->len || memcmp(curve->bytes, "edwards25519", curve->len)) {
        RELEASE_BUFFER(id);
        RELEASE_BUFFER(curve);
        RELEASE_BUFFER(pk);
        RELEASE_BUFFER(sk);
        RELEASE_BUFFER(msg);
        RELEASE_BUFFER(signature);
        return true;
    }

    struct ccrng_state *rng = ccrng(NULL);
    const struct ccdigest_info *di = ccsha512_di();

    uint8_t zero[] = {}; // Avoid "null pointer passed to nonnull parameter" warnings.
    uint8_t *msg_bytes = msg ? msg->bytes : zero;
    size_t msg_bytes_len = msg ? msg->len : 0;

    // Verify the signature.
    int rc = cced25519_verify(di, msg_bytes_len, msg_bytes, signature->bytes, pk->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup);

    // Re-create the deterministic signature.
    uint8_t sig[64];
    rc = cced25519_sign_deterministic(di, sig, msg_bytes_len, msg_bytes, pk->bytes, sk->bytes, rng);
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup_req);

    rc = memcmp(sig, signature->bytes, sizeof(sig));
    CC_WYCHEPROOF_CHECK_OP_RESULT(rc == 0, result, cleanup_req);

cleanup:
    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

cleanup_req:
    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(curve);
    RELEASE_BUFFER(pk);
    RELEASE_BUFFER(sk);
    RELEASE_BUFFER(msg);
    RELEASE_BUFFER(signature);

    return result;
}

