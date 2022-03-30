/* Copyright (c) (2019,2020) Apple Inc. All rights reserved.
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
#include "crypto_test_primality_runner.h"
#include "cctest_utils.h"

#include <corecrypto/ccrng.h>
#include "ccprime_internal.h"

#define MR_DEPTH 16

static const char *skipped_wycheproof_tests[] = {
    // Skip prime candidates p, where p-1 has 64 or more trailing zero bits.
    // That's not a random prime candidate and will be rejected by our
    // constant-time Miller-Rabin implementation (for performance reasons).
    "220", "221", "222", "223", "224"
};
static const size_t skipped_wycheproof_tests_len = CC_ARRAY_LEN(skipped_wycheproof_tests);

bool crypto_test_primality_runner(ccdict_t vector)
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
        goto cleanup;                           \
    }

#define RELEASE_BUFFER(BUFFER) \
    free(BUFFER);              \
    free(BUFFER##_string);

    STRING_TO_BUFFER(id, cctestvector_key_id);
    HEX_VALUE_TO_BUFFER(value, cctestvector_key_value);

    cc_assert(id && value);

    for (size_t i = 0; i < skipped_wycheproof_tests_len; i++) {
        const char *test_id = skipped_wycheproof_tests[i];
        if (strlen(id_string) == strlen(test_id) && strncmp(test_id, id_string, strlen(test_id)) == 0) {
            RELEASE_BUFFER(id);
            RELEASE_BUFFER(value);
            return true;
        }
    }

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);
    uint64_t flags = ccdict_get_flags(vector, cctestvector_key_flags);

    int result_code = 0;

    struct ccrng_state *rng = ccrng(NULL);
    assert(rng);

    cc_size n = ccn_nof_size(value->len);
    cc_unit p[n];

    result_code = ccn_read_uint(n, p, value->len, value->bytes);
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == CCERR_OK, result, cleanup);

    result_code = ccprime_rabin_miller(n, p, MR_DEPTH, rng);
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 1, result, cleanup);

cleanup:
    // We don't accept negative numbers in primality tests.
    if (flags & wycheproof_flag_NegativeOfPrime) {
        // Mark as success, some of those negatives might be prime.
        result = true;
    }

    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(value);

#undef RELEASE_BUFFER
#undef HEX_VALUE_TO_BUFFER

    return result;
}

