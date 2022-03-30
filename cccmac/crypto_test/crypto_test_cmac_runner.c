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
#include "crypto_test_cmac_runner.h"
#include "cctest_utils.h"

#include <corecrypto/cccmac.h>

bool crypto_test_cmac_runner(ccdict_t vector)
{
    bool result = true;

#define EXTRACT_PARAMETER(NAME)                               \
    if (NAME##_buffer != NULL && NAME##_len > 0) {            \
        NAME##_string = malloc(NAME##_len + 1);               \
        memset(NAME##_string, 0, NAME##_len + 1);             \
        memcpy(NAME##_string, NAME##_buffer, NAME##_len);     \
        NAME = hexStringToBytes((const char *)NAME##_string); \
    }

#define VALUE_TO_BUFFER(NAME, KEY)                                             \
    size_t NAME##_len = 0;                                                     \
    const uint8_t *NAME##_buffer = ccdict_get_value(vector, KEY, &NAME##_len); \
    char *NAME##_string = NULL;                                                \
    byteBuffer NAME = NULL;                                                    \
    EXTRACT_PARAMETER(NAME);

    VALUE_TO_BUFFER(id, cctestvector_key_id);
    VALUE_TO_BUFFER(key, cctestvector_key_key);
    VALUE_TO_BUFFER(tag, cctestvector_key_tag);
    VALUE_TO_BUFFER(msg, cctestvector_key_msg);

    uint64_t test_result = ccdict_get_uint64(vector, cctestvector_key_valid);

    uint8_t actual_answer[CMAC_BLOCKSIZE];

    const struct ccmode_cbc *mode = ccaes_cbc_encrypt_mode();

    if (id == NULL) {
        result = false;
        goto cleanup;
    }

    int result_code = cccmac_one_shot_generate(mode,
                                               key ? key->len : 0,
                                               key ? key->bytes : NULL,
                                               msg ? msg->len : 0,
                                               msg ? msg->bytes : NULL,
                                               tag ? tag->len : 0,
                                               actual_answer);
    CC_WYCHEPROOF_CHECK_OP_RESULT(result_code == 0, result, cleanup);
    CC_WYCHEPROOF_CHECK_OP_RESULT(tag == NULL || cc_cmp_safe(tag->len, actual_answer, tag->bytes) == 0, result, cleanup);

cleanup:
    if (test_result == cctestvector_result_invalid) {
        result = !result;
    }

    if (!result) {
        fprintf(stderr, "Test ID %s failed\n", id_string);
    }

#define RELEASE_BUFFER(BUFFER) \
    free(BUFFER);              \
    free(BUFFER##_string);

    RELEASE_BUFFER(id);
    RELEASE_BUFFER(key);
    RELEASE_BUFFER(tag);
    RELEASE_BUFFER(msg);

#undef RELEASE_BUFFER
#undef VALUE_TO_BUFFER
#undef VALIDATE_PARAMETE

    return result;
}
