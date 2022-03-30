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

#ifndef cctest_utils_h
#define cctest_utils_h

#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

#define CC_WYCHEPROOF_CHECK_OP_RESULT(_opresult_, _result_, _label_) \
    do {                                                             \
        if (!(_opresult_)) {                                         \
            _result_ = false;                                        \
            goto _label_;                                            \
        } else {                                                     \
            _result_ = true;                                         \
        }                                                            \
    } while (0)

CC_INLINE CC_NONNULL_ALL
const struct ccdigest_info* cctest_parse_digest(const byteBuffer sha)
{
    if (memcmp(sha->bytes, "SHA-1", 5) == 0) {
        return ccsha1_di();
    }

    if (memcmp(sha->bytes, "SHA-224", 7) == 0) {
        return ccsha224_di();
    }

    if (memcmp(sha->bytes, "SHA-256", 7) == 0) {
        return ccsha256_di();
    }

    if (memcmp(sha->bytes, "SHA-384", 7) == 0) {
        return ccsha384_di();
    }

    if (memcmp(sha->bytes, "SHA-512", 7) == 0) {
        return ccsha512_di();
    }

    return NULL;
}

#endif /* cctest_utils_h */
