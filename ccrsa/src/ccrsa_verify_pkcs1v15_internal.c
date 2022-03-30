/* Copyright (c) (2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

int ccrsa_verify_pkcs1v15_internal(ccrsa_pub_ctx_t key,
                                   const uint8_t *oid,
                                   size_t digest_len,
                                   const uint8_t *digest,
                                   size_t sig_len,
                                   const uint8_t *sig,
                                   int sig_len_validation,
                                   cc_fault_canary_t fault_canary_out)
{
    CC_FAULT_CANARY_CLEAR(fault_canary_out);

    size_t m_size = ccn_write_uint_size(ccrsa_ctx_n(key), ccrsa_ctx_m(key));
    cc_size n = ccrsa_ctx_n(key);
    cc_unit s[n]; // vla
    uint8_t *em = NULL;
    int err;
    int sig_len_valid;

    switch (sig_len_validation) {
    case CCRSA_SIG_LEN_VALIDATION_ALLOW_SHORT_SIGS:
        sig_len_valid = sig_len <= m_size;
        break;
    default:
        sig_len_valid = sig_len == m_size;
        break;
    }

    cc_require_action(sig_len_valid, errOut, err = CCRSA_INVALID_INPUT);

    // Public key operation
    cc_require_action(ccn_read_uint(n, s, sig_len, sig) == 0, errOut, err = CCRSA_INVALID_INPUT);

    cc_require((err = ccrsa_pub_crypt(key, s, s)) == 0, errOut);

    // Prepare data for encoding verification
    ccn_swap(n, s);
    em = (unsigned char *)s + (ccn_sizeof_n(n) - m_size);

    // Encoding verification
    err = ccrsa_emsa_pkcs1v15_verify_canary_out(m_size, em, digest_len, digest, oid, fault_canary_out);
    if (err == 0) {
        err = CCERR_VALID_SIGNATURE;
    } else {
        err = CCERR_INVALID_SIGNATURE;
    }

errOut:
    return err;
}
