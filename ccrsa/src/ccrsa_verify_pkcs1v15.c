/* Copyright (c) (2011,2012,2014,2015,2016,2018,2019,2020) Apple Inc. All rights reserved.
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

int ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key,
                          const uint8_t *oid,
                          size_t digest_len,
                          const uint8_t *digest,
                          size_t sig_len,
                          const uint8_t *sig,
                          bool *valid)
{
    *valid = false;
    int status = ccrsa_verify_pkcs1v15_digest(key, oid, digest_len, digest, sig_len, sig, NULL);

    // Backwards compatibility
    if (status == CCERR_VALID_SIGNATURE) {
        *valid = true;
        status = CCERR_OK;
    } else if (status == CCERR_INVALID_SIGNATURE) {
        status = CCERR_OK;
    }

    return status;
}

int ccrsa_verify_pkcs1v15_digest(ccrsa_pub_ctx_t key,
                                 const uint8_t *oid,
                                 size_t digest_len,
                                 const uint8_t *digest,
                                 size_t sig_len,
                                 const uint8_t *sig,
                                 cc_fault_canary_t fault_canary_out)
{
    if (fault_canary_out) {
        CC_FAULT_CANARY_CLEAR(fault_canary_out);
    }

    cc_fault_canary_t fault_canary;
    CC_FAULT_CANARY_CLEAR(fault_canary);

    int res =
        ccrsa_verify_pkcs1v15_internal(key, oid, digest_len, digest, sig_len, sig, CCRSA_SIG_LEN_VALIDATION_STRICT, fault_canary);
    if (fault_canary_out) {
        CC_FAULT_CANARY_MEMCPY(fault_canary_out, fault_canary);
    }
    return res;
}

int ccrsa_verify_pkcs1v15_msg(ccrsa_pub_ctx_t key,
                              const struct ccdigest_info *di,
                              size_t msg_len,
                              const uint8_t *msg,
                              size_t sig_len,
                              const uint8_t *sig,
                              cc_fault_canary_t fault_canary_out)
{
    uint8_t digest[di->output_size];
    ccdigest(di, msg_len, msg, digest);

    return ccrsa_verify_pkcs1v15_digest(key, di->oid, di->output_size, digest, sig_len, sig, fault_canary_out);
}
