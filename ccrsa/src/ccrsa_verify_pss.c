/* Copyright (c) (2015,2016,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

int ccrsa_verify_pss_digest(ccrsa_pub_ctx_t key,
                            const struct ccdigest_info *di,
                            const struct ccdigest_info *mgfdi,
                            size_t digestSize,
                            const uint8_t *digest,
                            size_t sigSize,
                            const uint8_t *sig,
                            size_t saltSize,
                            cc_fault_canary_t fault_canary_out)
{
    if (fault_canary_out) {
        CC_FAULT_CANARY_CLEAR(fault_canary_out);
    }
    cc_fault_canary_t fault_canary;
    CC_FAULT_CANARY_CLEAR(fault_canary);

    const cc_size modBits = ccn_bitlen(ccrsa_ctx_n(key), ccrsa_ctx_m(key));
    const cc_size modBytes = cc_ceiling(modBits, 8);
    const cc_size emBits = modBits - 1; // as defined in §8.1.1
    const cc_size emSize = cc_ceiling(emBits, 8);
    int rc = 0;

    // 1.
    if (modBytes != sigSize)
        return CCRSA_INVALID_INPUT;
    if (digestSize != di->output_size)
        return CCRSA_INVALID_INPUT;
    if (modBytes == 0)
        return CCRSA_KEY_ERROR;

    // 2.
    const cc_size modWords = ccrsa_ctx_n(key);
    // EM islarge enough to fit sig variable
    cc_unit EM[modWords]; // vla

    // 2.a read sig to tmp array and make sure it fits
    cc_require_action(ccn_read_uint(modWords, EM, sigSize, sig) == 0, errOut, rc = CCRSA_INVALID_INPUT);

    // 2.b
    cc_require((rc = ccrsa_pub_crypt(key, EM, EM)) == 0, errOut);

    // 2.c
    ccn_swap(modWords, EM);

    // 3
    const size_t ofs = modWords * sizeof(cc_unit) - emSize;
    cc_assert(ofs <= sizeof(cc_unit)); // make sure sizes are consistent and we don't overrun buffers.
    rc |= ccrsa_emsa_pss_decode_canary_out(di, mgfdi, saltSize, digestSize, digest, emBits, (uint8_t *)EM + ofs, fault_canary);

    if (rc == 0) {
        rc = CCERR_VALID_SIGNATURE;
    } else {
        rc = CCERR_INVALID_SIGNATURE;
    }

    if (fault_canary_out) {
        CC_FAULT_CANARY_MEMCPY(fault_canary_out, fault_canary);
    }

errOut:
    return rc;
}

int ccrsa_verify_pss_msg(ccrsa_pub_ctx_t key,
                         const struct ccdigest_info *di,
                         const struct ccdigest_info *mgfdi,
                         size_t msg_nbytes,
                         const uint8_t *msg,
                         size_t sig_nbytes,
                         const uint8_t *sig,
                         size_t salt_nbytes,
                         cc_fault_canary_t fault_canary_out)
{
    uint8_t digest[di->output_size];
    ccdigest(di, msg_nbytes, msg, digest);
    return ccrsa_verify_pss_digest(key, di, mgfdi, di->output_size, digest, sig_nbytes, sig, salt_nbytes, fault_canary_out);
}

// verify the signature in sig. The original (hash of the message) message is in digest
int ccrsa_verify_pss(ccrsa_pub_ctx_t key,
                     const struct ccdigest_info *di,
                     const struct ccdigest_info *MgfDi,
                     size_t digestSize,
                     const uint8_t *digest,
                     size_t sigSize,
                     const uint8_t *sig,
                     size_t saltSize,
                     bool *valid)
{
    *valid = false;
    int status = ccrsa_verify_pss_digest(key, di, MgfDi, digestSize, digest, sigSize, sig, saltSize, NULL);

    // Backwards compatibility
    if (status == CCERR_VALID_SIGNATURE) {
        *valid = true;
        status = CCERR_OK;
    }
    return status;
}
