/* Copyright (c) (2013,2014,2015,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#include <corecrypto/ccnistkdf.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cc.h>

/*

 From:

 NIST Special Publication 800-108
 Recommendation for Key Derivation
 Using Pseudorandom Functions

 http://csrc.nist.gov/publications/nistpubs/800-108/sp800-108.pdf
 Section 5.2
 KDF in Feedback Mode

 Fixed values:
 1. h - The length of the output of the PRF in bits, and
 2. r - The length of the binary representation of the counter i. r is specified only when a counter is used as an input.
 Input: KI, Label, Context, IV, and L.

 Process:
 1. n: = ⎡L/h⎤.
 2. If n > 232 -1, then indicate an error and stop.
 3. result(0):= ∅ and K(0):= IV.
 4. For i = 1 to n, do
    a. K(i) := PRF (KI, K(i-1) {|| [i]2 }|| Label || 0x00 || Context || [L]2)
    b. result(i) := result(i-1) || K(i)
 5. Return: KO := the leftmost L bits of result(n).

 Output: KO.
 In each iteration, the fixed input data is the string Label || 0x00 || Context || [L]2. The
 iteration variable is K(i-1){|| [i]2}.

 */

#include "ccnistkdf_priv.h"
/* This is still work in progress */
static void
F (const struct ccdigest_info *di, cchmac_ctx_t hc, const cc_unit *istate,
   size_t ivLen, const void *iv,
   size_t counter, size_t fixedDataLen, const void *fixedData, void *result) {
    cchmac_reset_from_cache(di, hc, istate);
    ccdigest_update(di, cchmac_digest_ctx(di, hc), ivLen, iv);
    if(counter) ccdigest_update_uint32_t(di, cchmac_digest_ctx(di, hc), (uint32_t) counter);
    ccdigest_update(di, cchmac_digest_ctx(di, hc), fixedDataLen, fixedData);
    cchmac_final(di, hc, result);
}

int ccnistkdf_fb_hmac_fixed(const struct ccdigest_info *di, int use_counter,
                      size_t kdkLen, const void *kdk,
                      size_t fixedDataLen, const void *fixedData,
                      size_t ivLen, const void *iv,
                      size_t dkLen, void *dk) {
    if(dkLen == 0) return CCERR_PARAMETER;
    size_t h = di->output_size;
    
    size_t completeBlocks = dkLen / h;
    size_t partialBlock_nbytes = dkLen % h;
    size_t evaluatedBlocks = (partialBlock_nbytes > 0) ? (completeBlocks + 1) : completeBlocks;
    
    uint8_t lastBlockBuf[h];
    uint8_t *result = dk;
    const uint8_t *iv_local = iv;
    size_t iv_local_len = ivLen;

    if(evaluatedBlocks > UINT32_MAX) return CCERR_PARAMETER;
    if(kdkLen == 0 || kdk == NULL) return CCERR_PARAMETER;
    if(dkLen == 0 || dk == NULL) return CCERR_PARAMETER;

    use_counter = (use_counter) ? 1: 0;

    cchmac_di_decl(di, hc);
    cchmac_state_cache(di, istate);
    cchmac_init(di, hc, kdkLen, kdk);
    cchmac_cache_state(di, hc, istate);

    for(size_t i = 1; i <= completeBlocks; i++, result += h) {
        F(di, hc, istate, iv_local_len, iv_local, i*(size_t)use_counter, fixedDataLen, fixedData, result);
        iv_local = result;
        iv_local_len = h;
    }
    
    if (partialBlock_nbytes > 0) {
        F(di, hc, istate, iv_local_len, iv_local, evaluatedBlocks*(size_t)use_counter, fixedDataLen, fixedData, lastBlockBuf);
        cc_memcpy(result, lastBlockBuf, partialBlock_nbytes);
    }

    cc_clear(h, lastBlockBuf);
	cchmac_di_clear(di, hc);
	cc_clear(di->state_size, istate);

    return 0;
}

int ccnistkdf_fb_hmac(const struct ccdigest_info *di, int use_counter,
                      size_t kdkLen, const void *kdk,
                      size_t labelLen, const void *label,
                      size_t contextLen, const void *context,
                      size_t ivLen, const void *iv,
                      size_t dkLen, void *dk) {
    size_t fixedDataLen = labelLen + contextLen + 5;
    uint8_t fixedData[fixedDataLen];
    construct_fixed_data(labelLen, label, contextLen, context, dkLen, 4,fixedData);
    int retval = ccnistkdf_fb_hmac_fixed(di, use_counter, kdkLen, kdk, fixedDataLen, fixedData, ivLen, iv, dkLen, dk);
    cc_clear(fixedDataLen,fixedData);
    return retval;
}
