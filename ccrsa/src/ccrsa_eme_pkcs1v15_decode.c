/* Copyright (c) (2011,2013,2014,2015,2016,2019,2020) Apple Inc. All rights reserved.
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

/*
 The s_size argument is really meant to be a size_t rather than a cc_size.  It's the size
 in bytes of the key for which this decoding is being done.  's' on the other hand is a
 cc_unit array large enough to contain the blocksize of the key.  We need to start the
 decoding "right justified" within s for s_size bytes.
 */

int ccrsa_eme_pkcs1v15_decode(size_t *r_size, uint8_t *r,
                              size_t s_size, cc_unit *s)
{
    ccn_swap(ccrsa_n_from_size(s_size), s);
    uint8_t *in = ccrsa_block_start(s_size, s, 0);
    size_t padlen, inlen = s_size;
    int retval = 0;

    // Expected structure is
    // 00:02:PS:00:Msg

    // -- Check for expected prefix 00:02
    CC_HEAVISIDE_STEP(retval, in[0] | (in[1] ^ 0x02));

    size_t zero_idx = 0;
    uint8_t looking_for_zero = 1;

    // Encoding must be PS || 0x00 || M.
    // Find the position of the 0x00 marker in constant-time.
    for (size_t i = 2; i < inlen; i++) {
        uint8_t is_not_zero;
        CC_HEAVISIDE_STEP(is_not_zero, in[i]);

        // Update zero_idx until we hit 0x00.
        CC_MUXU(zero_idx, looking_for_zero, i, zero_idx);

        looking_for_zero &= is_not_zero;
    }

    // Fail if we found no 0x00 marker.
    retval |= looking_for_zero;

    // Compute the padding length
    size_t mlen = inlen - zero_idx - 1;
    padlen = inlen - mlen - 3;

    // -- Check (padlen < 8)
    uint8_t is_gt7;
    CC_HEAVISIDE_STEP(is_gt7, padlen >> 3);
    retval |= is_gt7 ^ 1;

    if (retval) {
        goto decode_err;
    }

    if (*r_size < mlen) {
        retval = CCRSA_INVALID_INPUT;
        goto param_err;
    }

    memcpy(r, in + zero_idx + 1, mlen);
    *r_size = mlen;

decode_err:
    if (retval) {
        retval = CCRSA_PRIVATE_OP_ERROR;
    }

param_err:
    // Revert to the original formatting.
    ccn_swap(ccrsa_n_from_size(s_size), s);

    return retval;
}
