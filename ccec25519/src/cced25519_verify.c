/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/*
    Based on reference code from <http://ed25519.cr.yp.to/> and <http://bench.cr.yp.to/supercop.html>.
*/

#include <stdbool.h>
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng.h>
#include "cced25519_priv.h"
#include "cc_macros.h"

const uint8_t kCurve25519Order[] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static bool is_valid_scalar(const uint8_t s[32])
{
    unsigned i;

    // Find the most-significant byte different from the order.
    for (i = 31; i > 0 && s[i] == kCurve25519Order[i]; i--);

    return s[i] < kCurve25519Order[i];
}

int cced25519_verify(const struct ccdigest_info *di,
                     size_t mlen,
                     const void *inMsg,
                     const ccec25519signature sig,
                     const ccec25519pubkey pk)
{
    int rc = -1;
    const uint8_t *const m = (const uint8_t *)inMsg;
    ccdigest_di_decl(di, dc);
    uint8_t h[64];
    uint8_t checkr[32];
    ge_p3 A;
    ge_p2 R;

    ASSERT_DIGEST_SIZE(di);
    if (ge_frombytes_negate_vartime(&A, pk) != 0) {
        return -1;
    }

    ccdigest_init(di, dc);
    ccdigest_update(di, dc, 32, sig);
    ccdigest_update(di, dc, 32, pk);
    ccdigest_update(di, dc, mlen, m);
    ccdigest_final(di, dc, h);
    ccdigest_di_clear(di, dc);
    sc_reduce(h);

    // <https://tools.ietf.org/html/rfc8032#section-5.1.7>
    // S must be in range [0, q) to prevent malleability.
    cc_require(is_valid_scalar(sig + 32), errOut);

    cc_require((rc = ge_double_scalarmult_vartime(&R, h, &A, sig + 32)) == 0, errOut);

    ge_tobytes(checkr, &R);
    return crypto_verify_32(checkr, sig);
errOut:
    return rc;
}
