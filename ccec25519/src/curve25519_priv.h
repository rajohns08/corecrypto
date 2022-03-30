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
#ifndef _CORECRYPTO_CURVE25519_PRIV_H_
#define _CORECRYPTO_CURVE25519_PRIV_H_

#include <corecrypto/ccec25519.h>

#if CCEC25519_CURVE25519_64BIT

typedef uint64_t limb;
typedef uint64_t rlimb;
typedef unsigned uint128_t __attribute__((mode(TI)));

#define NLIMBS 5
#define NLIMBS_BIG 5

#else // CCEC25519_CURVE25519_64BIT

typedef int64_t limb;
typedef int32_t rlimb;

#define NLIMBS 10
#define NLIMBS_BIG 19

#endif // !CCEC25519_CURVE25519_64BIT

/*!
    @function   cccurve25519_internal
    @abstract   Scalar multiplication on Curve25519.

    @param      out  Output shared secret or public key.
    @param      sk   Input secret key.
    @param      base Input basepoint (for computing a shared secret)
                     or NULL (for computing a public key).
    @param      rng  RNG for masking and/or randomization.
 */
CC_NONNULL((1, 2, 4))
int cccurve25519_internal(ccec25519key out,
                          const ccec25519secretkey sk,
                          const ccec25519base base,
                          struct ccrng_state *rng);

/* Operations on group elements. */

CC_NONNULL_ALL void fsum(limb *output, const limb *a, const limb *b);
CC_NONNULL_ALL void fdiff(limb *out, const limb *a, const limb *b);
CC_NONNULL_ALL void fexpand(limb *output, const uint8_t *input);
CC_NONNULL_ALL void fcontract(uint8_t *output, const limb *input);
CC_NONNULL_ALL void fsquare_times(limb *output, const limb *in, limb count);
CC_NONNULL_ALL void fmul(limb *output, const limb *in2, const limb *in);
CC_NONNULL_ALL void fmul_121666(limb *output, const limb *in);

#endif /* _CORECRYPTO_CURVE25519_PRIV_H_ */
