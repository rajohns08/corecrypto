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
#ifndef _CORECRYPTO_CCSPAKE_H_
#define _CORECRYPTO_CCSPAKE_H_

#include <corecrypto/ccec.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>

/*
 * The CoreCrypto SPAKE2+ API.
 *
 * <https://tools.ietf.org/html/draft-irtf-cfrg-spake2-06>
 */

struct ccspake_ctx;
typedef struct ccspake_ctx *ccspake_ctx_t;
typedef const struct ccspake_ctx *ccspake_const_ctx_t;

struct ccspake_cp;
typedef const struct ccspake_cp *ccspake_const_cp_t;

CC_CONST ccspake_const_cp_t ccspake_cp_256(void);
CC_CONST ccspake_const_cp_t ccspake_cp_384(void);
CC_CONST ccspake_const_cp_t ccspake_cp_521(void);

struct ccspake_mac;
typedef const struct ccspake_mac *ccspake_const_mac_t;

CC_CONST ccspake_const_mac_t ccspake_mac_hkdf_cmac_aes128_sha256(void);
CC_CONST ccspake_const_mac_t ccspake_mac_hkdf_hmac_sha256(void);
CC_CONST ccspake_const_mac_t ccspake_mac_hkdf_hmac_sha512(void);

typedef uint8_t ccspake_state_t;

struct ccspake_ctx {
    ccspake_const_cp_t scp;
    ccspake_const_mac_t mac;
    struct ccrng_state *rng;
    bool is_prover;
    size_t aad_len;
    const uint8_t *aad;
    ccspake_state_t state;
    CC_ALIGNED(CCN_UNIT_SIZE) cc_unit ccn[];
};

/*! @function ccspake_sizeof_ctx
 @abstract Returns the size of a SPAKE2+ context

 @param cp SPAKE2+ curve parameters

 @return Size of a SPAKE2+ context
 */
CC_NONNULL((1))
size_t ccspake_sizeof_ctx(ccspake_const_cp_t cp);

/*! @function ccspake_sizeof_w
 @abstract Returns the size of scalars w0/w1

 @param cp SPAKE2+ curve parameters

 @return Size of w0/w1
 */
CC_NONNULL((1))
size_t ccspake_sizeof_w(ccspake_const_cp_t cp);

/*! @function ccspake_sizeof_point
 @abstract Returns the size of public shares transmitted between peers

 @param cp EC curve parameters

 @return Size of a public share
 */
CC_NONNULL((1))
size_t ccspake_sizeof_point(ccspake_const_cp_t cp);

#define ccspake_ctx_decl(_cp_, _name_) cc_ctx_decl(struct ccspake_ctx, ccspake_sizeof_ctx(_cp_), _name_)
#define ccspake_ctx_clear(_cp_, _name_) cc_clear(ccspake_sizeof_ctx(_cp_), _name_)

/*! @function ccspake_generate_L
 @abstract Generate the L-part of a verifier from w1

 @param cp     SPAKE2+ curve parameters
 @param w1_len Length of scalars w1
 @param w1     Scalar w1, first part of the verifier
 @param L_len  Length of L
 @param L      L, second part of the verifier
 @param rng    RNG state

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3, 5, 6))
int ccspake_generate_L(ccspake_const_cp_t cp,
                       size_t w1_len,
                       const uint8_t *w1,
                       size_t L_len,
                       uint8_t *L,
                       struct ccrng_state *rng);

/*! @function ccspake_prover_init
 @abstract Initialize a SPAKE2+ prover context

 @param ctx     SPAKE2+ context
 @param scp      SPAKE2+ curve parameters
 @param mac     MAC parameters
 @param rng     RNG state
 @param aad_len Length of the additional authenticated data
 @param aad     Pointer to additional authenticated data. Needs to remain valid until the MAC values have been generated and verified.
 @param w_len   Length of the scalars w0/w1
 @param w0      Scalar w0
 @param w1      Scalar w1

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 4, 8, 9))
int ccspake_prover_init(ccspake_ctx_t ctx,
                        ccspake_const_cp_t scp,
                        ccspake_const_mac_t mac,
                        struct ccrng_state *rng,
                        size_t aad_len,
                        const uint8_t *aad,
                        size_t w_len,
                        const uint8_t *w0,
                        const uint8_t *w1);

/*! @function ccspake_verifier_init
 @abstract Initialize a SPAKE2+ verifier context

 @param ctx    SPAKE2+ context
 @param scp     SPAKE2+ curve parameters
 @param mac    MAC parameters
 @param rng    RNG state
 @param w0_len Length of scalar w0
 @param w0     Scalar w0, first part of the verifier
 @param L_len  Length of L
 @param L      L, second part of the verifier

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 2, 3, 4, 8, 10))
int ccspake_verifier_init(ccspake_ctx_t ctx,
                          ccspake_const_cp_t scp,
                          ccspake_const_mac_t mac,
                          struct ccrng_state *rng,
                          size_t aad_len,
                          const uint8_t *aad,
                          size_t w0_len,
                          const uint8_t *w0,
                          size_t L_len,
                          const uint8_t *L);

/*! @function ccspake_kex_generate
 @abstract Generate a public share for key exchange

 @param ctx   SPAKE2+ context
 @param x_len Length of the X buffer (MUST be equal to ccspake_sizeof_point(ctx))
 @param x     Output buffer for the public share

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3))
int ccspake_kex_generate(ccspake_ctx_t ctx, size_t x_len, uint8_t *x);

/*! @function ccspake_kex_process
 @abstract Process a public share for key exchange

 @param ctx   SPAKE2+ context
 @param y_len Length of the Y buffer (MUST be equal to ccspake_sizeof_point(ctx))
 @param y     Public share sent by the peer

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3))
int ccspake_kex_process(ccspake_ctx_t ctx, size_t y_len, const uint8_t *y);

/*! @function ccspake_mac_compute
 @abstract Generate a MAC for key confirmation. If additional authenticated data was passed to the initializer, the passed pointer still needs to be valid.

 @param ctx   SPAKE2+ context
 @param t_len Desired length of the MAC
 @param t     Output buffer for the MAC

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3))
int ccspake_mac_compute(ccspake_ctx_t ctx, size_t t_len, uint8_t *t);

/*! @function ccspake_mac_verify_and_get_session_key
 @abstract Verify a MAC to confirm and derive the shared key. If additional authenticated data was passed to the initializer, the passed pointer still needs to be valid.

 @param ctx    SPAKE2+ context
 @param t_len  Length of the MAC
 @param t      MAC sent by the peer
 @param sk_len Desired length of the shared key
 @param sk     Output buffer for the shared key

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3, 5))
int ccspake_mac_verify_and_get_session_key(ccspake_ctx_t ctx, size_t t_len, const uint8_t *t, size_t sk_len, uint8_t *sk);

#endif /* _CORECRYPTO_CCSPAKE_H_ */
