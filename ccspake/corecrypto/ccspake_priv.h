/* Copyright (c) (2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSPAKE_PRIV_H_
#define _CORECRYPTO_CCSPAKE_PRIV_H_

/*
 The SPAKE2+ protocol state machine.

 An initialized context will always start at INIT.

 The two functions of the KEX and MAC phase may be called in arbitrary order.
 Both functions have to be called to be able to proceed to the next phase.

 Valid: INIT -> KEX_GENERATE -> KEX_PROCESS -> MAC_GENERATE
 Valid: INIT -> KEX_PROCESS -> KEX_GENERATE -> MAC_VERIFY

 NOT Valid: INIT -> KEX_GENERATE -> MAC_GENERATE

 The *_BOTH values of a phase are used as preconditions for the next.
 */
extern const uint8_t CCSPAKE_STATE_INIT;

extern const uint8_t CCSPAKE_STATE_KEX_GENERATE;
extern const uint8_t CCSPAKE_STATE_KEX_PROCESS;
extern const uint8_t CCSPAKE_STATE_KEX_BOTH;

extern const uint8_t CCSPAKE_STATE_MAC_GENERATE;
extern const uint8_t CCSPAKE_STATE_MAC_VERIFY;
extern const uint8_t CCSPAKE_STATE_MAC_BOTH;

#define CCSPAKE_STATE_NEQ(_st_) (ccspake_ctx_state(ctx) != CCSPAKE_STATE_##_st_)

#define CCSPAKE_EXPECT_STATE(_st_)  \
    if (CCSPAKE_STATE_NEQ(_st_)) {  \
        return CCERR_CALL_SEQUENCE; \
    }

#define CCSPAKE_EXPECT_STATES(_st_, _st2_)                     \
    if (CCSPAKE_STATE_NEQ(_st_) && CCSPAKE_STATE_NEQ(_st2_)) { \
        return CCERR_CALL_SEQUENCE;                            \
    }

#define CCSPAKE_ADD_STATE(_st_) ccspake_ctx_state(ctx) |= CCSPAKE_STATE_##_st_

#define ccspake_cp_decl_n(_n_) \
    struct {                   \
        ccec_const_cp_t cp;    \
        cc_unit mx[(_n_)];     \
        cc_unit my[(_n_)];     \
        cc_unit nx[(_n_)];     \
        cc_unit ny[(_n_)];     \
    }

struct ccspake_cp {
    ccec_const_cp_t cp;
    cc_unit ccn[];
} CC_ALIGNED(CCN_UNIT_SIZE);

#define ccspake_mac_decl(_name_)                                                                                    \
    struct _name_ {                                                                                                 \
        const struct ccdigest_info *di;                                                                             \
        const struct ccmode_cbc *cbc;                                                                               \
        int (*CC_SPTR(_name_, derive))(ccspake_const_ctx_t ctx, size_t ikm_len, const uint8_t *ikm, size_t keys_len, uint8_t *keys); \
        int (*CC_SPTR(_name_, compute))(ccspake_const_ctx_t ctx,                                                                     \
                       size_t key_len,                                                                              \
                       const uint8_t *key,                                                                          \
                       size_t info_len,                                                                             \
                       const uint8_t *info,                                                                         \
                       size_t t_len,                                                                                \
                       uint8_t *t);                                                                                 \
    }

ccspake_mac_decl(ccspake_mac);

#define ccspake_cp_decl(_bits_) ccspake_cp_decl_n(ccn_nof(_bits_))
#define ccspake_cp_ec(_cp_) (_cp_->cp)
#define ccspake_cp_ccn(_cp_) (_cp_->ccn)

#define ccspake_ctx_scp(ctx) (ctx->scp)
#define ccspake_ctx_cp(ctx) (ctx->scp->cp)
#define ccspake_ctx_mac(ctx) (ctx->mac)
#define ccspake_ctx_rng(ctx) (ctx->rng)
#define ccspake_ctx_aad_len(ctx) (ctx->aad_len)
#define ccspake_ctx_aad(ctx) (ctx->aad)
#define ccspake_ctx_is_prover(ctx) (ctx->is_prover)
#define ccspake_ctx_state(ctx) (ctx->state)
#define ccspake_ctx_MN(ctx, s) ((ccec_const_affine_point_t)(ctx->scp->ccn + ccec_cp_n(ctx->scp->cp) * 2 * (s)))

/*
 The SPAKE2+ protocol storage.

 We need to hold scalars, EC points, and shared keys.

 Each storage item takes the space of ccec_cp_n(cp) of the chosen curve.
 */
#define ccspake_ctx_ccn(ctx, n) (ctx->ccn + ccec_cp_n(ccspake_ctx_cp(ctx)) * n)

// w0 and w1
#define ccspake_ctx_w0(ctx) ccspake_ctx_ccn(ctx, 0)
#define ccspake_ctx_w1(ctx) ccspake_ctx_ccn(ctx, 1)
// The L part of the verifier.
#define ccspake_ctx_L(ctx) ccspake_ctx_ccn(ctx, 1)
#define ccspake_ctx_L_x(ctx) ccspake_ctx_ccn(ctx, 1)
#define ccspake_ctx_L_y(ctx) ccspake_ctx_ccn(ctx, 2)
// The scalar for our key share.
#define ccspake_ctx_xy(ctx) ccspake_ctx_ccn(ctx, 3)
// The public share for the KEX phase.
#define ccspake_ctx_XY(ctx) ccspake_ctx_ccn(ctx, 4)
#define ccspake_ctx_XY_x(ctx) ccspake_ctx_ccn(ctx, 4)
#define ccspake_ctx_XY_y(ctx) ccspake_ctx_ccn(ctx, 5)
// KDF inputs Q (Y or X), Z, and V.
#define ccspake_ctx_Q(ctx) ccspake_ctx_ccn(ctx, 6)
#define ccspake_ctx_Q_x(ctx) ccspake_ctx_ccn(ctx, 6)
#define ccspake_ctx_Q_y(ctx) ccspake_ctx_ccn(ctx, 7)
#define ccspake_ctx_Z(ctx) ccspake_ctx_ccn(ctx, 8)
#define ccspake_ctx_Z_x(ctx) ccspake_ctx_ccn(ctx, 8)
#define ccspake_ctx_Z_y(ctx) ccspake_ctx_ccn(ctx, 9)
#define ccspake_ctx_V(ctx) ccspake_ctx_ccn(ctx, 10)
#define ccspake_ctx_V_x(ctx) ccspake_ctx_ccn(ctx, 10)
#define ccspake_ctx_V_y(ctx) ccspake_ctx_ccn(ctx, 11)

/*! @function ccspake_cmp_pub_key
 @abstract Compares a public key to one in the internal storage

 @param pub The public key
 @param X   Pointer into the internal storage

 @return 0 on match, non-zero on mismatch.
 */
CC_NONNULL((1, 2))
int ccspake_cmp_pub_key(ccec_pub_ctx_t pub, const cc_unit *X);

/*! @function ccspake_import_pub
 @abstract Import a public share from a buffer

 @param pub   Target public key
 @param x_len Length of the public share
 @param x     Public share sent by the peer

 @return 0 on success, non-zero on failure. See cc_error.h for more details.
 */
CC_NONNULL((1, 3))
int ccspake_import_pub(ccec_pub_ctx_t pub, size_t x_len, const uint8_t *x);

/*! @function ccspake_store_pub_key
 @abstract Copy a public share into the internal storage

 @param pub  Public key to copy
 @param dest Pointer into the internal storage
 */
CC_NONNULL((1, 2))
void ccspake_store_pub_key(const ccec_pub_ctx_t pub, cc_unit *dest);

/*! @function ccspake_kdf_label_size
 @abstract Returns the size of the label used to derive MAC keys

 @param ctx SPAKE2+ context

 @return Size of the label
 */
CC_NONNULL((1))
size_t ccspake_kdf_label_size(ccspake_const_ctx_t ctx);

/*! @function ccspake_build_kdf_label
 @abstract Builds the label used to derive MAC keys

 @param ctx   SPAKE2+ context
 @param label Target buffer
 */
CC_NONNULL((1, 2))
void ccspake_build_kdf_label(ccspake_const_ctx_t ctx, uint8_t *label);

#endif /* _CORECRYPTO_CCSPAKE_PRIV_H_ */
