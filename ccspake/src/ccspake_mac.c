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
#include <corecrypto/ccspake.h>
#include "ccspake_priv.h"
#include "cc_priv.h"

static const uint8_t KDF_LABEL[] = "ConfirmationKeys";

/*! @function ccspake_kdf_label_size
 @abstract Returns the size of the label used for key derivation

 @param ctx SPAKE2+ context

 @return Size of the KDF label
 */
CC_NONNULL((1))
size_t ccspake_kdf_label_size(ccspake_const_ctx_t ctx)
{
    return sizeof(KDF_LABEL) - 1 + ccspake_ctx_aad_len(ctx);
}

/*! @function ccspake_build_kdf_label
 @abstract Builds the KDF label and writes it to `label`

 @param ctx   SPAKE2+ context
 @param label Target buffer
 */
CC_NONNULL((1, 2))
void ccspake_build_kdf_label(ccspake_const_ctx_t ctx, uint8_t *label)
{
    size_t kdf_label_len = sizeof(KDF_LABEL) - 1;
    size_t aad_len = ccspake_ctx_aad_len(ctx);

    cc_memcpy(label, KDF_LABEL, kdf_label_len);

    if (aad_len) {
        cc_memcpy(label + kdf_label_len, ccspake_ctx_aad(ctx), aad_len);
    }
}

/*! @function ccspake_ikm_write_len
 @abstract Write `len` to `ikm` as a 64-byte little-endian integer

 @param ikm Target buffer
 @param len Number to write

 @return ikm plus the number of bytes written
 */
CC_NONNULL((1))
static uint8_t *ccspake_ikm_write_len(uint8_t *ikm, uint64_t len)
{
    CC_STORE64_LE(len, ikm);
    return ikm + sizeof(len);
}

/*! @function ccspake_ikm_write_point_data
 @abstract Write an EC point's coordinates to `ikm`.

 @param ikm Target buffer
 @param cp  EC curve parameters
 @param x   x-coordinate of the point
 @param y   y-coordinate of the point

 @return ikm plus the number of bytes written
 */
CC_NONNULL((1, 2, 3, 4))
static uint8_t *ccspake_ikm_write_point_data(uint8_t *ikm, ccec_const_cp_t cp, const cc_unit *x, const cc_unit *y)
{
    size_t len = ccec_cp_prime_size(cp);
    cc_size n = ccec_cp_n(cp);

    *ikm++ = 0x04;

    // Write coordinates.
    ccn_write_uint_padded(n, x, len, ikm);
    ccn_write_uint_padded(n, y, len, ikm + len);

    return ikm + len * 2;
}

/*! @function ccspake_ikm_write_point
 @abstract Write an EC point's coordinates to `ikm`, prefixed by the length.

 @param ikm Target buffer
 @param cp  EC curve parameters
 @param x   x-coordinate of the point
 @param y   y-coordinate of the point

 @return ikm plus the number of bytes written
 */
CC_NONNULL((1, 2, 3, 4))
static uint8_t *ccspake_ikm_write_point(uint8_t *ikm, ccec_const_cp_t cp, const cc_unit *x, const cc_unit *y)
{
    size_t len = ccec_cp_prime_size(cp);

    // Write length.
    ikm = ccspake_ikm_write_len(ikm, (uint64_t)len * 2 + 1);

    // Write coordinates.
    return ccspake_ikm_write_point_data(ikm, cp, x, y);
}

/*! @function ccspake_ikm_size
 @abstract Returns the size of the "input key material" for key derivation

 @param ctx SPAKE2+ context

 @return The size of the "input key material"
 */
CC_NONNULL((1))
static size_t ccspake_ikm_size(ccspake_const_ctx_t ctx)
{
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);

    // Coordinates for points X, Y, Z, V (with leading 0x04).
    size_t sz = ccspake_sizeof_point(ccspake_ctx_scp(ctx)) * 4;

    // w0.
    sz += ccec_cp_order_size(cp);

    // Five 64-bit lengths.
    sz += 5 * 8;

    return sz;
}

/*! @function ccspake_derive_shared_key
 @abstract Derives the shared key when the protocol completes

 @param ctx    SPAKE2+ context
 @param sk     Target buffer
 */
CC_NONNULL((1, 2))
static void ccspake_derive_shared_key(ccspake_const_ctx_t ctx, uint8_t *sk)
{
    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);

    uint8_t ikm[ccspake_ikm_size(ctx)];
    uint8_t *out = ikm;

    // Write len(X) || X || len(Y) || Y.
    if (ccspake_ctx_is_prover(ctx)) {
        out = ccspake_ikm_write_point(out, cp, ccspake_ctx_XY_x(ctx), ccspake_ctx_XY_y(ctx));
        out = ccspake_ikm_write_point(out, cp, ccspake_ctx_Q_x(ctx), ccspake_ctx_Q_y(ctx));
    } else {
        out = ccspake_ikm_write_point(out, cp, ccspake_ctx_Q_x(ctx), ccspake_ctx_Q_y(ctx));
        out = ccspake_ikm_write_point(out, cp, ccspake_ctx_XY_x(ctx), ccspake_ctx_XY_y(ctx));
    }

    // Write len(Z) || Z.
    out = ccspake_ikm_write_point(out, cp, ccspake_ctx_Z_x(ctx), ccspake_ctx_Z_y(ctx));

    // Write len(V) || V.
    out = ccspake_ikm_write_point(out, cp, ccspake_ctx_V_x(ctx), ccspake_ctx_V_y(ctx));

    // Write len(w0) || w0.
    size_t len = ccec_cp_order_size(cp);
    out = ccspake_ikm_write_len(out, (uint64_t)len);
    ccn_write_uint_padded(ccec_cp_n(cp), ccspake_ctx_w0(ctx), len, out);

    // Sanity check.
    cc_assert((size_t)(out + len - ikm) == ccspake_ikm_size(ctx));

    // Derive.
    ccdigest(ccspake_ctx_mac(ctx)->di, sizeof(ikm), ikm, sk);
}

/*! @function ccspake_mac_compute_internal
 @abstract Generic function to derive MAC keys and compute MACs

 @param ctx    SPAKE2+ context
 @param key    Key to derive MAC keys from (of length `h_len / 2`)
 @param use_k1 Flag to tell whether to compute a MAC with K1 or K2
 @param x      x-coordinate of the point to confirm
 @param y      y-coordinate of the point to confirm
 @param t_len  Length of t
 @param t      Target buffer
 */
CC_NONNULL((1, 2, 4, 5, 7))
static int ccspake_mac_compute_internal(ccspake_const_ctx_t ctx,
                                        const uint8_t *key,
                                        bool use_k1,
                                        const cc_unit *x,
                                        const cc_unit *y,
                                        size_t t_len,
                                        uint8_t *t)
{
    size_t h_len = ccspake_ctx_mac(ctx)->di->output_size;

    uint8_t mac_keys[h_len];
    int rv = ccspake_ctx_mac(ctx)->derive(ctx, h_len / 2, key, sizeof(mac_keys), mac_keys);
    if (rv != 0) {
        return rv;
    }

    ccspake_const_cp_t scp = ccspake_ctx_scp(ctx);
    uint8_t info[ccspake_sizeof_point(scp)];

    ccec_const_cp_t cp = ccspake_ctx_cp(ctx);
    ccspake_ikm_write_point_data(info, cp, x, y);

    uint8_t *mkey = mac_keys + (!use_k1 * (h_len / 2));
    rv = ccspake_ctx_mac(ctx)->compute(ctx, h_len / 2, mkey, sizeof(info), info, t_len, t);

    cc_clear(sizeof(mac_keys), mac_keys);
    cc_clear(sizeof(info), info);

    return rv;
}

int ccspake_mac_compute(ccspake_ctx_t ctx, size_t t_len, uint8_t *t)
{
    CCSPAKE_EXPECT_STATES(KEX_BOTH, MAC_VERIFY);

    uint8_t key[ccspake_ctx_mac(ctx)->di->output_size];
    ccspake_derive_shared_key(ctx, key);

    int rv = ccspake_mac_compute_internal(
        ctx, key, !ccspake_ctx_is_prover(ctx), ccspake_ctx_Q_x(ctx), ccspake_ctx_Q_y(ctx), t_len, t);
    cc_clear(sizeof(key), key);

    if (rv != 0) {
        return rv;
    }

    CCSPAKE_ADD_STATE(MAC_GENERATE);

    return CCERR_OK;
}

int ccspake_mac_verify_and_get_session_key(ccspake_ctx_t ctx, size_t t_len, const uint8_t *t, size_t sk_len, uint8_t *sk)
{
    CCSPAKE_EXPECT_STATES(KEX_BOTH, MAC_GENERATE);

    size_t h_len = ccspake_ctx_mac(ctx)->di->output_size;
    if (sk_len != h_len / 2) {
        return CCERR_PARAMETER;
    }

    uint8_t key[h_len];
    ccspake_derive_shared_key(ctx, key);

    uint8_t tag[t_len];
    int rv = ccspake_mac_compute_internal(
        ctx, key, ccspake_ctx_is_prover(ctx), ccspake_ctx_XY_x(ctx), ccspake_ctx_XY_y(ctx), t_len, tag);

    if (rv != 0) {
        goto cleanup;
    }

    if (cc_cmp_safe(t_len, t, tag)) {
        rv = CCERR_INTEGRITY;
        goto cleanup;
    }

    cc_memcpy(sk, key + h_len / 2, h_len / 2);

    CCSPAKE_ADD_STATE(MAC_VERIFY);

cleanup:
    cc_clear(sizeof(tag), tag);
    cc_clear(sizeof(key), key);
    return rv;
}
