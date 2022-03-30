/* Copyright (c) (2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchkdf.h>

#include "cc_memory.h"
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "ccec_internal.h"
#include "cch2c_internal.h"
#include "cc_macros.h"

// See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-5.3
static int hash_to_base(const struct cch2c_info *info,
                        size_t dst_nbytes, const void *dst,
                        size_t data_nbytes, const void *data,
                        uint8_t ctr,
                        cc_unit *u)
{
    int status = CCERR_PARAMETER;

    uint8_t hkdf_info[5] = { 'H', '2', 'C', ctr, 1 };
    uint8_t buf[CCH2C_MAX_DATA_NBYTES + 1] = { 0 };

    ccec_const_cp_t cp = info->curve_params();
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MOD_WORKSPACE_N(n) + 2*n);
    CC_DECL_BP_WS(ws, bp);
    cc_unit *t = CC_ALLOC_WS(ws, 2*n);

    const struct ccdigest_info *di = info->digest_info();

    cc_require(data_nbytes <= CCH2C_MAX_DATA_NBYTES, out);

    memcpy(buf, data, data_nbytes);
    cchkdf_extract(di, dst_nbytes, dst, data_nbytes + 1, buf, buf);

    cchkdf_expand(di, di->output_size, buf,
                  sizeof(hkdf_info), hkdf_info,
                  info->l, buf);

    ccn_read_uint(2 * n, t, info->l, buf);
    cczp_mod_ws(ws, zp, u, t);

    status = CCERR_OK;

 out:
    CC_FREE_BP_WS(ws,bp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);

    return status;
}

// See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.2
static int map_to_curve_sswu(const struct cch2c_info *info,
                             cc_unit *u,
                             ccec_pub_ctx_t q)
{
    ccec_const_cp_t cp = info->curve_params();
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);
    cc_size ws_sizes[] = {
        CCZP_TO_WORKSPACE_N(n),
        CCZP_INV_WORKSPACE_N(n),
        CCZP_MUL_WORKSPACE_N(n),
        CCZP_SQR_WORKSPACE_N(n),
        CCZP_ADD_WORKSPACE_N(n),
        CCZP_IS_QUADRATIC_RESIDUE_WORKSPACE_N(n),
        CCZP_FROM_WORKSPACE_N(n),
        CCZP_SQRT_WORKSPACE_N(n)
    };
    cc_size ws_size = 0;
    for (size_t i = 0; i < CC_ARRAY_LEN(ws_sizes); i += 1) {
        ws_size = CC_MAX(ws_size, ws_sizes[i]);
    }
    CC_DECL_WORKSPACE_OR_FAIL(ws, (3*n + ws_size));
    CC_DECL_BP_WS(ws, bp);

    ccec_ctx_init(cp, q);

    cc_unit *x = ccec_ctx_x(q);
    cc_unit *y = ccec_ctx_y(q);
    cc_unit *z = ccec_ctx_z(q);
    cc_unit *t0 = CC_ALLOC_WS(ws, n);
    cc_unit *t1 = CC_ALLOC_WS(ws, n);
    cc_unit *t2 = CC_ALLOC_WS(ws, n);

    cc_unit u_parity = ccn_bit(u, 0);
    cc_unit e;

    // compute c2 = -1 / Z
    ccn_seti(n, z, info->z);
    cczp_to_ws(ws, zp, z, z);
    cczp_inv_ws(ws, zp, t1, z);

    // compute Z
    cczp_negate(zp, z, z);

    // compute c1 = -B / A
    ccn_seti(n, y, 3);
    cczp_to_ws(ws, zp, y, y);
    cczp_inv_ws(ws, zp, t0, y);
    cczp_mul_ws(ws, zp, t0, t0, ccec_cp_b(cp));

    // compute A
    cczp_negate(zp, y, y);

    // 1.   t1 = Z * u^2
    cczp_to_ws(ws, zp, u, u);
    cczp_sqr_ws(ws, zp, u, u);
    cczp_mul_ws(ws, zp, u, u, z);

    // 2.   t2 = t1^2
    cczp_sqr_ws(ws, zp, z, u);

    // 3.   x1 = t1 + t2
    cczp_add_ws(ws, zp, t2, u, z);

    // 4.   x1 = inv0(x1)
    cczp_inv_ws(ws, zp, t2, t2);

    // 5.   e1 = x1 == 0
    e = ccn_is_zero(n, t2);

    // 6.   x1 = x1 + 1
    ccn_seti(n, x, 1);
    cczp_to_ws(ws, zp, x, x);
    cczp_add_ws(ws, zp, t2, t2, x);

    // 7.   x1 = CMOV(x1, c2, e1)
    //      If (t1 + t2) == 0, set x1 = -1 / Z
    ccn_mux(n, e, t2, t1, t2);

    // 8.   x1 = x1 * c1
    //      x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
    cczp_mul_ws(ws, zp, t2, t2, t0);

    // 9.  gx1 = x1^2
    cczp_sqr_ws(ws, zp, t0, t2);

    // 10. gx1 = gx1 + A
    cczp_add_ws(ws, zp, t0, t0, y);

    // 11. gx1 = gx1 * x1
    cczp_mul_ws(ws, zp, t0, t0, t2);

    // 12. gx1 = gx1 + B
    //     gx1 = g(x1) = x1^3 + A * x1 + B
    cczp_add_ws(ws, zp, t0, t0, ccec_cp_b(cp));

    // 13.  x2 = t1 * x1             // x2 = Z * u^2 * x1
    cczp_mul_ws(ws, zp, x, u, t2);

    // 14.  t2 = t1 * t2
    cczp_mul_ws(ws, zp, z, u, z);

    // 15. gx2 = gx1 * t2
    //     gx2 = (Z * u^2)^3 * gx1
    cczp_mul_ws(ws, zp, z, t0, z);

    // 16.  e2 = is_square(gx1)
    e = (cc_unit)cczp_is_quadratic_residue_ws(ws, zp, t0);

    // 17.   x = CMOV(x2, x1, e2)
    //       If is_square(gx1), x = x1, else x = x2
    ccn_mux(n, e, x, t2, x);
    cczp_from_ws(ws, zp, x, x);

    // 18.  y2 = CMOV(gx2, gx1, e2)
    //      If is_square(gx1), y2 = gx1, else y2 = gx2
    ccn_mux(n, e, z, t0, z);

    // 19.   y = sqrt(y2)
    cczp_sqrt_ws(ws, zp, y, z);
    cczp_from_ws(ws, zp, y, y);

    // 20.  e3 = sgn0(u) == sgn0(y)
    //      Fix sign of y
    e = u_parity ^ ccn_bit(y, 0) ^ 1;

    // 21.   y = CMOV(-y, y, e3)
    cczp_negate(zp, z, y);
    ccn_mux(n, e, y, y, z);

    // 22. return (x, y)
    ccn_seti(n, z, 1);

    CC_FREE_BP_WS(ws,bp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);

    return CCERR_OK;
}

static int clear_cofactor_nop(CC_UNUSED const struct cch2c_info *info,
                              CC_UNUSED ccec_pub_ctx_t pubkey)
{
    return CCERR_OK;
}

static int encode_to_curve_ro(const struct cch2c_info *info,
                              size_t dst_nbytes, const void *dst,
                              size_t data_nbytes, const void *data,
                              ccec_pub_ctx_t q)
{
    int status;

    const cc_size n = CCN521_N;
    cc_unit u0[n];
    cc_unit u1[n];
    ccec_pub_ctx_decl(ccn_sizeof_n(n), q0);
    ccec_pub_ctx_decl(ccn_sizeof_n(n), q1);

    ccec_const_cp_t cp = info->curve_params();
    ccec_ctx_init(cp, q);

    status = info->hash_to_base(info, dst_nbytes, dst, data_nbytes, data, 0, u0);
    cc_require(status == CCERR_OK, out);

    status = info->hash_to_base(info, dst_nbytes, dst, data_nbytes, data, 1, u1);
    cc_require(status == CCERR_OK, out);

    status = info->map_to_curve(info, u0, q);
    cc_require(status == CCERR_OK, out);

    status = ccec_projectify(cp, ccec_ctx_point(q0), (ccec_const_affine_point_t)ccec_ctx_point(q), NULL);
    cc_require(status == CCERR_OK, out);

    status = info->map_to_curve(info, u1, q);
    cc_require(status == CCERR_OK, out);

    status = ccec_projectify(cp, ccec_ctx_point(q1), (ccec_const_affine_point_t)ccec_ctx_point(q), NULL);
    cc_require(status == CCERR_OK, out);

    ccec_full_add(cp, ccec_ctx_point(q0), ccec_ctx_point(q0), ccec_ctx_point(q1));

    status = ccec_affinify(cp, (ccec_affine_point_t)ccec_ctx_point(q), ccec_ctx_point(q0));
    cc_require(status == CCERR_OK, out);

    status = info->clear_cofactor(info, q);
    cc_require(status == CCERR_OK, out);

 out:
    cc_clear(sizeof(u0), u0);
    cc_clear(sizeof(u1), u1);
    ccec_pub_ctx_clear(ccn_sizeof_n(n), q0);
    ccec_pub_ctx_clear(ccn_sizeof_n(n), q1);

    return status;
}

int cch2c(const struct cch2c_info *info,
          size_t dst_nbytes, const void *dst,
          size_t data_nbytes, const void *data,
          ccec_pub_ctx_t pubkey)
{
    int status = CCERR_PARAMETER;

    cc_require(dst_nbytes > 0, out);

    status = info->encode_to_curve(info, dst_nbytes, dst, data_nbytes, data, pubkey);

 out:
    return status;
}

const char *cch2c_name(const struct cch2c_info *info)
{
    return info->name;
}

const struct cch2c_info cch2c_p256_sha256_sswu_ro_info = {
    .name = "P256-SHA256-SSWU-RO-",
    .l = 48,
    .z = 10,
    .curve_params = ccec_cp_256,
    .digest_info = ccsha256_di,
    .hash_to_base = hash_to_base,
    .map_to_curve = map_to_curve_sswu,
    .clear_cofactor = clear_cofactor_nop,
    .encode_to_curve = encode_to_curve_ro,
};

const struct cch2c_info cch2c_p384_sha512_sswu_ro_info = {
    .name = "P384-SHA512-SSWU-RO-",
    .l = 72,
    .z = 12,
    .curve_params = ccec_cp_384,
    .digest_info = ccsha512_di,
    .hash_to_base = hash_to_base,
    .map_to_curve = map_to_curve_sswu,
    .clear_cofactor = clear_cofactor_nop,
    .encode_to_curve = encode_to_curve_ro,
};

const struct cch2c_info cch2c_p521_sha512_sswu_ro_info = {
    .name = "P521-SHA512-SSWU-RO-",
    .l = 96,
    .z = 4,
    .curve_params = ccec_cp_521,
    .digest_info = ccsha512_di,
    .hash_to_base = hash_to_base,
    .map_to_curve = map_to_curve_sswu,
    .clear_cofactor = clear_cofactor_nop,
    .encode_to_curve = encode_to_curve_ro,
};

const struct cch2c_info cch2c_p256_sha256_sae_compat_info;

const struct cch2c_info cch2c_p384_sha384_sae_compat_info;
