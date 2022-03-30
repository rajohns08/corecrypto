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

#include "testmore.h"
#include "testbyteBuffer.h"
#include "cc_priv.h"

#if (CCH2C == 0)
entryPoint(cch2c_tests,"cch2c")
#else

#include <corecrypto/ccec.h>
#include "cch2c_internal.h"
#include "ccec_internal.h"

struct cch2c_sswu_test_vector {
    unsigned tcId;
    unsigned curve;
    unsigned hkdf;
    const uint8_t *alpha;
    size_t alpha_len;
    const uint8_t *DST;
    size_t DST_len;
    const uint8_t *NUx;
    size_t NUx_len;
    const uint8_t *NUy;
    size_t NUy_len;
    const uint8_t *ROx;
    size_t ROx_len;
    const uint8_t *ROy;
    size_t ROy_len;
    const uint8_t *u_nu;
    size_t u_nu_len;
    const uint8_t *u_ro0;
    size_t u_ro0_len;
    const uint8_t *u_ro1;
    size_t u_ro1_len;
    const uint8_t *Q0x;
    size_t Q0x_len;
    const uint8_t *Q0y;
    size_t Q0y_len;
    const uint8_t *Q1x;
    size_t Q1x_len;
    const uint8_t *Q1y;
    size_t Q1y_len;
};

#include "../test_vectors/h2c_sswu.kat"

#define CCH2C_TEST_MEMCMP(_buf1_, _buf2_, _buflen_, _desc_)         \
if (memcmp(_buf1_, _buf2_, _buflen_) != 0) {                        \
    diag("%s\n", _desc_);                                           \
    cc_print("Compare: ", _buflen_, (const uint8_t *)(_buf1_));     \
    cc_print("    and: ", _buflen_, (const uint8_t *)(_buf2_));     \
    return false;                                                   \
}

#define CCH2C_TEST_MEMCMP_PK(_pk_, _n_, _cpsz_, _x_, _xlen_, _y_, _ylen_, _desc_) \
{ \
cc_assert(_cpsz_ == _xlen_); \
cc_assert(_cpsz_ == _ylen_); \
uint8_t temp_x_buffer[_xlen_]; \
uint8_t temp_y_buffer[_xlen_]; \
ccn_write_uint_padded(_n_, ccec_ctx_x(_pk_), _xlen_, temp_x_buffer);  \
ccn_write_uint_padded(_n_, ccec_ctx_y(_pk_), _ylen_, temp_y_buffer);  \
CCH2C_TEST_MEMCMP(temp_x_buffer, _x_, _xlen_, _desc_ " x coordinate"); \
CCH2C_TEST_MEMCMP(temp_y_buffer, _y_, _ylen_, _desc_ " y coordinate"); \
}

static bool h2c_sswu_test_run_one(const struct cch2c_sswu_test_vector *tv)
{

    const struct cch2c_info *info = NULL;
    if (tv->curve == 256 && tv->hkdf == 256) {
        info = &cch2c_p256_sha256_sswu_ro_info;
    } else if (tv->curve == 384 && tv->hkdf == 512) {
        info = &cch2c_p384_sha512_sswu_ro_info;
    } else if (tv->curve == 521 && tv->hkdf == 512) {
        info = &cch2c_p521_sha512_sswu_ro_info;
    } else {
        diag("Unimplemented SSWU: curve = %d, hkdf = %d\n", tv->curve, tv->hkdf);
        return false;
    }

    ccec_const_cp_t cp = info->curve_params();
    cc_size n = ccec_cp_n(cp);
    size_t cp_sz = ccec_cp_prime_size(cp);
    cc_unit u0[n];
    uint8_t u0_b[cp_sz];
    cc_unit u1[n];
    uint8_t u1_b[cp_sz];

    info->hash_to_base(info, tv->DST_len, tv->DST, tv->alpha_len, tv->alpha, 0, u0);
    info->hash_to_base(info, tv->DST_len, tv->DST, tv->alpha_len, tv->alpha, 1, u1);
    ccn_write_uint_padded(n, u0, cp_sz, u0_b);
    ccn_write_uint_padded(n, u1, cp_sz, u1_b);

    CCH2C_TEST_MEMCMP(u0_b, tv->u_ro0, tv->u_ro0_len, "Invalid hash-to_base u0");
    CCH2C_TEST_MEMCMP(u1_b, tv->u_ro1, tv->u_ro1_len, "Invalid hash-to_base u1");

    ccec_pub_ctx_decl_cp(cp, Q0);
    ccec_pub_ctx_decl_cp(cp, Q1);
    info->map_to_curve(info, u0, Q0);
    info->map_to_curve(info, u1, Q1);
    CCH2C_TEST_MEMCMP_PK(Q0, n, cp_sz, tv->Q0x, tv->Q0x_len, tv->Q0y, tv->Q0y_len, "Q0");
    CCH2C_TEST_MEMCMP_PK(Q1, n, cp_sz, tv->Q1x, tv->Q1x_len, tv->Q1y, tv->Q1y_len, "Q1");

    ccec_pub_ctx_decl_cp(cp, R);

    cch2c(info, tv->DST_len, tv->DST, tv->alpha_len, tv->alpha, R);
    CCH2C_TEST_MEMCMP_PK(R, n, cp_sz, tv->ROx, tv->ROx_len, tv->ROy, tv->ROy_len, "R");
    return true;
}

static void h2c_sswu_test_runner()
{
    size_t nvectors = CC_ARRAY_LEN(h2c_sswu_vectors);
    for (size_t i = 0; i < nvectors; i++)
    {
        const struct cch2c_sswu_test_vector *tv = h2c_sswu_vectors[i];
        bool result = h2c_sswu_test_run_one(tv);
        is(result, true, "Failed SSWU test vector %d\n", tv->tcId);
    }
}


int cch2c_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int status = 0;
    size_t ntests = 0;
    ntests += CC_ARRAY_LEN(h2c_sswu_vectors);
    plan_tests((int) ntests);

    h2c_sswu_test_runner();

    return status;
}

#endif // (CCH2C == 0)
