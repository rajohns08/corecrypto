/* Copyright (c) (2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng_sequence.h>
#include <limits.h>
#include "testmore.h"
#include "cczp_internal.h"
#include "cc_debug.h"
#include "ccn_internal.h"

static const cc_unit expected_recips[] = {
    0x0,   0x4,   0x8,   0x5,   0x10,  0xc,   0xa,   0x9,   0x20,  0x1c,  0x19,  0x17,  0x15,  0x13,  0x12,  0x11,  0x40,  0x3c,
    0x38,  0x35,  0x33,  0x30,  0x2e,  0x2c,  0x2a,  0x28,  0x27,  0x25,  0x24,  0x23,  0x22,  0x21,  0x80,  0x7c,  0x78,  0x75,
    0x71,  0x6e,  0x6b,  0x69,  0x66,  0x63,  0x61,  0x5f,  0x5d,  0x5b,  0x59,  0x57,  0x55,  0x53,  0x51,  0x50,  0x4e,  0x4d,
    0x4b,  0x4a,  0x49,  0x47,  0x46,  0x45,  0x44,  0x43,  0x42,  0x41,  0x100, 0xfc,  0xf8,  0xf4,  0xf0,  0xed,  0xea,  0xe6,
    0xe3,  0xe0,  0xdd,  0xda,  0xd7,  0xd4,  0xd2,  0xcf,  0xcc,  0xca,  0xc7,  0xc5,  0xc3,  0xc0,  0xbe,  0xbc,  0xba,  0xb8,
    0xb6,  0xb4,  0xb2,  0xb0,  0xae,  0xac,  0xaa,  0xa8,  0xa7,  0xa5,  0xa3,  0xa2,  0xa0,  0x9f,  0x9d,  0x9c,  0x9a,  0x99,
    0x97,  0x96,  0x94,  0x93,  0x92,  0x90,  0x8f,  0x8e,  0x8d,  0x8c,  0x8a,  0x89,  0x88,  0x87,  0x86,  0x85,  0x84,  0x83,
    0x82,  0x81,  0x200, 0x1fc, 0x1f8, 0x1f4, 0x1f0, 0x1ec, 0x1e9, 0x1e5, 0x1e1, 0x1de, 0x1da, 0x1d7, 0x1d4, 0x1d0, 0x1cd, 0x1ca,
    0x1c7, 0x1c3, 0x1c0, 0x1bd, 0x1ba, 0x1b7, 0x1b4, 0x1b2, 0x1af, 0x1ac, 0x1a9, 0x1a6, 0x1a4, 0x1a1, 0x19e, 0x19c, 0x199, 0x197,
    0x194, 0x192, 0x18f, 0x18d, 0x18a, 0x188, 0x186, 0x183, 0x181, 0x17f, 0x17d, 0x17a, 0x178, 0x176, 0x174, 0x172, 0x170, 0x16e,
    0x16c, 0x16a, 0x168, 0x166, 0x164, 0x162, 0x160, 0x15e, 0x15c, 0x15a, 0x158, 0x157, 0x155, 0x153, 0x151, 0x150, 0x14e, 0x14c,
    0x14a, 0x149, 0x147, 0x146, 0x144, 0x142, 0x141, 0x13f, 0x13e, 0x13c, 0x13b, 0x139, 0x138, 0x136, 0x135, 0x133, 0x132, 0x130,
    0x12f, 0x12e, 0x12c, 0x12b, 0x129, 0x128, 0x127, 0x125, 0x124, 0x123, 0x121, 0x120, 0x11f, 0x11e, 0x11c, 0x11b, 0x11a, 0x119,
    0x118, 0x116, 0x115, 0x114, 0x113, 0x112, 0x111, 0x10f, 0x10e, 0x10d, 0x10c, 0x10b, 0x10a, 0x109, 0x108, 0x107, 0x106, 0x105,
    0x104, 0x103, 0x102, 0x101, 0x400, 0x3fc, 0x3f8, 0x3f4, 0x3f0, 0x3ec, 0x3e8, 0x3e4, 0x3e0, 0x3dd, 0x3d9, 0x3d5, 0x3d2, 0x3ce,
    0x3ca, 0x3c7, 0x3c3, 0x3c0, 0x3bc, 0x3b9, 0x3b5, 0x3b2, 0x3ae, 0x3ab, 0x3a8, 0x3a4, 0x3a1, 0x39e, 0x39b, 0x397, 0x394, 0x391,
    0x38e, 0x38b, 0x387, 0x384, 0x381, 0x37e, 0x37b, 0x378, 0x375, 0x372, 0x36f, 0x36c, 0x369, 0x366, 0x364, 0x361, 0x35e, 0x35b,
    0x358, 0x355, 0x353, 0x350, 0x34d, 0x34a, 0x348, 0x345, 0x342, 0x340, 0x33d, 0x33a, 0x338, 0x335, 0x333, 0x330, 0x32e, 0x32b,
    0x329, 0x326, 0x324, 0x321, 0x31f, 0x31c, 0x31a, 0x317, 0x315, 0x313, 0x310, 0x30e, 0x30c, 0x309, 0x307, 0x305, 0x303, 0x300,
    0x2fe, 0x2fc, 0x2fa, 0x2f7, 0x2f5, 0x2f3, 0x2f1, 0x2ef, 0x2ec, 0x2ea, 0x2e8, 0x2e6, 0x2e4, 0x2e2, 0x2e0, 0x2de, 0x2dc, 0x2da,
    0x2d8, 0x2d6, 0x2d4, 0x2d2, 0x2d0, 0x2ce, 0x2cc, 0x2ca, 0x2c8, 0x2c6, 0x2c4, 0x2c2, 0x2c0, 0x2be, 0x2bc, 0x2bb, 0x2b9, 0x2b7,
    0x2b5, 0x2b3, 0x2b1, 0x2b0, 0x2ae, 0x2ac, 0x2aa, 0x2a8, 0x2a7, 0x2a5, 0x2a3, 0x2a1, 0x2a0, 0x29e, 0x29c, 0x29b, 0x299, 0x297,
    0x295, 0x294, 0x292, 0x291, 0x28f, 0x28d, 0x28c, 0x28a, 0x288, 0x287, 0x285, 0x284, 0x282, 0x280, 0x27f, 0x27d, 0x27c, 0x27a,
    0x279, 0x277, 0x276, 0x274, 0x273, 0x271, 0x270, 0x26e, 0x26d, 0x26b, 0x26a, 0x268, 0x267, 0x265, 0x264, 0x263, 0x261, 0x260,
    0x25e, 0x25d, 0x25c, 0x25a, 0x259, 0x257, 0x256, 0x255, 0x253, 0x252, 0x251, 0x24f, 0x24e, 0x24d, 0x24b, 0x24a, 0x249, 0x247,
    0x246, 0x245, 0x243, 0x242, 0x241, 0x240, 0x23e, 0x23d, 0x23c, 0x23b, 0x239, 0x238, 0x237, 0x236, 0x234, 0x233, 0x232, 0x231,
    0x230, 0x22e, 0x22d, 0x22c, 0x22b, 0x22a, 0x229, 0x227, 0x226, 0x225, 0x224, 0x223, 0x222, 0x220, 0x21f, 0x21e, 0x21d, 0x21c,
    0x21b, 0x21a, 0x219, 0x218, 0x216, 0x215, 0x214, 0x213, 0x212, 0x211, 0x210, 0x20f, 0x20e, 0x20d, 0x20c, 0x20b, 0x20a, 0x209,
    0x208, 0x207, 0x206, 0x205, 0x204, 0x203, 0x202, 0x201,
};

static int test_cczp_init(void)
{
    /* Negative test */
    const cc_unit d[2] = { 0, 0 };
    const cc_unit recipd[3] = { 1, 1, 1 };

    cczp_decl_n(2, zerod);
    CCZP_N(zerod) = 2;
    ccn_set(2, CCZP_PRIME(zerod), d);
    cczp_init_with_recip(zerod, recipd);

    /* ccn_make_recip is expected to write zeroes when d is zero */
    cczp_init(zerod);
    ok(ccn_is_zero(3, cczp_recip(zerod)), "ccn_make_recip when d is zero");

    /* test small values of d to exercise edge cases */
    cczp_decl_n(1, testd);
    CCZP_N(testd) = 1;
    ccn_zero(1, CCZP_PRIME(testd));
    for (size_t i = 0; i < CC_ARRAY_LEN(expected_recips); i++) {
        ccn_seti(CCZP_N(testd), CCZP_PRIME(testd), i);
        is(cczp_init(testd), 0, "cczp_init");
        ok_ccn_cmp(1, CCZP_RECIP(testd), &expected_recips[i], "%zu, expected recip", i);
    }
    /* Extend test with a consistency check instead of known reciprocal */
    for (uint64_t i = CC_ARRAY_LEN(expected_recips); i < (1ULL << 24); i++) {
        ccn_seti(CCZP_N(testd), CCZP_PRIME(testd), (cc_unit)i);

        // Operation must be successful
        is(cczp_init(testd), 0, "cczp_init");

        // Verify that 2^2b - recip*testd < testd
        cc_size recip_nunits = (CCZP_N(testd) + 1);
        cc_unit tmp[2 * recip_nunits];
        cc_unit tmpd[2 * recip_nunits];
        cc_unit two_power_2b[2 * recip_nunits];
        ccn_setn(recip_nunits, tmpd, CCZP_N(testd), CCZP_PRIME(testd));
        ccn_mul(recip_nunits, tmp, tmpd, CCZP_RECIP(testd)); // tmpd*recip
        ccn_zero(2 * recip_nunits, two_power_2b);
        ccn_set_bit(two_power_2b, 2 * cczp_bitlen(testd), 1);          // 2^(2b)
        cc_unit c = ccn_sub(2 * recip_nunits, tmp, two_power_2b, tmp); // 2^(2b) - tmpd*recip
        is(c,0,"No borrow expected here");
        if (!ok(ccn_cmp(2 * recip_nunits, tmp, tmpd) <= 0, "Reciprocal is correct")) {
            ccn_lprint(CCZP_N(testd), "d", CCZP_PRIME(testd));
            ccn_lprint(recip_nunits, "recip", CCZP_RECIP(testd));
        }
    }
    return 0;
}

static const cc_unit p[] = {
    ccn256_32(0xe5a022bd, 0x33109be3, 0x536f9eda, 0x564edabe, 0x9b4ddf1c, 0x157c483c, 0x4caa41fc, 0xccbee49b)
};
static const size_t n = ccn_nof(256);

/* negative tests for cczp_power* edge cases */
/* common cases are well covered by higher-level tests (e.g. ccdh, ccrsa, etc.) */
static int test_cczp_power_fns(void)
{
    cc_unit r[n];
    cc_unit s[n];
    cc_unit t[n];
    cc_unit e[n];
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init(zp);

    ccn_seti(n, s, 2);

    ccn_seti(n, e, 0);
    cczp_power(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_power when e = 0");
    cczp_mm_power(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_mm_power when e = 0");
    cczp_power_ssma(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_power_ssma when e = 0");
    cczp_mm_power_ssma(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_mm_power_ssma when e = 0");
    cczp_power_fast(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_power_fast when e = 0");
    cczp_mm_power_fast(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_mm_power_fast when e = 0");
    cczp_powern(zp, r, s, 0, e);
    ok(ccn_is_one(n, r), "cczp_powern when e = 0");

    ccn_seti(n, e, 1);
    cczp_power(zp, r, s, e);
    ok_ccn_cmp(n, r, s, "cczp_power when e = 1");
    cczp_mm_power(zp, r, s, e);
    ok_ccn_cmp(n, r, s, "cczp_mm_power when e = 1");
    cczp_power_ssma(zp, r, s, e);
    ok_ccn_cmp(n, r, s, "cczp_power_ssma when e = 1");
    cczp_mm_power_ssma(zp, r, s, e);
    ok_ccn_cmp(n, r, s, "cczp_mm_power_ssma when e = 1");
    cczp_power_fast(zp, r, s, e);
    ok_ccn_cmp(n, r, s, "cczp_power_fast when e = 1");
    cczp_mm_power_fast(zp, r, s, e);
    ok_ccn_cmp(n, r, s, "cczp_mm_power_fast when e = 1");
    cczp_powern(zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, s, "cczp_powern when e = 1");

    ccn_seti(n, e, 2);
    ccn_seti(n, t, 4);
    cczp_power(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_power when e = 2");
    cczp_mm_power(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power when e = 2");
    cczp_power_ssma(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_power_ssma when e = 2");
    cczp_mm_power_ssma(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power_ssma when e = 2");
    cczp_power_fast(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_power_fast when e = 2");
    cczp_mm_power_fast(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power_fast when e = 2");
    cczp_powern(zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, t, "cczp_powern when e = 2");

    ccn_seti(n, e, 4);
    ccn_seti(n, t, 16);
    cczp_power(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_power when e = 4");
    cczp_mm_power(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power when e = 4");
    cczp_power_ssma(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_power_ssma when e = 4");
    cczp_mm_power_ssma(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power_ssma when e = 4");
    cczp_power_fast(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_power_fast when e = 4");
    cczp_mm_power_fast(zp, r, s, e);
    ok_ccn_cmp(n, r, t, "cczp_mm_power_fast when e = 4");
    cczp_powern(zp, r, s, ccn_bitlen(n, e), e);
    ok_ccn_cmp(n, r, t, "cczp_powern when e = 4");

    ccn_add(n, t, s, p);
    isnt(cczp_power(zp, r, t, e), 0, "cczp_power when base > p");
    isnt(cczp_mm_power(zp, r, t, e), 0, "cczp_mm_power when base > p");
    isnt(cczp_power_ssma(zp, r, t, e), 0, "cczp_power_ssma when base > p");
    isnt(cczp_mm_power_ssma(zp, r, t, e), 0, "cczp_mm_power_ssma when base > p");
    isnt(cczp_power_fast(zp, r, t, e), 0, "cczp_power_fast when base > p");
    isnt(cczp_mm_power_fast(zp, r, t, e), 0, "cczp_mm_power_fast when base > p");
    isnt(cczp_powern(zp, r, t, ccn_bitlen(n, e), e), 0, "cczp_powern when base > p");

    return 0;
}

#define NUM_RANDOM_POWER_TESTS 1000

static int test_cczp_power_fns_randomized(cczp_const_t zp)
{
    struct ccrng_state *rng = global_test_rng;

    cc_size n = cczp_n(zp);
    cc_unit r0[n], r1[n], r2[n], r3[n], r4[n], r5[n], r6[n];
    cc_unit b[n], e[n];

    for (int i = 0; i < NUM_RANDOM_POWER_TESTS; i++) {
        is(cczp_generate_non_zero_element(zp, rng, e), CCERR_OK, "RNG failed");
        is(cczp_generate_non_zero_element(zp, rng, b), CCERR_OK, "RNG failed");

        is(cczp_power(zp, r0, b, e), 0, "cczp_power randomized");
        is(cczp_mm_power(zp, r1, b, e), 0, "cczp_mm_power randomized");
        is(cczp_power_ssma(zp, r2, b, e), 0, "cczp_power_ssma randomized");
        is(cczp_mm_power_ssma(zp, r3, b, e), 0, "cczp_mm_power_ssma randomized");
        is(cczp_power_fast(zp, r4, b, e), 0, "cczp_power_fast randomized");
        is(cczp_mm_power_fast(zp, r5, b, e), 0, "cczp_mm_power_fast randomized");
        is(cczp_powern(zp, r6, b, ccn_bitlen(n, e), e), 0, "cczp_powern randomized");

        ok_ccn_cmp(n, r0, r1, "cczp_power != cczp_mm_power");
        ok_ccn_cmp(n, r0, r2, "cczp_power != cczp_power_ssma");
        ok_ccn_cmp(n, r0, r3, "cczp_power != cczp_mm_power_ssma");
        ok_ccn_cmp(n, r0, r4, "cczp_power != cczp_power_fast");
        ok_ccn_cmp(n, r0, r5, "cczp_power != cczp_mm_power_fast");
        ok_ccn_cmp(n, r0, r6, "cczp_power != cczp_powern");
    }

    return 0;
}

static int test_cczp_sqrt_single(cc_unit *r, cc_unit q, size_t p_len, const uint8_t *p)
{
    cc_size n = ccn_nof_size(p_len);

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_read_uint(n, CCZP_PRIME(zp), p_len, p);
    cczp_init(zp);

    cc_unit x[n];
    ccn_seti(n, x, q);

    return cczp_sqrt(zp, r, x);
}

#define NUM_RANDOM_SQRT_TESTS 1000

static int test_cczp_sqrt_randomized(cczp_const_t zq, cc_size n)
{
    cc_unit x[n];
    cc_unit r1[n];

    for (int i = 0; i < NUM_RANDOM_SQRT_TESTS; i++) {
        is(cczp_generate_non_zero_element(zq, global_test_rng, x), CCERR_OK, "RNG Failure");
        cczp_sqr(zq, x, x);

        is(cczp_sqrt(zq, r1, x), CCERR_OK, "sqrt() failed");
        cczp_sqr(zq, r1, r1);

        is(ccn_cmp(n, r1, x), 0, "SQRT FAILURE");
    }
    return 0;
}

static int test_cczp_sqrt(void)
{
    // 597035519 = 3 mod 4
    const uint8_t prime1[] = { 0x23, 0x96, 0x09, 0xff };
    cc_unit r1[ccn_nof_sizeof(prime1)];
    is(test_cczp_sqrt_single(r1, 2, sizeof(prime1), prime1), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r1, 2, sizeof(prime1), prime1), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r1, 0, sizeof(prime1), prime1), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r1, 0, sizeof(prime1), prime1), 0, "cczp_sqrt failed");

    // 597035539 = 3 mod 4
    const uint8_t prime2[] = { 0x23, 0x96, 0x0a, 0x13 };
    cc_unit r2[ccn_nof_sizeof(prime2)];

    // x^2 = 2 mod 597035539 has no solution as 2 is not a quadratic residue.
    is(test_cczp_sqrt_single(r2, 2, sizeof(prime2), prime2), CCERR_PARAMETER, "cczp_sqrt should fail");
    is(test_cczp_sqrt_single(r2, 2, sizeof(prime2), prime2), CCERR_PARAMETER, "cczp_sqrt should fail");

    // 40961 = 1 mod 4
    const uint8_t prime3[] = { 0xa0, 0x01 };
    cc_unit r3[ccn_nof_sizeof(prime3)];
    is(test_cczp_sqrt_single(r3, 5, sizeof(prime3), prime3), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r3, 5, sizeof(prime3), prime3), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r3, 0, sizeof(prime3), prime3), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r3, 0, sizeof(prime3), prime3), 0, "cczp_sqrt failed");

    // 360027784083079948259017962255826129 = 1 mod 4
    const uint8_t prime4[] = { 0x45, 0x56, 0xbd, 0x7f, 0x9d, 0xf3, 0x85, 0xb1, 0xcb, 0xb2, 0x24, 0xe3, 0x64, 0x3c, 0xd1 };
    cc_unit r4[ccn_nof_sizeof(prime4)];
    is(test_cczp_sqrt_single(r4, 2, sizeof(prime4), prime4), 0, "cczp_sqrt failed");
    is(test_cczp_sqrt_single(r4, 2, sizeof(prime4), prime4), 0, "cczp_sqrt failed");

    // x^2 = 23 mod 360027784083079948259017962255826129 has no solution.
    is(test_cczp_sqrt_single(r4, 23, sizeof(prime4), prime4), CCERR_PARAMETER, "cczp_sqrt should fail");
    is(test_cczp_sqrt_single(r4, 23, sizeof(prime4), prime4), CCERR_PARAMETER, "cczp_sqrt should fail");

    // 2^224 - 4733179336708116180759420887881155 = 1 mod 4
    ccec_const_cp_t p224 = ccec_cp_224();
    cczp_const_t zq224 = ccec_cp_zq(p224);
    cc_size n224 = ccec_cp_n(p224);

    cc_unit r5[n224], x5[n224];
    ccn_seti(n224, x5, 3);
    is(cczp_sqrt(zq224, r5, x5), 0, "cczp_sqrt failed");

    return 0;
}

static int test_cczp_sqr_vs_mul(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init(zp);

    cc_unit r_sqr[n];
    cc_unit r_mul[n];
    cc_unit x[n];

    for (int i = 0; i < NUM_RANDOM_SQRT_TESTS; i++) {
        is(cczp_generate_non_zero_element(zp, global_test_rng, x), CCERR_OK, "Gen Element Failure");
        cczp_sqr(zp, r_sqr, x);
        cczp_mul(zp, r_mul, x, x);
        ok_ccn_cmp(n, r_sqr, r_mul, "SQR != MUL");
    }
    return 0;
}

static int test_cczp_add_sub(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init(zp);

    cc_unit x[n];
    cc_unit r[n];
    cc_unit one[n];

    ccn_seti(n, one, 1);
    ccn_set(n, x, p);
    x[0] -= 1; // x = p - 1

    cczp_add(zp, r, x, one); // r = p - 1 + 1 == 0
    is(ccn_is_zero(n, r), 1, "p - 1 + 1 is not zero!");

    cczp_sub(zp, r, r, one); // r = p - 1
    is(ccn_cmp(n, r, x), 0, "0 - 1 is not p - 1!");

    return 0;
}

static int test_cczp_div2(void)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CC_MAX_EVAL(CCZP_INIT_WORKSPACE_N(n),
                                    CC_MAX_EVAL(CCZP_DIV2_WORKSPACE_N(n),
                                                CCZP_MUL_WORKSPACE_N(n))));

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init_ws(ws, zp);

    cc_unit x[n];
    cc_unit r[n];
    cc_unit two[n];
    ccn_seti(n, two, 2);

    ccn_seti(n, x, 0);
    cczp_div2_ws(ws, zp, r, x); // 0 / 2
    is(ccn_is_zero(n, r), 1, "div2 failure");

    ccn_seti(n, x, 1);
    cczp_div2_ws(ws, zp, r, x); // 1 / 2
    cczp_mul_ws(ws, zp, r, r, two);
    is(ccn_is_one(n, r), 1, "div2 failure");

    ccn_seti(n, x, 2);
    cczp_div2_ws(ws, zp, r, x); // 2 / 2
    is(ccn_is_one(n, r), 1, "div2 failure");

    ccn_sub1(n, x, cczp_prime(zp), 1);
    cczp_div2_ws(ws, zp, r, x);
    cczp_mul_ws(ws, zp, r, r, two); // (p - 1) / 2
    ok_ccn_cmp(n, r, x, "div2 failure");

    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return 0;
}

static int test_cczp_modn(size_t cn)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init(zp);

    cc_unit x[cn * n];
    cc_unit r[n];
    ccn_clear(cn * n, x);

    ccn_set(n, x + (cn - 1) * n, p);
    cczp_modn(zp, r, cn * n, x); // r = p << (cn - 1) * 256 mod p
    is(ccn_is_zero(n, r), 1, "modn failure");

    ccn_add1(cn * n, x, x, 1);
    cczp_modn(zp, r, cn * n, x); // r = (p + 1) mod p
    is(ccn_is_one(n, r), 1, "modn failure");

    ccn_sub1(cn * n, x, x, 2);
    cczp_modn(zp, r, cn * n, x); // p = (p - 1) mod p
    ccn_add1(n, r, r, 1);
    ok_ccn_cmp(n, r, p, "modn failure");

    return 0;
}
static int test_cczp_mod(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init(zp);

    cc_unit x[2 * n];
    cc_unit r[n];
    ccn_clear(2 * n, x);
    ccn_set(n, x + n, p);

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MOD_WORKSPACE_N(n));

    cczp_mod_ws(ws, zp, r, x); // 0 mod p
    is(ccn_is_zero(n, r), 1, "mod failure");

    ccn_add1(2 * n, x, x, 1);
    cczp_mod_ws(ws, zp, r, x); // 1 mod p
    is(ccn_is_one(n, r), 1, "mod failure");

    ccn_sub1(2 * n, x, x, 2);
    cczp_mod_ws(ws, zp, r, x); // p - 1 mod p
    ccn_add1(n, r, r, 1);
    ok_ccn_cmp(n, r, p, "mod failure");

    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return 0;
}

static int test_cczp_inv(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init(zp);

    int res;
    cc_unit x[n];
    cc_unit r[n];

    ccn_seti(n, x, 1);
    res = cczp_inv(zp, r, x); // 1 / 1
    is(res, 0, "cczp_inv failure");
    is(ccn_is_one(n, r), 1, "cczp_inv failure");

    ccn_seti(n, x, 2);
    res = cczp_inv(zp, r, x); // 1 / 2
    cczp_mul(zp, r, r, x);
    is(res, 0, "cczp_inv failure");
    is(ccn_is_one(n, r), 1, "cczp_inv failure");

    ccn_sub1(n, x, p, 1);
    res = cczp_inv(zp, r, x); // 1 / (p - 1)
    cczp_mul(zp, r, r, x);
    is(res, 0, "cczp_inv failure");
    is(ccn_is_one(n, r), 1, "cczp_inv failure");

    res = cczp_inv(zp, r, p); // 1 / p
    isnt(res, 0, "cczp_inv should have failed");

    ccn_clear(n, x);
    res = cczp_inv(zp, r, x); // 1 / 0
    isnt(res, 0, "cczp_inv should have failed");

    return 0;
}

static int test_cczp_inv_fast(void)
{
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    ccn_sub1(n, CCZP_PRIME(zp), CCZP_PRIME(zp), 2);
    cczp_init(zp);

    int res;
    cc_unit x[n];
    cc_unit r[n];

    ccn_seti(n, x, 1);
    res = cczp_inv_fast(zp, r, x); // 1 / 1
    is(res, 0, "inv_fast failure");
    is(ccn_is_one(n, r), 1, "inv_fast failure");

    ccn_seti(n, x, 2);
    res = cczp_inv_fast(zp, r, x); // 1 / 2
    cczp_mul(zp, r, r, x);
    is(res, 0, "inv_fast failure");
    is(ccn_is_one(n, r), 1, "inv_fast failure");

    ccn_seti(n, x, 17);
    res = cczp_inv_fast(zp, r, x); // 1 / 17
    isnt(res, 0, "inv_fast should have failed");

    return 0;
}

static int test_cczp_quadratic_residue(void)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CC_MAX_EVAL(CCZP_INIT_WORKSPACE_N(n),
                                              CCZP_IS_QUADRATIC_RESIDUE_WORKSPACE_N(n)));

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init_ws(ws, zp);

    int res;
    cc_unit x[n];

    ccn_seti(n, x, 23); // 23 is a quadratic residue
    res = cczp_is_quadratic_residue_ws(ws, zp, x);
    is(res, 1, "QR test failure: x = 23 is a QR");

    ccn_seti(n, x, 235); // 235 is not a quadratic residue
    res = cczp_is_quadratic_residue_ws(ws, zp, x);
    isnt(res, 1, "QR test failure: x = 235 is not a QR");

    ccn_set(n, x, p);
    res = cczp_is_quadratic_residue_ws(ws, zp, x);
    isnt(res, 1, "QR test failure: x = p is not a QR");

    x[0] += 1;
    res = cczp_is_quadratic_residue_ws(ws, zp, x);
    isnt(res, 1, "QR test failure: x = p + 1 is invalid");

    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return 0;
}

static int test_cczp_mod_2n(void)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, CC_MAX_EVAL(CCZP_INIT_WORKSPACE_N(n),
                                              CCZP_MOD_WORKSPACE_N(n)));

    cc_size n = 2;
    cc_unit a[2 * n], r[n];
    ccn_seti(2 * n, a, 0x51);

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_seti(n, CCZP_PRIME(zp), 0x10);
    cczp_init_ws(ws, zp);

    cczp_mod_ws(ws, zp, r, a);
    is(ccn_n(n, r), 1, "wrong remainder");
    is(r[0], 0x01, "wrong remainder");

    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return 0;
}

int cczp_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int num_tests = 0;
    num_tests += 2 + ((3ULL << 24) - CC_ARRAY_LEN(expected_recips)); // test_cczp_init
    num_tests += 1 + 35;                                // test_cczp_power_fns
    num_tests += 2 + (2 * 15 * NUM_RANDOM_POWER_TESTS); // test_cczp_power_fns_randomized
    num_tests += 1 + 15;                                // test_cczp_sqrt

    num_tests += 2 + (2 * (3 * NUM_RANDOM_SQRT_TESTS)); // test_cczp_sqrt_randomized
    num_tests += 1 + (2 * NUM_RANDOM_SQRT_TESTS);       // test_cczp_sqr_vs_mul
    num_tests += 1 + 2;                                 // test_cczp_add_sub
    num_tests += 1 + 4;                                 // test_cczp_div2
    num_tests += 3 + 3 * 3;                             // test_cczp_modn
    num_tests += 1 + 3;                                 // test_cczp_mod
    num_tests += 1 + 8;                                 // test_cczp_inv
    num_tests += 1 + 5;                                 // test_cczp_inv_fast
    num_tests += 1 + 4;                                 // test_cczp_quadratic_residue
    num_tests += 1 + 2;                                 // test_cczp_mod_2n

    plan_tests(num_tests);

    is(test_cczp_init(), 0, "test_cczp_init failed");

    is(test_cczp_power_fns(), 0, "test_cczp_power_fns failed");
    is(test_cczp_power_fns_randomized(ccec_cp_zq(ccec_cp_256())), 0, "test_cczp_power_fns_randomized failed");
    is(test_cczp_power_fns_randomized(ccec_cp_zq(ccec_cp_384())), 0, "test_cczp_power_fns_randomized failed");

    is(test_cczp_sqrt(), 0, "test_cczp_sqrt failed");

    ccec_const_cp_t p224 = ccec_cp_224(); // q == 1 mod 4
    is(test_cczp_sqrt_randomized(ccec_cp_zq(p224), ccec_cp_n(p224)), 0, "test_cczp_sqrt_randomized p224 failed");
    ccec_const_cp_t p384 = ccec_cp_384(); // q == 3 mod 4
    is(test_cczp_sqrt_randomized(ccec_cp_zq(p384), ccec_cp_n(p384)), 0, "test_cczp_sqrt_randomized p384 failed");

    is(test_cczp_sqr_vs_mul(), 0, "test_cczp_sqr_vs_mul failed");

    is(test_cczp_add_sub(), 0, "test_cczp_add_sub failed");

    is(test_cczp_div2(), 0, "test_cczp_div2 failed");

    is(test_cczp_modn(1), 0, "test_cczp_modn failed");
    is(test_cczp_modn(2), 0, "test_cczp_modn failed");
    is(test_cczp_modn(4), 0, "test_cczp_modn failed");
    is(test_cczp_mod(), 0, "test_cczp_mod failed");

    is(test_cczp_inv(), 0, "test_cczp_inv failed");

    is(test_cczp_inv_fast(), 0, "test_cczp_inv_fast failed");

    is(test_cczp_quadratic_residue(), 0, "test_cczp_quadratic_residue failed");

    is(test_cczp_mod_2n(), 0, "test_cczp_mod_2n failed");

    return 0;
}
