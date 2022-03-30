/* Copyright (c) (2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_debug.h"
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include "crypto_test_ccn.h"
#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"
#include "ccn_op.h"
#include "ccn_internal.h"
#include "cc_memory.h"
#include <corecrypto/cc.h>
#include "cczp_internal.h"

static int test_ccn_sqr()
{
    ccnBuffer input = hexStringToCcn("FFFFFFFFffffffffFFFFFFFFffffffffFFFFFFFFffffffff");
    cc_size n = input->len;
    cc_unit square_result[n * 2];
    cc_unit square_ws_result[n * 2];
    cc_unit mult_result[n * 2];

    CC_DECL_WORKSPACE_OR_FAIL(workspace, CCN_MUL_WS_WORKSPACE_N(n));
    ccn_sqr_ws(workspace, n, square_ws_result, input->units);
    CC_FREE_WORKSPACE(workspace);

    ccn_sqr(n, square_result, input->units);
    ccn_mul(n, mult_result, input->units, input->units);

    ok_ccn_cmp(n, square_result, mult_result, "ccn_sqr failed");
    ok_ccn_cmp(n, square_ws_result, mult_result, "ccn_sqr_ws failed");

    free(input);
    
    return 1;
}

static void mult(cc_unit *r, cc_size ns, const cc_unit *s, cc_size nt, const cc_unit *t)
{
    cc_assert(r != s);
    cc_assert(r != t);

    r[ns] = ccn_mul1(ns, r, s, t[0]);
    while (nt > 1) {
        r += 1;
        t += 1;
        nt -= 1;
        r[ns] = ccn_addmul1(ns, r, s, t[0]);
    }
}

static int verify_ccn_div_euclid(cc_size nq,
                                 const cc_unit *q,
                                 cc_size nr,
                                 const cc_unit *r,
                                 cc_size na,
                                 const cc_unit *a,
                                 cc_size nd,
                                 const cc_unit *d)
{
    cc_unit v[nq + nd];
    // ccn_zero(nq+nd, v);
    mult(v, nq, q, nd, d);
    ccn_addn(nq + nd, v, v, nr, r);

    int rc = ccn_cmp(na, a, v);
    return rc;
}

#define CCN_READ_WRITE_TEST_N 3
#define CCN_READ_WRITE_TEST_BYTES ccn_sizeof_n(CCN_READ_WRITE_TEST_N)
static int test_ccn_write_test(size_t size) {
    int rc = 1;
    cc_assert(size<=CCN_READ_WRITE_TEST_BYTES);
    cc_unit t [CCN_READ_WRITE_TEST_N];
    uint8_t t_bytes[size+1+CCN_UNIT_SIZE];
    uint8_t expected_t_bytes[size+2+CCN_UNIT_SIZE];
    
    
    size_t MSByte_index = sizeof(expected_t_bytes)-size-1;
    size_t LSByte_index = sizeof(expected_t_bytes)-2;
    
    // Set a big integer with the given size
    ccn_clear(CCN_READ_WRITE_TEST_N,t);
    cc_clear(sizeof(expected_t_bytes),expected_t_bytes);
    if (size>0) {
        ccn_set_bit(t, 0, 1);
        ccn_set_bit(t, size*8-1, 1);
        expected_t_bytes[LSByte_index]=0x01;
        expected_t_bytes[MSByte_index]|=0x80;
    }
    if (size>1) {
        ccn_set_bit(t, 9, 1);
        expected_t_bytes[LSByte_index-1]|=0x02;
    }
    
    // Test ccn_write_uint, which supports truncation
    if(size>0) {
        ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes);
        rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size-1, "Size %zu: Truncated output",size);
    }
    ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size,t_bytes);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);
    
    ccn_write_uint(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Extra output",size);
    
    // Test ccn_write_uint_padded, which supports truncation and padding
    if(size>0) {
        rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes), 0, "Size %zu: return value",size);
        rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size-1, "Size %zu: Truncated output",size);
    }
    rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size,t_bytes), 0, "Size %zu: Truncated output",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);
    
    rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes), 1, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1], size+1, "Size %zu: Extra output",size);
    
    rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+CCN_UNIT_SIZE,t_bytes), CCN_UNIT_SIZE, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);
    
    rc&=is(ccn_write_uint_padded(CCN_READ_WRITE_TEST_N,t,size+1+CCN_UNIT_SIZE,t_bytes), 1+CCN_UNIT_SIZE, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1-CCN_UNIT_SIZE], size+1, "Size %d: Extra output",size);
    
    // Test ccn_write_uint_padded_ct, which supports padding, but not truncation
    if(size>0) {
        rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size-1,t_bytes), CCERR_PARAMETER, "Size %zu: return value",size);
    }
    rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size,t_bytes), 0, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index], size, "Size %zu: Exact output",size);
    
    rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+1,t_bytes), 1, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1], size+1, "Size %zu: Extra output",size);
    
    rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+CCN_UNIT_SIZE,t_bytes), CCN_UNIT_SIZE, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);
    
    rc&=is(ccn_write_uint_padded_ct(CCN_READ_WRITE_TEST_N,t,size+1+CCN_UNIT_SIZE,t_bytes), 1+CCN_UNIT_SIZE, "Size %zu: return value",size);
    rc&=ok_memcmp(t_bytes, &expected_t_bytes[MSByte_index-1-CCN_UNIT_SIZE], size+1, "Size %zu: Extra output",size);
    
    return rc;
}

static int test_ccn_read_test(size_t size) {
    int rc = 1;
    cc_assert(size<=CCN_READ_WRITE_TEST_BYTES);
    cc_unit expected_t [CCN_READ_WRITE_TEST_N];
    cc_unit t [CCN_READ_WRITE_TEST_N];
    uint8_t t_bytes[CCN_READ_WRITE_TEST_BYTES];
    
    // Set a big integer with the given size
    size_t MSByte_index = sizeof(t_bytes)-size;
    size_t LSByte_index = sizeof(t_bytes)-1;
    ccn_clear(CCN_READ_WRITE_TEST_N,expected_t);
    cc_clear(sizeof(t_bytes),t_bytes);
    if (size>0) {
        ccn_set_bit(expected_t, 0, 1);
        ccn_set_bit(expected_t, size*8-1, 1);
        t_bytes[LSByte_index]=0x01;
        t_bytes[MSByte_index]|=0x80;
    }
    if (size>1) {
        ccn_set_bit(expected_t, 9, 1);
        t_bytes[LSByte_index-1]|=0x02;
    }

    rc&=is(ccn_read_uint(CCN_READ_WRITE_TEST_N,t,CCN_READ_WRITE_TEST_BYTES,t_bytes),0,"Size %zu: Return value",size);
    rc&=ok_ccn_cmp(CCN_READ_WRITE_TEST_N, t, expected_t, "Size %zu: Exact size",size);
    
    if (size>0) {
        rc&=is(ccn_read_uint(ccn_nof_size(size)-1,t,size,&t_bytes[MSByte_index]),CCERR_PARAMETER,"Size %zu: Overflow protection",size);
    }
    
    return rc;
}

#define num_of_tests_ccn_read_write 621 // Keep track of number of tests below so we can add to total testplan count
static int test_ccn_read_write() {
    int rc = 1;
    for (size_t i=0;i<=CCN_READ_WRITE_TEST_BYTES;i++) {
        rc&=test_ccn_read_test(i);
        rc&=test_ccn_write_test(i);
    }
    return rc;
}

static int test_ccn_div(size_t modulus_bits, size_t modulus_real_bits, size_t divisor_bits)
{
    struct ccrng_state *rng = global_test_rng;
    if (modulus_real_bits > modulus_bits)
        modulus_real_bits = modulus_bits;

    // create divisor
    cc_size nd = ccn_nof(modulus_bits);
    cc_unit d[nd];
    cc_unit r[nd];
    ccn_zero(nd, d);
    ccn_random_bits(modulus_real_bits, d, rng);

    // create random dividend
    cc_size na = ccn_nof(divisor_bits);
    cc_unit a[na];
    ccn_zero(na, a);
    cc_unit q[na];
    ccn_zero(na, q);
    ccn_random_bits(divisor_bits, a, rng);

    // other rc's are input parameter error and are considered fine here
    int rc = ccn_div_euclid(na, q, nd, r, na, a, nd, d);
    ok(rc != -1, "ccn_div_euclid() returned error");
    if (rc == 0) {
        rc = verify_ccn_div_euclid(na, q, nd, r, na, a, nd, d);
    } else
        rc = 0;

    return rc;
}

static void ccn_addn_kat()
{
    ccnBuffer s = hexStringToCcn("FFFFFFFFffffffffFFFFFFFFffffffffFFFFFFFFffffffff");
    ccnBuffer t = hexStringToCcn("00000000000000000000000000000001");
    cc_size n = s->len;
    cc_unit r[n];

    cc_unit cr = ccn_add(t->len, r, s->units, t->units);
    ok(cr == 1, "ccn_add carry KAT");
    ok(ccn_is_zero(t->len, r), "ccn_add KAT");

    cr = ccn_addn(n, r, s->units, t->len, t->units);
    ok(cr == 1, "ccn_addn KAT");
    ok(ccn_is_zero(n, r), "ccn_addn KAT");

    cr = ccn_addn(t->len, r, s->units, t->len, t->units);
    ok(cr == 1, "ccn_addn carry KAT");
    ok(ccn_is_zero(t->len, r), "ccn_add KAT");

    cr = ccn_add1(0, r, r, 7);
    ok(cr == 7, "ccn_add1 carry KAT");

    cr = ccn_addn(n, r, s->units, n, s->units);
    ok(cr == 1, "ccn_addn carry KAT");

    free(s);
    free(t);
}

const struct rshift_test_vector {
    const char *r;
    const char *x;
    const char *k;
} rshift_test_vectors[] = {
#include "../test_vectors/shift_right.kat"
};

const size_t rshift_test_vectors_num = CC_ARRAY_LEN(rshift_test_vectors);

static int test_ccn_shift_right()
{
    for (unsigned i = 0; i < rshift_test_vectors_num; i++) {
        const struct rshift_test_vector *test = &rshift_test_vectors[i];

        ccnBuffer r = hexStringToCcn(test->r);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer k = hexStringToCcn(test->k);

        cc_size n = x->len;
        cc_unit r2[n];

        ccn_shift_right_multi(n, r2, x->units, (size_t)k->units[0]);
        ok_ccn_cmp(r->len, r->units, r2, "r = x >> %llu", k->units[0]);

        if (k->units[0] < CCN_UNIT_BITS) {
            ccn_cond_shift_right(n, 1, r2, x->units, (size_t)k->units[0]);
            ok_ccn_cmp(r->len, r->units, r2, "r = x >> %llu", k->units[0]);
        } else {
            ok(true, "easier to calculate the test count that way");
        }

        free(r);
        free(x);
        free(k);
    }

    return 0;
}

const struct lshift_test_vector {
    const char *r;
    const char *x;
    const char *k;
} lshift_test_vectors[] = {
#include "../test_vectors/shift_left.kat"
};

const size_t lshift_test_vectors_num = CC_ARRAY_LEN(lshift_test_vectors);

static int test_ccn_shift_left()
{
    for (unsigned i = 0; i < lshift_test_vectors_num; i++) {
        const struct lshift_test_vector *test = &lshift_test_vectors[i];

        ccnBuffer r = hexStringToCcn(test->r);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer k = hexStringToCcn(test->k);

        cc_size n = r->len;
        cc_unit r2[n], x2[n];
        ccn_setn(n, x2, x->len, x->units);

        ccn_shift_left_multi(n, r2, x2, (size_t)k->units[0]);
        ok_ccn_cmp(n, r->units, r2, "r = x << %llu", k->units[0]);

        free(r);
        free(x);
        free(k);
    }

    return 0;
}

static void test_ccn_sub1(void)
{
    cc_size n = 1;
    cc_unit r[n];
    cc_unit s[n];

    ccnBuffer t1 = hexStringToCcn("00000000000000000000000000000001");
    ccnBuffer t2 = hexStringToCcn("ffffffffffffffffffffffffffffffff");
    ccnBuffer t3 = hexStringToCcn("00000001000000000000000000000001");

    cc_unit borrow = ccn_sub1(0, r, s, 7);
    is(borrow, (cc_unit)7, "ccn_sub1 with zero length scalar failed");

    borrow = ccn_sub1(t1->len, t1->units, t1->units, 1);
    is(borrow, 0, "ccn_sub1 shouldn't borrow");
    ok(ccn_is_zero(t1->len, t1->units), "t1 should be 0");

    borrow = ccn_sub1(t1->len, t1->units, t1->units, 1);
    is(borrow, 1, "ccn_sub1 should borrow");
    ok_ccn_cmp(t1->len, t1->units, t2->units, "t1 should be -1");

    borrow = ccn_sub1(t2->len, t2->units, t2->units, ~CC_UNIT_C(0));
    is(borrow, 0, "ccn_sub1 shouldn't borrow");

    borrow = ccn_sub1(t3->len, t3->units, t3->units, 1);
    is(borrow, 0, "ccn_sub1 shouldn't borrow");
    ok(!ccn_is_zero(t3->len, t3->units), "t3 shouldn't be 0");

    borrow = ccn_subn(t3->len, t3->units, t3->units, t2->len, t2->units);
    is(borrow, 1, "ccn_subn should borrow");

    free(t1);
    free(t2);
    free(t3);
}

static int test_ccn_cmp_zerolen(void)
{
    int cmp;
    cc_size n = 0;
    cc_unit r[1];
    cc_unit s[1];

    cmp = ccn_cmp(n, r, s);
    is(cmp, 0, "ccn_cmp with size zero should return zero");

    return 1;
}

static void test_ccn_bitlen(void)
{
    cc_unit z[5] = {0, 0, 0, 0, 0};
    is(ccn_bitlen(5, z), 0, "ccn_bitlen() returned wrong result");
    is(ccn_bitlen(0, z), 0, "ccn_bitlen() returned wrong result");

    cc_unit a[5] = {0, 0, 1, 0, 0};
    is(ccn_bitlen(5, a), 2 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit b[5] = {1, 0, 1, 0, 0};
    is(ccn_bitlen(5, b), 2 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit c[5] = {1, 0, 1, 0, 1};
    is(ccn_bitlen(5, c), 4 * CCN_UNIT_BITS + 1, "ccn_bitlen() returned wrong result");

    cc_unit d[5] = {1, 0, 0, 0, 0};
    is(ccn_bitlen(5, d), 1, "ccn_bitlen() returned wrong result");
}

static int test_ccn_abs(void)
{
    cc_unit a[1] = {5};
    cc_unit b[1] = {4};
    cc_unit r[1];

    CC_DECL_WORKSPACE_OR_FAIL(ws, CCN_ABS_WORKSPACE_N(1));

    is(ccn_abs_ws(ws, 1, r, a, b), 0, "ccn_abs() returned wrong result");
    ok(ccn_is_one(1, r), "ccn_abs() computed wrong result");

    is(ccn_abs_ws(ws, 1, r, a, a), 0, "ccn_abs() returned wrong result");
    ok(ccn_is_zero(1, r), "ccn_abs() computed wrong result");

    is(ccn_abs_ws(ws, 1, r, b, a), 1, "ccn_abs() returned wrong result");
    ok(ccn_is_one(1, r), "ccn_abs() computed wrong result");

    CC_FREE_WORKSPACE(ws);
    return 0;
}

static void test_ccn_cmpn()
{
    cc_unit a[4] = { 1, 2, 0, 0 };
    cc_unit b[4] = { 1, 2, 0, 3 };

    // ns == nt
    is(ccn_cmpn(0, a, 0, b), 0, "{} == {}");
    is(ccn_cmpn(1, a, 1, b), 0, "{1} == {1}");
    is(ccn_cmpn(2, a, 2, b), 0, "{1,2} == {1,2}");
    is(ccn_cmpn(3, a, 3, b), 0, "{1,2,0} == {1,2,0}");
    is(ccn_cmpn(4, a, 4, b), -1, "{1,2,0,0} < {1,2,0,3}");
    is(ccn_cmpn(4, b, 4, a), 1, "{1,2,0,3} > {1,2,0,0}");

    // ns > nt
    is(ccn_cmpn(4, a, 3, b), 0, "{1,2,0,0} == {1,2,0}");
    is(ccn_cmpn(4, a, 2, b), 0, "{1,2,0,0} == {1,2}");
    is(ccn_cmpn(3, a, 2, b), 0, "{1,2,0} == {1,2}");
    is(ccn_cmpn(4, a, 1, b), 1, "{1,2,0,0} > {1}");
    is(ccn_cmpn(3, a, 1, b), 1, "{1,2,0} > {1}");
    is(ccn_cmpn(2, a, 1, b), 1, "{1,2} > {1}");
    is(ccn_cmpn(1, a, 0, b), 1, "{1} > {}");

    // ns < nt
    is(ccn_cmpn(3, b, 4, a), 0, "{1,2,0} == {1,2,0,0}");
    is(ccn_cmpn(2, b, 4, a), 0, "{1,2} == {1,2,0,0}");
    is(ccn_cmpn(2, b, 3, a), 0, "{1,2} == {1,2,0}");
    is(ccn_cmpn(1, b, 4, a), -1, "{1} < {1,2,0,0}");
    is(ccn_cmpn(1, b, 3, a), -1, "{1} < {1,2,0}");
    is(ccn_cmpn(1, b, 2, a), -1, "{1} < {1,2}");
    is(ccn_cmpn(0, b, 1, a), -1, "{} < {1}");
}

const struct gcd_test_vector {
    const char *gcd;
    const char *a;
    const char *b;
    const char *lcm;
} gcd_test_vectors[] = {
#include "../test_vectors/gcd_lcm.kat"
};

const size_t gcd_test_vectors_num = CC_ARRAY_LEN(gcd_test_vectors);

static int test_ccn_gcd()
{
    for (unsigned i = 0; i < gcd_test_vectors_num; i++) {
        const struct gcd_test_vector *test = &gcd_test_vectors[i];

        ccnBuffer gcd = hexStringToCcn(test->gcd);
        ccnBuffer a = hexStringToCcn(test->a);
        ccnBuffer b = hexStringToCcn(test->b);
        ccnBuffer lcm = hexStringToCcn(test->lcm);

        cc_size n = CC_MAX(a->len, b->len);
        cc_unit r[2 * n], an[n], bn[n];

        CC_DECL_WORKSPACE_OR_FAIL(ws,
            CC_MAX(CCN_GCD_WORKSPACE_N(n), CCN_LCM_WORKSPACE_N(n)));

        size_t k = ccn_gcd_ws(ws, n, r, a->len, a->units, b->len, b->units);
        ccn_shift_left_multi(n, r, r, k);
        ok_ccn_cmp(gcd->len, gcd->units, r, "r = gcd(a, b)");

        if (ccn_is_zero(n, r)) {
            ok(true, "hard to predict the test count otherwise");
        } else {
            ccn_setn(n, an, a->len, a->units);
            ccn_setn(n, bn, b->len, b->units);

            ccn_lcm_ws(ws, n, r, an, bn);
            ok_ccn_cmp(lcm->len, lcm->units, r, "r = lcm(a, b)");
        }

        CC_FREE_WORKSPACE(ws);

        free(gcd);
        free(a);
        free(b);
        free(lcm);
    }

    return 0;
}

static int test_ccn_div_exact()
{
    cc_size n = ccn_nof(256);
    cc_unit a[n * 2], b[n * 2], c[n * 2], r1[n * 2], r2[n * 2];
    ccn_clear(n * 2, a);
    ccn_clear(n * 2, b);

    CC_DECL_WORKSPACE_OR_FAIL(ws,
        CCN_DIV_EUCLID_WORKSPACE_SIZE(2 * n, 2 * n) + CCN_DIV_EXACT_WORKSPACE_N(2 * n));

    for (size_t i = 0; i < 2000; i++) {
        ccn_random(n, a, global_test_rng);
        ccn_random(n, b, global_test_rng);
        ccn_mul(n, c, a, b);

        ccn_div_exact_ws(ws, n * 2, r1, c, b);
        is(ccn_div_ws(ws, n * 2, r2, n * 2, c, n * 2, b), CCERR_OK, "ccn_div_ws() succeeded");
        ok_ccn_cmp(n * 2, r1, r2, "quotients match");
    }

    // x / x == 1
    ccn_div_exact_ws(ws, n, a, a, a);
    ok(ccn_is_one(n * 2, a), "x / x == 1");

    // x / 1 == x
    ccn_div_exact_ws(ws, n, a, b, a);
    ok_ccn_cmp(n, a, b, "x / 1 == x");

    CC_FREE_WORKSPACE(ws);
    return 0;
}

static int test_ccn_div_2n()
{
    cc_size n = 2;
    cc_unit q[n], r[n], a[n], d[n];

    ccn_seti(n, a, 0x51);
    ccn_seti(n, d, 0x10);

    int rv = ccn_div_euclid(n, q, n, r, n, a, n, d);
    is(rv, CCERR_OK, "ccn_div_euclid() failed");

    is(ccn_n(n, q), 1, "wrong quotient");
    is(q[0], 0x05, "wrong quotient");
    is(ccn_n(n, r), 1, "wrong remainder");
    is(r[0], 0x01, "wrong remainder");

    return 0;
}

const struct invmod_test_vector {
    const char *inv;
    const char *x;
    const char *m;
    int rv;
} invmod_test_vectors[] = {
#include "../test_vectors/invmod.kat"
};

const size_t invmod_test_vectors_num = CC_ARRAY_LEN(invmod_test_vectors);

static int test_ccn_invmod()
{
    for (unsigned i = 0; i < invmod_test_vectors_num; i++) {
        const struct invmod_test_vector *test = &invmod_test_vectors[i];

        ccnBuffer inv = hexStringToCcn(test->inv);
        ccnBuffer x = hexStringToCcn(test->x);
        ccnBuffer m = hexStringToCcn(test->m);

        cc_size n = m->len;
        cc_unit r[n];

        CC_DECL_WORKSPACE_OR_FAIL(ws, CCN_INVMOD_WORKSPACE_N(n) +
            CCZP_INIT_WORKSPACE_N(n) + CCZP_INV_FAST_WORKSPACE_N(n));

        int rv = ccn_invmod_ws(ws, n, r, x->len, x->units, m->units);
        is(rv, test->rv, "unexpected ccn_invmod_ws() result");
        ok_ccn_cmp(inv->len, inv->units, r, "r = ccn_invmod_ws(x, m)");

        // Test cczp_inv() and cczp_inv_fast().
        if ((m->units[0] & 1) && ccn_cmpn(m->len, m->units, x->len, x->units) > 0) {
            cczp_decl_n(n, zp);
            CCZP_N(zp) = n;

            ccn_set(n, CCZP_PRIME(zp), m->units);
            cczp_init_ws(ws, zp);

            cc_unit xn[n];
            ccn_setn(n, xn, x->len, x->units);

            int rv = cczp_inv_ws(ws, zp, r, xn);
            is(rv, test->rv, "unexpected cczp_inv() result");
            ok_ccn_cmp(inv->len, inv->units, r, "r = cczp_inv(x, m)");

            rv = cczp_inv_fast_ws(ws, zp, r, xn);
            is(rv, test->rv, "unexpected cczp_inv_fast() result");
            ok_ccn_cmp(inv->len, inv->units, r, "r = cczp_inv_fast(x, m)");
        } else {
            ok(true, "always increase test count");
            ok(true, "always increase test count");
            ok(true, "always increase test count");
            ok(true, "always increase test count");
        }

        CC_FREE_WORKSPACE(ws);

        free(inv);
        free(x);
        free(m);
    }

    return 0;
}

#define MODULUS_BITS 653
#define MODULUS_REAL_BITS 457
#define DIVISOR_BITS 1985
int ccn_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int rc = 0;
    size_t modulus_bits = MODULUS_BITS;
    size_t modulus_real_bits = MODULUS_REAL_BITS;
    size_t divisor_bits = DIVISOR_BITS;

    int num_tests = 100335 + num_of_tests_ccn_read_write;
    num_tests += 20;   // ccn_cmpn
    num_tests += 4002; // ccn_div_exact
    num_tests += 5;    // ccn_div_2n
    num_tests += gcd_test_vectors_num * 2;    // ccn_gcd
    num_tests += rshift_test_vectors_num * 2; // ccn_shift_right
    num_tests += lshift_test_vectors_num;     // ccn_shift_left
    num_tests += invmod_test_vectors_num * 6; // ccn_invmod
    plan_tests(num_tests);

    // Functional tests
    for (int i = 0; i < 25000; i++) {
        modulus_bits = cc_rand_unit() % 753 + 30;
        modulus_real_bits = modulus_bits / (cc_rand_unit() % 4 + 1) + cc_rand_unit() % 5;

        divisor_bits = modulus_bits * (cc_rand_unit() % 4 + 1) + cc_rand_unit() % 7;
        rc = test_ccn_div(modulus_bits, modulus_real_bits, divisor_bits);
        is(rc, 0, "test_ccn_div() division results doesn't verify");

        divisor_bits = modulus_bits / (cc_rand_unit() % 3 + 1) + cc_rand_unit() % 7;
        rc = test_ccn_div(modulus_bits, modulus_real_bits, divisor_bits);
        is(rc, 0, "test_ccn_div() division results doesn't verify");
    }

    // Negative tests
    cc_unit d[2] = { 0, 0 };
    cc_unit a[5] = { 5, 4, 3, 2, 1 };
    cc_unit q[5], r[2];

    rc = ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
    is(rc, -2, "ccn_div_euclid() division by zero");
    for (int i = 50; i >= 1; i--) {
        d[0] = (cc_unit)i;
        rc = ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
        is(rc, 0, "ccn_div_euclid()");
        rc = verify_ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
        is(rc, 0, "ccn_div_euclid() division by small divisor");
    }

    // Make sure arithmetic right shift is in place
    for (int i = 0; i < 200; i++) {
        cc_unit v = cc_rand_unit();
        ok(ccop_msb(v) == (ccn_bit(&v, CCN_UNIT_BITS - 1) ? ~(cc_unit)0 : 0), "ccop_msb() produces incorrect result");
    }

    ccn_addn_kat();
    test_ccn_sub1();
    test_ccn_shift_right();
    test_ccn_shift_left();
    is(test_ccn_sqr(), 1, "test_ccn_sqr failed");
    is(test_ccn_cmp_zerolen(), 1, "test_ccn_cmp_zerolen failed");
    is(test_ccn_read_write(),1, "test_ccn_read_write failed");
    test_ccn_bitlen();
    test_ccn_abs();
    test_ccn_cmpn();
    test_ccn_gcd();
    test_ccn_div_exact();
    test_ccn_div_2n();
    test_ccn_invmod();

    return rc;
}
