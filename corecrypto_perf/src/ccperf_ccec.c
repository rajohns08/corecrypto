/* Copyright (c) (2011,2012,2014-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccperf.h"
#include "cczp_internal.h"
#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>

static ccec_const_cp_t ccec_cp(size_t nbits) {
    switch (nbits) {
        case (192):
            return ccec_cp_192();
        case (224):
            return ccec_cp_224();
        case (256):
            return ccec_cp_256();
        case (384):
            return ccec_cp_384();
        case (521): /* -- 544 = 521 rounded up to the nearest multiple of 32*/
            return ccec_cp_521();
        default:
            return (ccec_const_cp_t)(const struct cczp* )0;
    }
}

static struct ccec_full_ctx* gkey=NULL;

static void update_gkey(ccec_const_cp_t cp) {
    if (gkey==NULL || (ccec_cp_prime_bitlen(ccec_ctx_cp(gkey))!=ccec_cp_prime_bitlen(cp))) {
        gkey = realloc(gkey, ccec_full_ctx_size(ccec_ccn_size(cp)));
        int status=ccec_generate_key_internal_fips(cp, rng, gkey);
        if (status) abort();
    }
}

static double perf_ccec_compact_import_pub(size_t loops, ccec_const_cp_t cp)
{
    update_gkey(cp);

    size_t  export_pubsize = ccec_compact_export_size(0, ccec_ctx_pub(gkey));
    uint8_t exported_pubkey[export_pubsize];
    ccec_pub_ctx_decl_cp(ccec_ctx_cp(gkey), reconstituted_pub);
    ccec_compact_export(0, exported_pubkey, gkey);
    
    perf_start();
    do {
        int status=ccec_compact_import_pub(ccec_ctx_cp(gkey), export_pubsize, exported_pubkey, reconstituted_pub);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_legacy(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_legacy(cp, rng, key);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_fips(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_fips(cp, rng, key);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_compact_generate_key(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_compact_generate_key(cp, rng, key);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_internal_fips(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_internal_fips(cp, rng, key);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_sign(size_t loops, ccec_const_cp_t cp)
{
    size_t original_siglen = ccec_sign_max_size(cp);
    size_t siglen = original_siglen;
    uint8_t sig[siglen];
    uint8_t digest[24] = "012345678912345678901234";

    update_gkey(cp);

    perf_start();
    do {
        siglen = original_siglen;
        int status=ccec_sign(gkey, sizeof(digest), digest, &siglen, sig, rng);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_verify(size_t loops, ccec_const_cp_t cp)
{
    size_t siglen = ccec_sign_max_size(cp);
    uint8_t sig[siglen];
    uint8_t digest[24] = "012345678912345678901234";
    bool ok;

    update_gkey(cp);

    ccec_sign(gkey, sizeof(digest), digest, &siglen, sig, rng);

    perf_start();
    do {
        int status=ccec_verify(ccec_ctx_pub(gkey), sizeof(digest), digest, siglen, sig, &ok);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccecdh_compute_shared_secret(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key2);
    uint8_t out1[ccec_ccn_size(cp)];
    size_t out1_len;

    // Key 1
    update_gkey(cp);

    // Key 2
    int status=ccec_generate_key_internal_fips(cp, rng, key2);
    if (status) abort();

    perf_start();
    do {
        out1_len=sizeof(out1);
        status=ccecdh_compute_shared_secret(gkey, ccec_ctx_pub(key2), &out1_len, out1, NULL);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccecdh_generate_key(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);
    ccec_ctx_init(cp, key);

    perf_start();
    do {
        if (ccecdh_generate_key(cp, rng, key)) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_ccec_diversify_pub_twin(size_t loops, ccec_const_cp_t cp)
{
    ccec_pub_ctx_decl_cp(cp, pub_out);
    ccec_ctx_init(cp, pub_out);

    ccec_full_ctx_decl_cp(cp, full);
    ccec_ctx_init(cp, full);

    if (ccec_generate_key(cp, rng, full)) {
        abort();
    }

    uint8_t entropy[ccec_diversify_min_entropy_len(cp) * 2];
    if (ccrng_generate(rng, sizeof(entropy), entropy)) {
        abort();
    }

    perf_start();
    do {
        if (ccec_diversify_pub_twin(cp, ccec_ctx_pub(full), sizeof(entropy), entropy, rng, pub_out)) {
            abort();
        }
    } while (--loops != 0);

    return perf_seconds();
}

static double perf_ccec_cczp_mul(size_t loops, ccec_const_cp_t cp)
{
    cczp_const_t zp = (cczp_const_t)cp;
    cc_size n = cczp_n(zp);

    cc_unit a[n], r[n * 2];
    cczp_generate_non_zero_element(zp, rng, a);

    CC_DECL_WORKSPACE_STACK(ws, CCZP_MUL_WORKSPACE_N(n));

    perf_start();
    do {
        cczp_mul_ws(ws, zp, r, a, a);
    } while (--loops != 0);

    CC_FREE_WORKSPACE_STACK(ws);

    return perf_seconds();
}

static double perf_ccec_cczp_inv_mod_p(size_t loops, ccec_const_cp_t cp)
{
    cczp_const_t zp = ccec_cp_zp(cp);
    cc_size n = cczp_n(zp);

    cc_unit a[n], r[n];
    cczp_generate_non_zero_element(zp, rng, a);

    CC_DECL_WORKSPACE_STACK(ws, CCZP_INV_WORKSPACE_N(n));

    perf_start();
    do {
        if (cczp_inv_ws(ws, zp, r, a)) {
            abort();
        }
    } while (--loops != 0);

    CC_FREE_WORKSPACE_STACK(ws);

    return perf_seconds();
}

static double perf_ccec_cczp_inv_mod_q(size_t loops, ccec_const_cp_t cp)
{
    cczp_const_t zq = ccec_cp_zq(cp);
    cc_size n = cczp_n(zq);

    cc_unit a[n], r[n];
    ccn_random_bits(ccec_cp_prime_bitlen(cp), a, rng);

    CC_DECL_WORKSPACE_STACK(ws, CCZP_INV_WORKSPACE_N(cczp_n(zq)));

    perf_start();
    do {
        if (cczp_inv_ws(ws, zq, r, a)) {
            abort();
        }
    } while (--loops != 0);

    CC_FREE_WORKSPACE_STACK(ws);

    return perf_seconds();
}

static double perf_ccec_cczp_sqrt(size_t loops, ccec_const_cp_t cp)
{
    cczp_const_t zp = (cczp_const_t)cp;
    cc_size n = cczp_n(zp);

    cc_unit a[n], r[n];
    cczp_generate_non_zero_element(zp, rng, a);

    perf_start();
    do {
        cczp_sqrt(zp, r, a);
    } while (--loops != 0);

    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct ccec_perf_test {
    const char *name;
    double(*func)(size_t loops, ccec_const_cp_t cp);
} ccec_perf_tests[] = {

    _TEST(ccec_generate_key_internal_fips),
    _TEST(ccec_generate_key_fips),
    _TEST(ccec_generate_key_legacy),
    _TEST(ccec_compact_generate_key),
    _TEST(ccec_sign),
    _TEST(ccec_verify),
    _TEST(ccec_compact_import_pub),
    _TEST(ccecdh_generate_key),
    _TEST(ccecdh_compute_shared_secret),
    _TEST(ccec_diversify_pub_twin),
    _TEST(ccec_cczp_mul),
    _TEST(ccec_cczp_sqrt),
    _TEST(ccec_cczp_inv_mod_p),
    _TEST(ccec_cczp_inv_mod_q),
};

static double perf_ccec(size_t loops, size_t *pnbits, const void *arg)
{
    const struct ccec_perf_test *test=arg;
    return test->func(loops, ccec_cp(*pnbits));
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccec(int argc, char *argv[])
{
    F_GET_ALL(family, ccec);

    static const size_t sizes[]={192,224,256,384,521};
    F_SIZES_FROM_ARRAY(family,sizes);

    family.size_kind=ccperf_size_bits;
    return &family;
}
