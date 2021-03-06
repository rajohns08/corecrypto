/* Copyright (c) (2011,2012,2013,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_internal.h>

/* mode created with the XTS factory */
static struct ccmode_xts ccaes_generic_ltc_xts_encrypt_mode;
static struct ccmode_xts ccaes_generic_ltc_xts_decrypt_mode;
static struct ccmode_xts ccaes_default_xts_encrypt_mode;
static struct ccmode_xts ccaes_default_xts_decrypt_mode;

#define CCMODE_XTS_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .xts=&_mode, .keylen=_keylen }

static struct ccxts_perf_test {
    const char *name;
    const struct ccmode_xts *xts;
    size_t keylen;
} ccxts_perf_tests[] = {
    CCMODE_XTS_TEST(ccaes_generic_ltc_xts_encrypt_mode, 16),
    CCMODE_XTS_TEST(ccaes_generic_ltc_xts_decrypt_mode, 16),
    CCMODE_XTS_TEST(ccaes_generic_ltc_xts_encrypt_mode, 24),
    CCMODE_XTS_TEST(ccaes_generic_ltc_xts_decrypt_mode, 24),
    CCMODE_XTS_TEST(ccaes_generic_ltc_xts_encrypt_mode, 32),
    CCMODE_XTS_TEST(ccaes_generic_ltc_xts_decrypt_mode, 32),

    CCMODE_XTS_TEST(ccaes_default_xts_encrypt_mode, 16),
    CCMODE_XTS_TEST(ccaes_default_xts_decrypt_mode, 16),
    CCMODE_XTS_TEST(ccaes_default_xts_encrypt_mode, 24),
    CCMODE_XTS_TEST(ccaes_default_xts_decrypt_mode, 24),
    CCMODE_XTS_TEST(ccaes_default_xts_encrypt_mode, 32),
    CCMODE_XTS_TEST(ccaes_default_xts_decrypt_mode, 32),
};

static double perf_ccxts_init(size_t loops, size_t *psize  CC_UNUSED, const void *arg)
{
    const struct ccxts_perf_test *test=arg;
    const struct ccmode_xts *xts=test->xts;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char tweakkeyd[keylen];

    cc_clear(keylen,keyd);
    ccxts_ctx_decl(xts->size, key);

    perf_start();
    while(loops--)
        ccxts_init(xts, key, keylen, keyd, tweakkeyd);

    return perf_seconds();
}

static double perf_ccxts_set_tweak(size_t loops, size_t *psize CC_UNUSED, const void *arg)
{
    const struct ccxts_perf_test *test=arg;
    const struct ccmode_xts *xts=test->xts;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    unsigned char tweakkeyd[keylen];
    unsigned char tweakd[xts->block_size];

    cc_clear(keylen,keyd);
    ccxts_ctx_decl(xts->size, key);
    ccxts_tweak_decl(xts->tweak_size, tweak);
    ccxts_init(xts, key, keylen, keyd, tweakkeyd);

    perf_start();
    while(loops--)
        ccxts_set_tweak(xts, key, tweak, tweakd);

    return perf_seconds();
}

static double perf_ccxts_update(size_t loops, size_t *psize, const void *arg)
{
    const struct ccxts_perf_test *test=arg;
    const struct ccmode_xts *xts=test->xts;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/xts->block_size;

    unsigned char keyd[keylen];
    unsigned char tweakkeyd[keylen];
    unsigned char tweakd[xts->block_size];
    unsigned char temp[nblocks*xts->block_size];

    cc_clear(keylen,keyd);
    cc_clear(sizeof(tweakd),tweakd);
    ccxts_ctx_decl(xts->size, key);
    ccxts_tweak_decl(xts->tweak_size, tweak);

    ccxts_init(xts, key, keylen, keyd, tweakkeyd);
    ccxts_set_tweak(xts, key, tweak, tweakd);

    perf_start();
    while(loops--)
        ccxts_update(xts, key, tweak, nblocks, temp, temp);

    return perf_seconds();
}

static double perf_ccxts_one_shot(size_t loops, size_t *psize, const void *arg)
{
    const struct ccxts_perf_test *test=arg;
    const struct ccmode_xts *xts=test->xts;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/xts->block_size;

    unsigned char keyd[keylen];
    unsigned char tweakkeyd[keylen];
    unsigned char tweakd[xts->block_size];
    unsigned char temp[nblocks*xts->block_size];

    cc_clear(keylen,keyd);
    cc_clear(sizeof(tweakd),tweakd);

    perf_start();
    while(loops--) {
        ccxts_one_shot(xts, keylen, keyd, tweakkeyd, tweakd, nblocks, temp, temp);
    }

    return perf_seconds();
}


static void ccperf_family_ccxts_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_xts_encrypt(&ccaes_generic_ltc_xts_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode,  &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_xts_decrypt(&ccaes_generic_ltc_xts_decrypt_mode, &ccaes_ltc_ecb_decrypt_mode,  &ccaes_ltc_ecb_encrypt_mode);
    ccaes_default_xts_encrypt_mode=*ccaes_xts_encrypt_mode();
    ccaes_default_xts_decrypt_mode=*ccaes_xts_decrypt_mode();
}

static const size_t tweak_sizes[]={16};

F_DEFINE(ccxts, init, ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccxts, set_tweak,ccperf_size_bytes, tweak_sizes)
F_DEFINE_SIZE_ARRAY(ccxts, update, ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccxts, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
