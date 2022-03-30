/* Copyright (c) (2011,2013,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
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

/* mode created with the OMAC factory */
static struct ccmode_omac ccaes_generic_ltc_omac_encrypt_mode;
static struct ccmode_omac ccaes_generic_ltc_omac_decrypt_mode;
#if CCAES_ARM_ASM
static struct ccmode_omac ccaes_generic_arm_omac_encrypt_mode;
static struct ccmode_omac ccaes_generic_arm_omac_decrypt_mode;
#endif

#define CCMODE_OMAC_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .omac=&_mode, .keylen=_keylen }

static struct ccomac_perf_test {
    const char *name;
    const struct ccmode_omac *omac;
    size_t keylen;
} ccomac_perf_tests[] = {
    CCMODE_OMAC_TEST(ccaes_generic_ltc_omac_encrypt_mode, 16),
    CCMODE_OMAC_TEST(ccaes_generic_ltc_omac_decrypt_mode, 16),
    CCMODE_OMAC_TEST(ccaes_generic_ltc_omac_encrypt_mode, 24),
    CCMODE_OMAC_TEST(ccaes_generic_ltc_omac_decrypt_mode, 24),
    CCMODE_OMAC_TEST(ccaes_generic_ltc_omac_encrypt_mode, 32),
    CCMODE_OMAC_TEST(ccaes_generic_ltc_omac_decrypt_mode, 32),

#if CCAES_ARM_ASM
    CCMODE_OMAC_TEST(ccaes_generic_arm_omac_encrypt_mode, 16),
    CCMODE_OMAC_TEST(ccaes_generic_arm_omac_decrypt_mode, 16),
    CCMODE_OMAC_TEST(ccaes_generic_arm_omac_encrypt_mode, 24),
    CCMODE_OMAC_TEST(ccaes_generic_arm_omac_decrypt_mode, 24),
    CCMODE_OMAC_TEST(ccaes_generic_arm_omac_encrypt_mode, 32),
    CCMODE_OMAC_TEST(ccaes_generic_arm_omac_decrypt_mode, 32),
#endif
};

static double perf_ccomac_init(size_t loops, size_t *psize  CC_UNUSED, const void *arg)
{
    const struct ccomac_perf_test *test=arg;
    const struct ccmode_omac *omac=test->omac;
    size_t tweaklen=omac->block_size;
    size_t keylen=test->keylen;
    unsigned char keyd[keylen];

    cc_clear(keylen,keyd);
    ccomac_ctx_decl(omac->size, key);

    perf_start();
    while(loops--)
        ccomac_init(omac, key, tweaklen, keylen, keyd);

    return perf_seconds();
}

static double perf_ccomac_update(size_t loops, size_t *psize, const void *arg)
{
    const struct ccomac_perf_test *test=arg;
    const struct ccmode_omac *omac=test->omac;
    size_t tweaklen=omac->block_size;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/omac->block_size;

    unsigned char keyd[keylen];
    unsigned char tweakd[omac->block_size];
    unsigned char temp[nblocks*omac->block_size];

    cc_clear(keylen,keyd);
    cc_clear(tweaklen,tweakd);
    ccomac_ctx_decl(omac->size, key);
    ccomac_init(omac, key, tweaklen, keylen, keyd);

    perf_start();
    while(loops--)
        ccomac_update(omac, key, *psize, tweakd, temp, temp);

    return perf_seconds();
}

static double perf_ccomac_one_shot(size_t loops, size_t *psize, const void *arg)
{
    const struct ccomac_perf_test *test=arg;
    const struct ccmode_omac *omac=test->omac;
    size_t tweaklen=omac->block_size;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/omac->block_size;

    unsigned char keyd[keylen];
    unsigned char tweakd[omac->block_size];
    unsigned char temp[nblocks*omac->block_size];

    cc_clear(keylen,keyd);
    cc_clear(tweaklen,tweakd);

    perf_start();
    while(loops--) {
        ccomac_one_shot(omac,tweaklen, keylen, keyd, tweakd, *psize,temp, temp);
    }

    return perf_seconds();
}


static void ccperf_family_ccomac_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    ccmode_factory_omac_encrypt(&ccaes_generic_ltc_omac_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_omac_decrypt(&ccaes_generic_ltc_omac_decrypt_mode, &ccaes_ltc_ecb_decrypt_mode);
#if CCAES_ARM_ASM
    ccmode_factory_omac_encrypt(&ccaes_generic_arm_omac_encrypt_mode, &ccaes_arm_ecb_encrypt_mode);
    ccmode_factory_omac_decrypt(&ccaes_generic_arm_omac_decrypt_mode, &ccaes_arm_ecb_decrypt_mode);
#endif

}

F_DEFINE(ccomac, init, ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccomac, update, ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccomac, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
