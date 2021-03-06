/* Copyright (c) (2011,2012,2013,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdes.h>
#include <corecrypto/ccrc2.h>
#include <corecrypto/cccast.h>
#include <corecrypto/ccblowfish.h>

#include "cccast_internal.h"
#include "ccblowfish_internal.h"
#include "ccdes_internal.h"
#include "ccrc2_internal.h"

#define CCMODE_ECB_TEST(_mode, _keylen) { .name=#_mode"_"#_keylen, .ecb=&_mode, .keylen=_keylen }

static struct ccecb_perf_test {
    const char *name;
    const struct ccmode_ecb *ecb;
    size_t keylen;
} ccecb_perf_tests[] = {
    CCMODE_ECB_TEST(ccaes_ltc_ecb_encrypt_mode, 16),
    CCMODE_ECB_TEST(ccaes_ltc_ecb_decrypt_mode, 16),
    CCMODE_ECB_TEST(ccaes_ltc_ecb_encrypt_mode, 24),
    CCMODE_ECB_TEST(ccaes_ltc_ecb_decrypt_mode, 24),
    CCMODE_ECB_TEST(ccaes_ltc_ecb_encrypt_mode, 32),
    CCMODE_ECB_TEST(ccaes_ltc_ecb_decrypt_mode, 32),
#if CCAES_ARM_ASM
    CCMODE_ECB_TEST(ccaes_arm_ecb_encrypt_mode, 16),
    CCMODE_ECB_TEST(ccaes_arm_ecb_decrypt_mode, 16),
    CCMODE_ECB_TEST(ccaes_arm_ecb_encrypt_mode, 24),
    CCMODE_ECB_TEST(ccaes_arm_ecb_decrypt_mode, 24),
    CCMODE_ECB_TEST(ccaes_arm_ecb_encrypt_mode, 32),
    CCMODE_ECB_TEST(ccaes_arm_ecb_decrypt_mode, 32),
#endif
    CCMODE_ECB_TEST(cccast_eay_ecb_encrypt_mode, 16),
    CCMODE_ECB_TEST(cccast_eay_ecb_decrypt_mode, 16),

    CCMODE_ECB_TEST(ccblowfish_ltc_ecb_encrypt_mode, 16),
    CCMODE_ECB_TEST(ccblowfish_ltc_ecb_decrypt_mode, 16),

    CCMODE_ECB_TEST(ccdes_ltc_ecb_encrypt_mode, 8),
    CCMODE_ECB_TEST(ccdes_ltc_ecb_decrypt_mode, 8),

    CCMODE_ECB_TEST(ccdes3_ltc_ecb_encrypt_mode, 24),
    CCMODE_ECB_TEST(ccdes3_ltc_ecb_decrypt_mode, 24),

    CCMODE_ECB_TEST(ccrc2_ltc_ecb_encrypt_mode, 8),
    CCMODE_ECB_TEST(ccrc2_ltc_ecb_decrypt_mode, 8),

    CCMODE_ECB_TEST(ccrc2_ltc_ecb_encrypt_mode, 16),
    CCMODE_ECB_TEST(ccrc2_ltc_ecb_decrypt_mode, 16),

};

static double perf_ccecb_init(size_t loops, size_t *psize CC_UNUSED, const void *arg)
{
    const struct ccecb_perf_test *test=arg;
    const struct ccmode_ecb *ecb=test->ecb;
    size_t keylen=test->keylen;

    unsigned char keyd[keylen];
    cc_clear(keylen,keyd);
    ccecb_ctx_decl(ecb->size, key);

    perf_start();
    while(loops--)
        ccecb_init(ecb, key, keylen, keyd);
    return perf_seconds();
}


static double perf_ccecb_update(size_t loops, size_t *psize, const void *arg)
{
    const struct ccecb_perf_test *test=arg;
    const struct ccmode_ecb *ecb=test->ecb;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/ecb->block_size;

    unsigned char keyd[keylen];
    unsigned char temp[nblocks*ecb->block_size];

    cc_clear(keylen,keyd);
    ccecb_ctx_decl(ecb->size, key);
    ccecb_init(ecb, key, keylen, keyd);

    perf_start();
    while(loops--)
        ccecb_update(ecb,key, nblocks, temp, temp);
    return perf_seconds();
}

static double perf_ccecb_one_shot(size_t loops, size_t *psize, const void *arg)
{
    const struct ccecb_perf_test *test=arg;
    const struct ccmode_ecb *ecb=test->ecb;
    size_t keylen=test->keylen;
    size_t nblocks=*psize/ecb->block_size;

    unsigned char keyd[keylen];
    unsigned char temp[nblocks*ecb->block_size];

    cc_clear(keylen,keyd);

    perf_start();
    while(loops--) {
        ccecb_one_shot(ecb,keylen, keyd, nblocks, temp, temp);
    }

    return perf_seconds();
}

static void ccperf_family_ccecb_once(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
}

F_DEFINE(ccecb, init,     ccperf_size_iterations, 1)
F_DEFINE_SIZE_ARRAY(ccecb, update,   ccperf_size_bytes, symmetric_crypto_data_nbytes)
F_DEFINE_SIZE_ARRAY(ccecb, one_shot, ccperf_size_bytes, symmetric_crypto_data_nbytes)
