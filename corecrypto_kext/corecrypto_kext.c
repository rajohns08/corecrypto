/* Copyright (c) (2012-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccblowfish.h>
#include <corecrypto/cccast.h>
#include <corecrypto/ccchacha20poly1305.h>
#include "cckprng_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_cryptographic.h>

#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <libkern/crypto/register_crypto.h>
#include <prng/random.h>

kern_return_t corecrypto_kext_start(kmod_info_t *ki, void *d);
kern_return_t corecrypto_kext_stop(kmod_info_t *ki, void *d);
extern void panic(const char *, ...);

#include "fipspost.h"

#include <libkern/libkern.h>
#include <pexpert/pexpert.h>

#include <corecrypto/cc_memory.h>

#include <sys/sysctl.h>

static CC_READ_ONLY_LATE(struct crypto_functions) kpis;

static const struct ccchacha20poly1305_fns ccchacha20poly1305_fns = { .info = ccchacha20poly1305_info,
                                                                      .init = ccchacha20poly1305_init,
                                                                      .reset = ccchacha20poly1305_reset,
                                                                      .setnonce = ccchacha20poly1305_setnonce,
                                                                      .incnonce = ccchacha20poly1305_incnonce,
                                                                      .aad = ccchacha20poly1305_aad,
                                                                      .encrypt = ccchacha20poly1305_encrypt,
                                                                      .finalize = ccchacha20poly1305_finalize,
                                                                      .decrypt = ccchacha20poly1305_decrypt,
                                                                      .verify = ccchacha20poly1305_verify };

static struct cckprng_ctx kprng_ctx;

SYSCTL_NODE(_kern, OID_AUTO, prng, CTLFLAG_RD, 0, NULL);

// SYSCTL_QUAD(_kern_prng, OID_AUTO, user_reseed_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.userreseed_nreseeds, NULL);
SYSCTL_QUAD(_kern_prng, OID_AUTO, scheduled_reseed_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.nreseeds, NULL);
SYSCTL_QUAD(_kern_prng, OID_AUTO, scheduled_reseed_max_sample_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.schedreseed_nsamples_max, NULL);
SYSCTL_QUAD(_kern_prng, OID_AUTO, entropy_max_sample_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.addentropy_nsamples_max, NULL);

#define SYSCTL_PRNG_POOL(pool_id)                                           \
    SYSCTL_NODE(_kern_prng, OID_AUTO, pool_##pool_id, CTLFLAG_RD, 0, NULL); \
    SYSCTL_QUAD(_kern_prng_pool_##pool_id, OID_AUTO, sample_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.pools[pool_id].nsamples, NULL); \
    SYSCTL_QUAD(_kern_prng_pool_##pool_id, OID_AUTO, drain_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.pools[pool_id].ndrains, NULL); \
    SYSCTL_QUAD(_kern_prng_pool_##pool_id, OID_AUTO, max_sample_count, CTLFLAG_RD, &kprng_ctx.fortuna_ctx.pools[pool_id].nsamples_max, NULL) \

SYSCTL_PRNG_POOL(0);
SYSCTL_PRNG_POOL(1);
SYSCTL_PRNG_POOL(2);
SYSCTL_PRNG_POOL(3);
SYSCTL_PRNG_POOL(4);
SYSCTL_PRNG_POOL(5);
SYSCTL_PRNG_POOL(6);
SYSCTL_PRNG_POOL(7);
SYSCTL_PRNG_POOL(8);
SYSCTL_PRNG_POOL(9);
SYSCTL_PRNG_POOL(10);
SYSCTL_PRNG_POOL(11);
SYSCTL_PRNG_POOL(12);
SYSCTL_PRNG_POOL(13);
SYSCTL_PRNG_POOL(14);
SYSCTL_PRNG_POOL(15);
SYSCTL_PRNG_POOL(16);
SYSCTL_PRNG_POOL(17);
SYSCTL_PRNG_POOL(18);
SYSCTL_PRNG_POOL(19);
SYSCTL_PRNG_POOL(20);
SYSCTL_PRNG_POOL(21);
SYSCTL_PRNG_POOL(22);
SYSCTL_PRNG_POOL(23);
SYSCTL_PRNG_POOL(24);
SYSCTL_PRNG_POOL(25);
SYSCTL_PRNG_POOL(26);
SYSCTL_PRNG_POOL(27);
SYSCTL_PRNG_POOL(28);
SYSCTL_PRNG_POOL(29);
SYSCTL_PRNG_POOL(30);
SYSCTL_PRNG_POOL(31);

kern_return_t corecrypto_kext_start(kmod_info_t *ki, void *d)
{
    int status;
#pragma unused(d)

#if CC_FIPSPOST_TRACE
    kprintf("corecrypto_kext_start called: tracing enabled\n");
#else
    kprintf("corecrypto_kext_start called\n");
#endif

    sysctl_register_oid(&sysctl__kern_prng);
    sysctl_register_oid(&sysctl__kern_prng_scheduled_reseed_count);
    sysctl_register_oid(&sysctl__kern_prng_scheduled_reseed_max_sample_count);
    sysctl_register_oid(&sysctl__kern_prng_entropy_max_sample_count);

#define SYSCTL_REGISTER_OID_PRNG_POOL(pool_id)                          \
    do {                                                                \
        sysctl_register_oid(&sysctl__kern_prng_pool_##pool_id); \
        sysctl_register_oid(&sysctl__kern_prng_pool_##pool_id##_sample_count); \
        sysctl_register_oid(&sysctl__kern_prng_pool_##pool_id##_drain_count); \
        sysctl_register_oid(&sysctl__kern_prng_pool_##pool_id##_max_sample_count); \
    } while (0)                                                         \

    SYSCTL_REGISTER_OID_PRNG_POOL(0);
    SYSCTL_REGISTER_OID_PRNG_POOL(1);
    SYSCTL_REGISTER_OID_PRNG_POOL(2);
    SYSCTL_REGISTER_OID_PRNG_POOL(3);
    SYSCTL_REGISTER_OID_PRNG_POOL(4);
    SYSCTL_REGISTER_OID_PRNG_POOL(5);
    SYSCTL_REGISTER_OID_PRNG_POOL(6);
    SYSCTL_REGISTER_OID_PRNG_POOL(7);
    SYSCTL_REGISTER_OID_PRNG_POOL(8);
    SYSCTL_REGISTER_OID_PRNG_POOL(9);
    SYSCTL_REGISTER_OID_PRNG_POOL(10);
    SYSCTL_REGISTER_OID_PRNG_POOL(11);
    SYSCTL_REGISTER_OID_PRNG_POOL(12);
    SYSCTL_REGISTER_OID_PRNG_POOL(13);
    SYSCTL_REGISTER_OID_PRNG_POOL(14);
    SYSCTL_REGISTER_OID_PRNG_POOL(15);
    SYSCTL_REGISTER_OID_PRNG_POOL(16);
    SYSCTL_REGISTER_OID_PRNG_POOL(17);
    SYSCTL_REGISTER_OID_PRNG_POOL(18);
    SYSCTL_REGISTER_OID_PRNG_POOL(19);
    SYSCTL_REGISTER_OID_PRNG_POOL(20);
    SYSCTL_REGISTER_OID_PRNG_POOL(21);
    SYSCTL_REGISTER_OID_PRNG_POOL(22);
    SYSCTL_REGISTER_OID_PRNG_POOL(23);
    SYSCTL_REGISTER_OID_PRNG_POOL(24);
    SYSCTL_REGISTER_OID_PRNG_POOL(25);
    SYSCTL_REGISTER_OID_PRNG_POOL(26);
    SYSCTL_REGISTER_OID_PRNG_POOL(27);
    SYSCTL_REGISTER_OID_PRNG_POOL(28);
    SYSCTL_REGISTER_OID_PRNG_POOL(29);
    SYSCTL_REGISTER_OID_PRNG_POOL(30);
    SYSCTL_REGISTER_OID_PRNG_POOL(31);

    const struct cckprng_funcs kprng_funcs = {
        .init = cckprng_init,
        .initgen = cckprng_initgen,
        .reseed = cckprng_reseed,
        .refresh = cckprng_refresh,
        .generate = cckprng_generate,
        .init_with_getentropy = cckprng_init_with_getentropy,
    };

    /* Install the kernel PRNG */
    register_and_init_prng(&kprng_ctx, &kprng_funcs);

    // Initialize RNG before ccrng is used
    status = ccrng_cryptographic_init_once();
    if (status != 0) {
        // Fatal error, we can't boot if the RNG failed to initialize
        panic("corecrypto kext RNG initialization failure (%d)", status);
    };

    int result;
    uint32_t fips_mode = 0;

    if (!PE_parse_boot_argn("fips_mode", &fips_mode, sizeof(fips_mode))) {
        fips_mode = FIPS_MODE_FLAG_FULL;
    }

    if (!FIPS_MODE_IS_DISABLE(fips_mode)) {
        if ((result = fipspost_post(fips_mode, (struct mach_header *)ki->address)) != 0) {
            panic("FIPS Kernel POST Failed (%d)!", result);
        }
    }

    /* Register KPIs */

    /* digests common functions */
    kpis.ccdigest_init_fn = &ccdigest_init;
    kpis.ccdigest_update_fn = &ccdigest_update;
    kpis.ccdigest_fn = &ccdigest;
    /* digest implementations */
    kpis.ccmd5_di = ccmd5_di();
    kpis.ccsha1_di = ccsha1_di();
    kpis.ccsha256_di = ccsha256_di();
    kpis.ccsha384_di = ccsha384_di();
    kpis.ccsha512_di = ccsha512_di();

    /* hmac common function */
    kpis.cchmac_init_fn = &cchmac_init;
    kpis.cchmac_update_fn = &cchmac_update;
    kpis.cchmac_final_fn = &cchmac_final;
    kpis.cchmac_fn = &cchmac;

    /* ciphers modes implementations */
    /* AES, ecb, cbc and xts */
    kpis.ccaes_ecb_encrypt = ccaes_ecb_encrypt_mode();
    kpis.ccaes_ecb_decrypt = ccaes_ecb_decrypt_mode();
    kpis.ccaes_cbc_encrypt = ccaes_cbc_encrypt_mode();
    kpis.ccaes_cbc_decrypt = ccaes_cbc_decrypt_mode();
    kpis.ccaes_ctr_crypt = ccaes_ctr_crypt_mode();
    kpis.ccaes_gcm_encrypt = ccaes_gcm_encrypt_mode();
    kpis.ccaes_gcm_decrypt = ccaes_gcm_decrypt_mode();

    kpis.ccgcm_init_with_iv_fn = &ccgcm_init_with_iv;
    kpis.ccgcm_inc_iv_fn = &ccgcm_inc_iv;

    kpis.ccchacha20poly1305_fns = &ccchacha20poly1305_fns;

    kpis.ccaes_xts_encrypt = ccaes_xts_encrypt_mode();
    kpis.ccaes_xts_decrypt = ccaes_xts_decrypt_mode();
    /* DES, ecb and cbc */
    kpis.ccdes_ecb_encrypt = ccdes_ecb_encrypt_mode();
    kpis.ccdes_ecb_decrypt = ccdes_ecb_decrypt_mode();
    kpis.ccdes_cbc_encrypt = ccdes_cbc_encrypt_mode();
    kpis.ccdes_cbc_decrypt = ccdes_cbc_decrypt_mode();
    /* TDES, ecb and cbc */
    kpis.cctdes_ecb_encrypt = ccdes3_ecb_encrypt_mode();
    kpis.cctdes_ecb_decrypt = ccdes3_ecb_decrypt_mode();
    kpis.cctdes_cbc_encrypt = ccdes3_cbc_encrypt_mode();
    kpis.cctdes_cbc_decrypt = ccdes3_cbc_decrypt_mode();
    /* DES key helper functions */
    kpis.ccdes_key_is_weak_fn = &ccdes_key_is_weak;
    kpis.ccdes_key_set_odd_parity_fn = &ccdes_key_set_odd_parity;
    /* CTS3 padding+encrypt */
    kpis.ccpad_cts3_encrypt_fn = &ccpad_cts3_encrypt;
    kpis.ccpad_cts3_decrypt_fn = &ccpad_cts3_decrypt;

    /* rng */
    kpis.ccrng_fn = &ccrng;

    /* rsa */
    kpis.ccrsa_make_pub_fn = &ccrsa_make_pub;
    kpis.ccrsa_verify_pkcs1v15_fn = &ccrsa_verify_pkcs1v15;

    register_crypto_functions(&kpis);

    if (FIPS_MODE_IS_VERBOSE(fips_mode)) {
        kprintf("corecrypto_kext_start completed sucessfully\n");
    }

    return KERN_SUCCESS;
}

kern_return_t corecrypto_kext_stop(kmod_info_t *ki CC_UNUSED, void *d CC_UNUSED)
{
    // Corecrypto kext is never unloaded
    return KERN_SUCCESS;
}
