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

#include "crypto_test_rng.h"
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccrng_csprng.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_absolute_time.h>
#include "testmore.h"
#include "cc_priv.h"

// Enable timers if the platform allows it
#define CCRNG_CSPRNG_TEST_TIMER_ENABLED !CC_LINUX
#if CCRNG_CSPRNG_TEST_TIMER_ENABLED
#if CC_KERNEL
#include <kern/clock.h>
static uint64_t cc_uptime_seconds(void)
{
    clock_sec_t sec;
    clock_usec_t discard;
    clock_get_calendar_microtime(&sec, &discard);
    discard = 0;
    return sec;
}
#else

#if (defined(__x86_64__) || defined(__i386__))
#define STORE_CSR 1
#else
#define STORE_CSR 0
#endif

static uint64_t cc_uptime_seconds(void)
{
#if STORE_CSR
    uint32_t csr = __builtin_ia32_stmxcsr();
#endif

    uint64_t uptime = (uint64_t)(cc_absolute_time_sf() * (double)cc_absolute_time());

#if STORE_CSR
    __builtin_ia32_ldmxcsr(csr);
#endif

    return uptime;
}
#endif
#endif /* CCRNG_CSPRNG_TIMER_ENABLED */

#define CCRNG_CSPRNG_TEST_TIMER_AMOUNT 5
#define CCRNG_CSPRNG_TEST_SLEEP_AMOUNT (2 * CCRNG_CSPRNG_TEST_TIMER_AMOUNT)
#if defined(_WIN32)
#include <windows.h>
static void sleep_some() {
    Sleep(CCRNG_CSPRNG_TEST_SLEEP_AMOUNT * 1000);
}
#else
#include <unistd.h>
static void sleep_some() {
    sleep(CCRNG_CSPRNG_TEST_SLEEP_AMOUNT);
}
#endif

struct ccrng_csprng_hmac_drbg_test_vector {
    unsigned tcId;
    const struct ccdigest_info *(*di)(void);
    const uint8_t *init_seed;
    size_t init_seed_len;
    const uint8_t *init_nonce;
    size_t init_nonce_len;
    const uint8_t *init_ps;
    size_t init_ps_len;
    const uint8_t *gen1;
    size_t gen1_len;
    size_t ngens; // Number of generations
    const uint8_t *genn;
    size_t genn_len;
    const uint8_t *reseed_nonce;
    size_t reseed_nonce_len;
    const uint8_t *gen_after_reseed;
    size_t gen_after_reseed_len;
};
#include "../test_vectors/ccrng_csprng_hmac_tvs.kat"
#include "../test_vectors/ccrng_csprng_hmac_always_reseed_tvs.kat"
#include "../test_vectors/ccrng_csprng_hmac_timer_tvs.kat"

static int ccrng_csprng_getentropy_all_one(size_t *entropy_len, void *entropy, void *getentropy_ctx) {
    (void) getentropy_ctx;
    uint8_t *eb = (uint8_t *) entropy;
    for (size_t i = 0; i < *entropy_len; i++) {
        eb[i] = 0x01;
    }
    return CCERR_OK;
}

static bool csprng_test_one(const struct ccrng_csprng_hmac_drbg_test_vector *tv, struct ccrng_csprng_state *rng, bool use_sleep)
{
    int err = 0;
    uint8_t gen1[tv->gen1_len];
    uint8_t genn[tv->genn_len];
    uint8_t gen_final[tv->gen_after_reseed_len];
    
    err = ccrng_csprng_init(rng, tv->init_seed_len, tv->init_seed, tv->init_nonce_len, tv->init_nonce, tv->init_ps_len, tv->init_ps);
    if (err != CCERR_OK) {
        diag("ccrng_csprng init failure");
        return false;
    }
    
    err = ccrng_generate(rng, tv->gen1_len, gen1);
    //cc_printf("First GEN end...\n");
    if (err != CCERR_OK) {
        diag("ccrng_csprng generate failure");
        return false;
    }
    
    if (memcmp(gen1, tv->gen1, tv->gen1_len) != 0) {
        diag("ccrng_csprng gen1 failure");
        return false;
    }
    
    for (size_t n = 0; n <= tv->ngens; n++) {
        err = ccrng_generate(rng, tv->genn_len, genn);
        if (err != CCERR_OK) {
            diag("ccrng_csprng generate failure");
            return false;
        }
    }
    
    if (memcmp(genn, tv->genn, tv->genn_len) != 0) {
        diag("ccrng_csprng genn failure");
        return false;
    }
    
    if (use_sleep && CCRNG_CSPRNG_TEST_TIMER_ENABLED) {
        diag("Sleeping for %d seconds", CCRNG_CSPRNG_TEST_SLEEP_AMOUNT);
        sleep_some();
        diag("Sleep complete\n");
    } else {
        err = ccrng_csprng_reseed_get_entropy(rng, tv->reseed_nonce_len, tv->reseed_nonce);
        if (err != CCERR_OK) {
            diag("ccrng_csprng_reseed_get_entropy failure");
            return false;
        }
    }
    
    err = ccrng_generate(rng, tv->gen_after_reseed_len, gen_final);
    if (err != CCERR_OK) {
        diag("ccrng_csprng generate failure");
        return false;
    }
    
    ok_memcmp(gen_final, tv->gen_after_reseed, tv->gen_after_reseed_len, "GEN FINAL");
    
    if (memcmp(gen_final, tv->gen_after_reseed, tv->gen_after_reseed_len) != 0) {
        diag("ccrng_csprng gen_final failure");
        return false;
    }
    
    return true;
    
}

static uint64_t ccrng_csprng_test_timer;
static bool ccrng_csprng_test_needreseed_timer(void *reseed_ctx) {
    uint64_t *timer = (uint64_t *) reseed_ctx;
#if CCRNG_CSPRNG_TEST_TIMER_ENABLED
    int64_t time_delta = (int64_t)(cc_uptime_seconds() - *timer);
    if (time_delta >= CCRNG_CSPRNG_TEST_TIMER_AMOUNT) {
        *timer = cc_uptime_seconds();
        return true;
    }
#else
    (void) reseed_ctx;
#endif
    return false;
}

static void ccrng_csprng_test_reseedcomplete_timer(void *reseed_ctx) {
#if CCRNG_CSPRNG_TEST_TIMER_ENABLED
    uint64_t *timer = (uint64_t *) reseed_ctx;
    *timer =cc_uptime_seconds();
#else
    (void) reseed_ctx;
#endif
}

static bool csprng_test_one_normal(const struct ccrng_csprng_hmac_drbg_test_vector *tv, bool use_sleep)
{
    
    struct ccrng_csprng_state rng;
    rng.getentropy = ccrng_csprng_getentropy_all_one;
    rng.getentropy_ctx = NULL;
    rng.needreseed = ccrng_csprng_test_needreseed_timer;
    rng.reseedcomplete = ccrng_csprng_test_reseedcomplete_timer;
    rng.reseed_ctx = &ccrng_csprng_test_timer;
    
#if CCRNG_CSPRNG_TEST_TIMER_ENABLED
    ccrng_csprng_test_timer = cc_uptime_seconds();
#endif
    
    const struct ccdigest_info *di = tv->di();
    struct ccdrbg_nisthmac_custom drbg_custom;
    drbg_custom.di = di;
    drbg_custom.strictFIPS = 1;
    ccdrbg_factory_nisthmac(&rng.drbg_info, &drbg_custom);
    
    return csprng_test_one(tv, &rng, use_sleep);
}

static int sanity_check_reseeds = 0;
static bool ccrng_csprng_test_needreseed_always(void *reseed_ctx) {
    (void) reseed_ctx;
    return true;
}

static void ccrng_csprng_test_reseedcomplete_always(void *reseed_ctx) {
    int *scr = (int *) reseed_ctx;
    *scr += 1;
}

static bool csprng_test_one_aggressive(const struct ccrng_csprng_hmac_drbg_test_vector *tv, bool use_sleep)
{
    struct ccrng_csprng_state rng;
    rng.getentropy = ccrng_csprng_getentropy_all_one;
    rng.getentropy_ctx = NULL;
    rng.needreseed = ccrng_csprng_test_needreseed_always;
    rng.reseedcomplete = ccrng_csprng_test_reseedcomplete_always;
    rng.reseed_ctx = &sanity_check_reseeds;
    
    const struct ccdigest_info *di = tv->di();
    struct ccdrbg_nisthmac_custom drbg_custom;
    drbg_custom.di = di;
    drbg_custom.strictFIPS = 1;
    ccdrbg_factory_nisthmac(&rng.drbg_info, &drbg_custom);

    return csprng_test_one(tv, &rng, use_sleep);
}

#if CC_TSAN
#include <pthread.h>

static struct ccrng_csprng_state tsan_rng;
static int tsan_sanity_check_reseeds;

static void *ccrng_tsan_thread_generate(void *arg) {
    (void) arg;
    uint8_t generate[32] = {0};
    for (int i = 0; i < 10000; i++) {
        ccrng_generate(&tsan_rng, sizeof(generate), generate);
    }
    return NULL;
}

static void *ccrng_tsan_thread_reseed(void *arg) {
    (void) arg;
    uint8_t seed[32] = {1,2,3,4,5};
    uint8_t nonce[8] = {1,2,3,4,5};
    for (int i = 0; i < 10000; i++) {
        ccrng_csprng_reseed(&tsan_rng, sizeof(seed), seed, sizeof(nonce), nonce);
    }
    return NULL;
}

static int csprng_tsan_test() {
    tsan_rng.getentropy = ccrng_csprng_getentropy_all_one;
    tsan_rng.getentropy_ctx = NULL;
    tsan_rng.needreseed = ccrng_csprng_test_needreseed_always;
    tsan_rng.reseedcomplete = ccrng_csprng_test_reseedcomplete_always;
    tsan_rng.reseed_ctx = &tsan_sanity_check_reseeds;
    
    struct ccdrbg_nisthmac_custom drbg_custom;
    drbg_custom.di = ccsha256_di();
    drbg_custom.strictFIPS = 1;
    ccdrbg_factory_nisthmac(&tsan_rng.drbg_info, &drbg_custom);
    
    uint8_t seed[64] = {0};
    uint8_t nonce[32] = {0};
    uint8_t ps[8] = {0};
    
    int err = ccrng_csprng_init(&tsan_rng, sizeof(seed), seed, sizeof(nonce), nonce, sizeof(ps), ps);
    if (err != CCERR_OK) {
        return -1;
    }
    
    pthread_t t_generate, t_reseed;
    
    pthread_create(&t_generate, NULL, ccrng_tsan_thread_generate, NULL);
    pthread_create(&t_reseed, NULL, ccrng_tsan_thread_reseed, NULL);
    
    pthread_join(t_generate, NULL);
    pthread_join(t_reseed, NULL);
    
    return 0;
}

#endif

int csprng_test_kat(void) {
    diag("Starting CSPRNG KAT Tests");
    
    diag("\tNormal KAT Tests");
    size_t nvectors = CC_ARRAY_LEN(ccrng_csprng_hmac_tvs);
    for (size_t i = 0; i < nvectors; i++)
    {
        const struct ccrng_csprng_hmac_drbg_test_vector *tv = ccrng_csprng_hmac_tvs[i];
        bool result = csprng_test_one_normal(tv, false);
        is(result, true, "Failed csprng kat test vector %d\n", tv->tcId);
    }
    
    diag("\tAggressive Reseeding KAT Tests");
    nvectors = CC_ARRAY_LEN(ccrng_csprng_hmac_always_reseed_tvs);
    int sanity_check_reseed_count = 0;
    for (size_t i = 0; i < nvectors; i++)
    {
        const struct ccrng_csprng_hmac_drbg_test_vector *tv = ccrng_csprng_hmac_always_reseed_tvs[i];
        sanity_check_reseed_count += (4 + tv->ngens);
        bool result = csprng_test_one_aggressive(tv, false);
        is(result, true, "Failed aggressive reseed csprng kat test vector %d\n", tv->tcId);
    }
    ok(sanity_check_reseed_count == sanity_check_reseeds, "Not reseeding properly");
    
    diag("\tTimer Based Reseeding KAT Tests");
    nvectors = CC_ARRAY_LEN(ccrng_csprng_hmac_timer_tvs);
    cc_assert(nvectors == 1);
    const struct ccrng_csprng_hmac_drbg_test_vector *tv = ccrng_csprng_hmac_timer_tvs[0];
    bool result = csprng_test_one_normal(tv, true);
    is(result, true, "Failed csprng kat test vector %d\n", tv->tcId);
    
    diag("Finished CSPRNG KAT Tests");
    
    int ret = 0;
#if CC_TSAN
    diag("Starting CSPRNG TSAN Tests");
    ret = csprng_tsan_test();
    diag("Finished CSPRNG TSAN Tests");
#endif
    return ret;
}
