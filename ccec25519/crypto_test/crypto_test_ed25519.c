/* Copyright (c) (2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
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
#include "testccnBuffer.h"

#if (CCED25519 == 0)
entryPoint(cced25519, "cced25519 test")
#else
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccsha2.h>
#include "cced25519_priv.h"

static int verbose = 0;

typedef struct {
    uint8_t sk[32];
    uint8_t pk[32];
    uint8_t sig[64];
    size_t len;
    const void *msg;

} ed25519_test_vector;

static const ed25519_test_vector testVectors[] = {
#include "crypto_test_ed25519.inc"
};

static int cced_round_trip(const struct ccdigest_info *di,
                           char *extlabel,
                           const ccec25519secretkey sk,
                           const ccec25519pubkey pk,
                           const void *katsig,
                           size_t msglen,
                           const void *msg)
{
    uint8_t sig[64];
    int err;

    cc_clear(sizeof(sig), sig);

    if (katsig) {
        err = cced25519_sign_deterministic(di, sig, msglen, msg, pk, sk, global_test_rng);
        is(err, 0, "Sign %s", extlabel);
        ok_memcmp(sig, katsig, sizeof(sig), "Signature %s", extlabel);
    }

    cced25519_sign(di, sig, msglen, msg, pk, sk);
    err = cced25519_verify(di, msglen, msg, sig, pk);
    is(err, 0, "Verify %s", extlabel);

    return err == 0;
}

static void test_rng(const struct ccdigest_info *di, size_t msg_len, const void *msg)
{
    const uint8_t zeros = 0x00;
    const uint8_t ones = 0xff;

    uint8_t prime[32] = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };

    struct ccrng_sequence_state seq_rng;
    struct ccrng_state *rng = (struct ccrng_state *)&seq_rng;

    int rv;
    uint8_t sig[64];
    ccec25519pubkey pk;
    ccec25519secretkey sk;
    cced25519_make_key_pair(di, global_test_rng, pk, sk);

    ccrng_sequence_init(&seq_rng, 1, &zeros);
    rv = cced25519_sign_deterministic(di, sig, msg_len, msg, pk, sk, rng);
    isnt(rv, CCERR_OK, "RNG returning only zeros should fail");

    ccrng_sequence_init(&seq_rng, 1, &ones);
    rv = cced25519_sign_deterministic(di, sig, msg_len, msg, pk, sk, rng);
    isnt(rv, CCERR_OK, "RNG returning only ones should fail");

    ccrng_sequence_init(&seq_rng, sizeof(prime), prime);
    rv = cced25519_sign_deterministic(di, sig, msg_len, msg, pk, sk, rng);
    isnt(rv, CCERR_OK, "RNG returning only p should fail");

    prime[0] -= 1;
    ccrng_sequence_init(&seq_rng, sizeof(prime), prime);
    rv = cced25519_sign_deterministic(di, sig, msg_len, msg, pk, sk, rng);
    is(rv, CCERR_OK, "RNG returning p-1 should work");
}

int cced25519_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    size_t i, n;
    struct ccrng_state *rng = global_test_rng;
    const struct ccdigest_info *di = ccsha512_di();
    char label[64];

    plan_tests(3086);

    if (verbose) {
        diag("Starting ed25519 tests\n");
    }

    n = CC_ARRAY_LEN(testVectors);
    for (i = 0; i < n; ++i) {
        const ed25519_test_vector *const tv = &testVectors[i];
        snprintf(label, sizeof(label), "test vector %zu", i + 1);
        cced_round_trip(di, label, tv->sk, tv->pk, tv->sig, tv->len, tv->msg);
    }

    byteBuffer msg = hexStringToBytes("1010101010101010101010101010");
    for (i = 0; i < 10; ++i) {
        ccec25519secretkey sk;
        ccec25519pubkey pk;
        cced25519_make_key_pair(di, rng, pk, sk);
        snprintf(label, sizeof(label), "Generated Pair Test %zu", i + 1);
        cced_round_trip(di, label, sk, pk, NULL, msg->len, msg->bytes);
    }

    test_rng(di, msg->len, msg->bytes);
    free(msg);

    return 0;
}

#endif // CCED25519TEST
