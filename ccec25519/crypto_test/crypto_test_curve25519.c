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

#if (CCCURVE25519 == 0)
entryPoint(cccurve25519_tests, "cccurve25519 test")
#else
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccrng_sequence.h>
#include "curve25519_priv.h"

static int verbose = 0;

typedef struct {
    const char *e;
    const char *k;
    const char *ek;
} curve25519_test_vector;

static const curve25519_test_vector testVectors[] = {
#include "test_vectors/crypto_test_curve25519_vectors.inc"
};

static int roundtrip25519dh(ccec25519pubkey pk1, ccec25519secretkey sk1, ccec25519pubkey pk2, ccec25519secretkey sk2)
{
    ccec25519key sess1, sess2;
    cccurve25519(sess1, sk1, pk2);
    cccurve25519(sess2, sk2, pk1);

    ok_memcmp(sess1, sess2, 32, "Computed Session Keys are equal");
    return memcmp(sess1, sess2, 32) == 0;
}

static int test_kat(void)
{
    int good;
    size_t i, n;
    uint8_t ek2[32], ek3[32], ek4[32];
    ccec25519pubkey pk1, pk2;
    ccec25519secretkey sk1, sk2;
    struct ccrng_state *rng = global_test_rng;

    n = sizeof(testVectors) / sizeof(*testVectors);
    for (i = 0; i < n; ++i) {
        const curve25519_test_vector *const tv = &testVectors[i];
        byteBuffer e = hexStringToBytes(tv->e);
        byteBuffer k = hexStringToBytes(tv->k);
        byteBuffer ek = hexStringToBytes(tv->ek);

        good = (e->len == 32);
        good &= (k->len == 32);
        good &= (ek->len == 32);
        if (good) {
            cc_clear(sizeof(ek2), ek2);
            cccurve25519(ek2, e->bytes, k->bytes);
            good = (memcmp(ek->bytes, ek2, 32) == 0);
        }

        free(e);
        free(k);
        free(ek);

        ok(good, "Check test vector %zu", i + 1);
    }

    // Non-canonical tests (not used in normal Curve25519, but detects issues when used with Ed25519).

    // This is a non canonical test.
    // Public key is 2^255.
    //  If MSbit is NOT masked, equivalent (2^256 - 1) mod (2^255 - 19) = 0x25
    //  If MSbit IS masked, equivalent to  (2^255 - 1) mod (2^255 - 19) = 0x12
    cccurve25519(
        ek2,
        (const uint8_t *)"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                         "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        (const uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                         "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"); // Public key set to 2^256-1

    cccurve25519(ek3,
                 (const uint8_t *)"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                 (const uint8_t *)"\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"); // Public key set to 0x25

    cccurve25519(ek4,
                 (const uint8_t *)"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                 (const uint8_t *)"\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"); // Public key set to 0x12

    // If truncation, ek2 == ek4. If no truncation ek2 == ek3. If bug, ek2 neither == ek3 nor ek4.
    good = ((memcmp(ek2, ek3, 32) != 0) && (memcmp(ek2, ek4, 32) == 0));
    ok(good, "Non-canonical tests: most significant bit masking failure");

    cccurve25519_make_key_pair(rng, pk1, sk1);
    cccurve25519_make_key_pair(rng, pk2, sk2);

    good = roundtrip25519dh(pk1, sk1, pk2, sk2);
    return good;
}

static void test_rng(void)
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
    ccec25519key out;
    ccec25519secretkey sk;
    cccurve25519_make_priv(global_test_rng, sk);

    ccrng_sequence_init(&seq_rng, 1, &zeros);
    rv = cccurve25519_internal(out, sk, NULL, rng);
    isnt(rv, CCERR_OK, "RNG returning only zeros should fail");

    ccrng_sequence_init(&seq_rng, 1, &ones);
    rv = cccurve25519_internal(out, sk, NULL, rng);
    isnt(rv, CCERR_OK, "RNG returning only ones should fail");

    ccrng_sequence_init(&seq_rng, sizeof(prime), prime);
    rv = cccurve25519_internal(out, sk, NULL, rng);
    isnt(rv, CCERR_OK, "RNG returning only p should fail");

    prime[0] -= 1;
    ccrng_sequence_init(&seq_rng, sizeof(prime), prime);
    rv = cccurve25519_internal(out, sk, NULL, rng);
    is(rv, CCERR_OK, "RNG returning p-1 should work");
}

int cccurve25519_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(77);

    if (verbose) {
        diag("Starting curve25519 tests");
    }

    ok(test_kat(), "Check test vectors");

    test_rng();

    return 0;
}

#endif // CCCURVE25519TEST
