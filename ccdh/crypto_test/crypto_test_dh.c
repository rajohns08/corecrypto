/* Copyright (c) (2016-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "crypto_test_dh.h"
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/cc_config.h>
#include "testmore.h"
#include <stdlib.h>
#include "ccdh_internal.h"

#define F false
#define P true

static const struct ccdh_compute_vector dh_compute_vectors[]=
{
    #include "../test_vectors/DH.inc"
};

#define N_COMPUTE_VECTORS (sizeof(dh_compute_vectors)/sizeof(dh_compute_vectors[0]))

static int testDHCompute (void) {
    int rc = 1;
    for(unsigned int i = 0; i < N_COMPUTE_VECTORS; i++) {
        rc &= is(ccdh_test_compute_vector(&dh_compute_vectors[i]), 0, "testDHCompute Vector %d", i);
    }
    return rc;
}

#include <corecrypto/ccdh_gp.h>

/*
 This test generates 2 random key pairs for a given group and do the key exchange both way,
 Test fail if the generated secrets do not match
 */

static int testDHexchange(ccdh_const_gp_t gp) {
    int rc = 1;
    struct ccrng_sequence_state seq_rng;
    struct ccrng_state *rng_dummy = (struct ccrng_state *)&seq_rng;
    struct ccrng_state *rng = global_test_rng;

    /* Key exchange with l */
    const cc_size n = ccdh_gp_n(gp);
    const size_t s = ccn_sizeof_n(n);
    uint8_t key_seed[s];
    ccdh_full_ctx_decl(s, a);
    ccdh_full_ctx_decl(s, b);
    uint8_t z1[s], z2[s];
    size_t z1_len = s,z2_len = s;
    size_t private_key_length;

    
    rc &= is(ccdh_gp_prime_bitlen(gp), ccn_bitsof_n(n), "Bitlength");

    rc &= is(ccdh_generate_key(gp, rng, a), 0, "Computing first key");

    private_key_length = ccn_bitlen(n, ccdh_ctx_x(a));
    if (ccdh_gp_order_bitlen(gp)) {
        // Probabilistic test. Fails with prob < 2^-64
        rc &= ok((private_key_length<=ccdh_gp_order_bitlen(gp))
                      && (private_key_length>ccdh_gp_order_bitlen(gp)-64),
                      "Checking private key length is exactly l");
    }
    else if (ccdh_gp_l(gp)) {
        rc &= ok(private_key_length == ccdh_gp_l(gp),
                      "Checking private key length is exactly l");
    }

    rc &= is(ccdh_generate_key(gp, rng, b),0, "Computing second key");
    private_key_length = ccn_bitlen(n, ccdh_ctx_x(a));
    if (ccdh_gp_order_bitlen(gp)) {
        // Probabilistic test. Fails with prob < 2^-64
        rc &= ok((private_key_length <= ccdh_gp_order_bitlen(gp))
                      && (private_key_length > ccdh_gp_order_bitlen(gp) - 64),
                      "Checking private key length is exactly l");
    }
    else if (ccdh_gp_l(gp)) {
        rc &= ok(private_key_length == ccdh_gp_l(gp),
                      "Checking private key length is exactly l");
    }

    memset(z1,'a', z1_len);
    memset(z2,'b', z2_len);
    rc&=is(ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &z1_len, z1, rng), 0, "Computing first secret");
    rc&=is(ccdh_compute_shared_secret(b, ccdh_ctx_public(a), &z2_len, z2, rng), 0, "Computing second secret");
    rc&=is(z1_len, z2_len, "Shared key have same size");
    rc&=ok_memcmp(z1, z2, z2_len, "Computed secrets dont match");

    /* Key exchange without l, 4 steps. */
    ccdh_gp_decl(ccn_sizeof_n(n), gp2);
    ccdh_gp_t gp_local = (ccdh_gp_t)gp2;
    CCDH_GP_N(gp_local) = n;

    // a) encode / decode in gp_local
    size_t encSize = ccder_encode_dhparams_size(gp);
    uint8_t *encder = malloc(encSize);
    uint8_t *encder_end = encder + encSize;
    is(ccder_encode_dhparams(gp, encder, encder_end),encder,"Encode failed");
    isnt(ccder_decode_dhparams(gp_local, encder, encder_end),NULL,"Decode failed");
    free(encder);

    // b) Force l to 0
    CCDH_GP_L(gp_local) = 0;

    // c) re-generate the key a
    rc&=is(ccdh_generate_key(gp_local, rng, a), 0, "Computing first key with l=0");
    rc&=ok((ccn_bitlen(n, ccdh_ctx_x(a)) <= ccn_bitlen(n,ccdh_ctx_prime(a)))
                  && (ccn_bitlen(n,ccdh_ctx_x(a)) >= ccn_bitlen(n,ccdh_ctx_prime(a))) - 64,
                  "Checking private key length when l==0");

    // d) Key exchange
    z1_len = s;
    z2_len = s;
    memset(z1, 'c', z1_len);
    memset(z2, 'd', z2_len);
    
    rc &= is(ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &z1_len, z1, rng), 0, "Computing first secret");
    rc &= is(ccdh_compute_shared_secret(b, ccdh_ctx_public(a), &z2_len, z2, rng), 0, "Computing second secret");
    rc &= is(z1_len, z2_len, "Shared key have same size");
    rc &= ok_memcmp(z1, z2, z2_len,"Computed secrets dont match");

    // In the following tests, the regeneration of edge cases will fail if ccder_decode_dhaparams
    // returns the group order q in gp_local, as it changes how the random dummy keys are created.
    // To circumvent this, and get good tests, we zero out q in gp_local
    ccn_zero(CCDH_GP_N(gp_local), CCDH_GP_Q(gp_local));
    
    // e) re-generate the key a = p-2
    cc_unit p_minus_2[n];
    ccn_sub1(n, p_minus_2, ccdh_ctx_prime(a), 2);
    memcpy(key_seed, p_minus_2, s);
    ccrng_sequence_init(&seq_rng, sizeof(key_seed), key_seed);
    rc &= is(ccdh_generate_key(gp_local, rng_dummy, a), 0, "Private key with random = p-2");
    rc &= ok_memcmp(ccdh_ctx_x(a), p_minus_2, s, "Private key is p-2");

    // f) re-generate the key a = 1
    memset(key_seed, 0x00, s);
    key_seed[0] = 1;
    ccrng_sequence_init(&seq_rng, sizeof(key_seed), key_seed);
    rc &= is(ccdh_generate_key(gp_local, rng_dummy, a), 0, "Private key with random = 1");
    rc &= ok_memcmp(ccdh_ctx_x(a), key_seed, s, "Private key is 1");

    /* Negative testing */

    // 1) Bad random
    ccrng_sequence_init(&seq_rng,0,NULL);
    rc &= is(ccdh_generate_key(gp, rng_dummy, a),
                   CCERR_CRYPTO_CONFIG,
                   "Error random");

    // 2) Random too big
    uint8_t c=0xff;
    ccrng_sequence_init(&seq_rng,1,&c);
    rc &= is(ccdh_generate_key(gp_local, rng_dummy, a),
                   CCDH_GENERATE_KEY_TOO_MANY_TRIES,
                   "Value consistently too big (all FF)");

    // 3) Random too big p-1
    memcpy(key_seed, ccdh_ctx_prime(a), s);
    key_seed[0] ^= 1;
    ccrng_sequence_init(&seq_rng, 1, &c);
    rc &= is(ccdh_generate_key(gp_local, rng_dummy, a),
                   CCDH_GENERATE_KEY_TOO_MANY_TRIES,
                "Value consistently too big (p-1)");

    // 4) Verify that ccdh_valid_shared_secret is catching errors */
    cc_unit shared_secret_placebo[n];
    ccn_sub1(n, shared_secret_placebo, ccdh_gp_prime(gp), 1);
    rc &= is(ccdh_valid_shared_secret(n, shared_secret_placebo, gp), false,
            "Failure to catch shared secret that is p-1");
    ccn_seti(n, shared_secret_placebo, 0);
    rc &= is(ccdh_valid_shared_secret(n, shared_secret_placebo, gp), false,
            "Failure to catch shared secret that is 0");
    ccn_seti(n, shared_secret_placebo, 1);
    rc &= is(ccdh_valid_shared_secret(n, shared_secret_placebo, gp), false,
            "Failure to catch shared secret that is 1");
    
        // 5) Random zero
    c = 0;
    ccrng_sequence_init(&seq_rng, 1, &c);
    rc&=is(ccdh_generate_key(gp_local, rng_dummy, a),
                   CCDH_GENERATE_KEY_TOO_MANY_TRIES,
                   "Value consistently zero");

    return rc;
}

struct {
    const char *name;
    char *data;
    size_t length;
    int pass;
    int actualL;
    int retrievedL;
} dhparams[] = {
    {
        .name = "no l",
        .data = "\x30\x06\x02\x01\x03\x02\x01\x04",
        .length = 8,
        .pass = 1,
        .actualL = 0,
        .retrievedL = CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH,
    },
    {
        .name = "with l smaller than 160",
        .data = "\x30\x09\x02\x01\x03\x02\x01\x04\x02\x01\x05",
        .length = 11,
        .pass = 1,
        .actualL = 5,
        .retrievedL = CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH,
    },
    {
        .name = "with l at 160",
        .data = "\x30\x0A\x02\x01\x03\x02\x01\x04\x02\x02\x00\xA0",
        .length = 12,
        .pass = 1,
        .actualL = 160,
        .retrievedL = 160,
    },
    {
        .name = "with l at 256",
        .data = "\x30\x0A\x02\x01\x03\x02\x01\x04\x02\x02\x01\x00",
        .length = 12,
        .pass = 1,
        .actualL = 256,
        .retrievedL = 256,

    },
    {
        .name = "missing g",
        .data = "\x30\x03\x02\x01\x03",
        .length = 5,
        .pass = 0,
        .actualL = 0,
        .retrievedL = 0,
    }
};

static int testDHParameter(void) {
    const uint8_t *der, *der_end;
    const size_t size = 2048;
    ccdh_gp_decl(size, gp);
    size_t n;
    int rc=1;
    ccdh_gp_t gpfoo = (ccdh_gp_t)gp;

    CCDH_GP_N(gpfoo) = ccn_nof_size(size);

    for (n = 0; n < sizeof(dhparams) / sizeof(dhparams[0]); n++) {
        der = (const uint8_t *)dhparams[n].data;
        der_end = (const uint8_t *)dhparams[n].data + dhparams[n].length;

        size_t nNew = ccder_decode_dhparam_n(der, der_end);
        rc &= is(nNew, (size_t)1, "cc_unit is small? these have really small integers tests");

        der = ccder_decode_dhparams(gp, der, der_end);
        if (der == NULL) {
            rc &= ok(!dhparams[n].pass, "not passing test is supposed to pass");
            break;
        }
        rc &= ok(dhparams[n].pass, "passing test is not supposed to pass");

        size_t encSize = ccder_encode_dhparams_size(gp);
        if (dhparams[n].actualL == dhparams[n].retrievedL){
            rc &= is(encSize, dhparams[n].length, "length wrong");
        } else {
            rc &= isnt(encSize, dhparams[n].length, "length wrong");
        }
        
        uint8_t *encder = malloc(encSize);
        uint8_t *encder2, *encder_end;

        encder_end = encder + encSize;
        encder2 = ccder_encode_dhparams(gp, encder, encder_end);
        if (encder2 == NULL) {
            rc &= ok(false, "log foo");
            free(encder);
            break;
        }
        rc &= is(encder2, encder, "didn't encode the full length");

        // Only test for proper re-encoding if we didn't change the exponent length in read.
        if (dhparams[n].actualL == dhparams[n].retrievedL) {
             rc &= ok_memcmp(encder, dhparams[n].data, dhparams[n].length, "encoding length wrong on test %d" , n);
         }

        free(encder);
    }
    return rc;
}

// Tests to ensure that ccdh_copy_gp works. Copies an arbitrary group, and then ensures that memcmp matches the two groups.
void ccdh_copy_gp_test(void)
{
    int error;
    ccdh_const_gp_t test_group = ccdh_gp_apple768(); // Need a group to compare to, apple768 is arbitray
    ccdh_gp_decl(ccn_sizeof_n(test_group->n), gp1);
    CCDH_GP_N(gp1) = test_group->n; // Set the destination to be of the same length as the source group.
    ccdh_copy_gp(gp1, test_group);
    is(memcmp(gp1, test_group, ccdh_gp_n(test_group) * sizeof(cc_unit) ), 0, "ccdh_copy_gp_test failed memcmp, group didn't copy");
    
    // Create another group which should fail because group sizes are different
    ccdh_gp_decl (ccn_sizeof_n(test_group->n), gp2);
    CCDH_GP_N(gp2) = test_group->n + 1;
    error = ccdh_copy_gp(gp2, gp1);
    is (error, CCDH_DOMAIN_PARAMETER_MISMATCH, "ccdh_copy_gp_test failed size comparison");
    
    return;
}

// Tests to ensure that the ramp function properly increases the exponent bit-length in the group function
// in a monitonically increasing way, with a minimum bit length.
void ccdh_gp_ramp_exponent_test(void)
{
    // Need a writeable group to apply ramp function to, apple768 is arbitray
    ccdh_const_gp_t test_group = ccdh_gp_apple768();
    ccdh_gp_decl(ccn_sizeof_n(test_group->n), gp1);
    CCDH_GP_N(gp1) = test_group->n; // Set the destination to be of the same length as the source group.
    ccdh_copy_gp(gp1, test_group);

    // !!!! We use CCDH_GP_L macro below for comparison as opposed to the funciton cal ccdh_gp_l,
    // because the compiler was erroneously optimizing these calls by calling the first time, and storing the result
    // leading to erroneous reults when compiled in release mode.
    
    // Test to ensure exponents that enter lower than MIN ramp to MIN.
    CCDH_GP_L(gp1) = CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH;
    ccdh_ramp_gp_exponent(CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH - 10, gp1);
    is(CCDH_GP_L(gp1), CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH, "ccdh_gp_ramp_exponent_test: Not Min Length");
    
    // Test to ensure exponents that enter lower than MIN ramp to MIN.
    CCDH_GP_L(gp1) = CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH - 10;
    ccdh_ramp_gp_exponent(CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH - 10, gp1);
    is(CCDH_GP_L(gp1), CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH, "ccdh_gp_ramp_exponent_test: Not Min Length");

    // Test to ensure exponents that enter higher than MIN, but MAX is already set maintain max.
    CCDH_GP_L(gp1) = CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH;
    ccdh_ramp_gp_exponent(CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH + 10, gp1);
    is(CCDH_GP_L(gp1), CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH, "ccdh_gp_ramp_exponent_test: Not Max Length");
    
    // Test to ensure exponents that enter higher than MIN, but MAX is already set maintain max.
    CCDH_GP_L(gp1) = CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH;
    ccdh_ramp_gp_exponent(CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH, gp1);
    is(CCDH_GP_L(gp1), CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH,"ccdh_gp_ramp_exponent_test: Not Max Length");
 
    return;
}

static void ccdh_test_invalid_gp()
{
    ccdh_const_gp_t orig = ccdh_gp_rfc5114_MODP_1024_160();

    ccdh_gp_decl(1024, gp);
    CCDH_GP_N(gp) = ccdh_gp_n(orig);

    int rv = ccdh_copy_gp(gp, orig);
    is(rv, CCERR_OK, "ccdh_copy_gp() failed");

    // Set a generator that's not in the large prime subgroup.
    ccn_seti(ccdh_gp_n(gp), CCDH_GP_G(gp), 2);

    // Generating a DH key should fail.
    ccdh_full_ctx_decl_gp(gp, full);
    rv = ccdh_generate_key(gp, global_test_rng, full);
    is(rv, CCDH_SAFETY_CHECK, "ccdh_generate_key() should fail");

    // Generating a DH key in the original group should work.
    ccdh_full_ctx_decl_gp(orig, full2);
    rv = ccdh_generate_key(orig, global_test_rng, full2);
    is(rv, CCERR_OK, "ccdh_generate_key() failed");
}

#define TEST_GP(_name_)     diag("Test " #_name_); ok(testDHexchange(ccdh_gp_##_name_()), #_name_);
#define TEST_GP_SRP(_name_) diag("Test " #_name_); ok(testDHexchange(ccsrp_gp_##_name_()), #_name_);

int ccdh_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(567);
    
    diag("testDHCompute");
    ok(testDHCompute(), "testDHCompute");

    diag("testDHParameter");
    ok(testDHParameter(), "testDHParameter");

#if CORECRYPTO_HACK_FOR_WINDOWS_DEVELOPMENT
    TEST_GP(rfc5114_MODP_1024_160)
    TEST_GP(rfc5114_MODP_2048_224)
    TEST_GP(rfc2409group02)
    TEST_GP(rfc3526group05)
    TEST_GP(rfc3526group14)
    TEST_GP(rfc3526group15)
    TEST_GP(rfc3526group16)
    TEST_GP_SRP(rfc5054_1024)
    TEST_GP_SRP(rfc5054_2048)
#else
    TEST_GP(apple768)
    TEST_GP(rfc5114_MODP_1024_160)
    TEST_GP(rfc5114_MODP_2048_224)
    TEST_GP(rfc5114_MODP_2048_256)
    TEST_GP(rfc2409group02)
    TEST_GP(rfc3526group05)
    TEST_GP(rfc3526group14)
    TEST_GP(rfc3526group15)
    TEST_GP(rfc3526group16)
    TEST_GP(rfc3526group17)
    TEST_GP(rfc3526group18)
    TEST_GP_SRP(rfc5054_1024)
    TEST_GP_SRP(rfc5054_2048)
    TEST_GP_SRP(rfc5054_3072)
    TEST_GP_SRP(rfc5054_4096)
    TEST_GP_SRP(rfc5054_8192)
#endif
    ccdh_copy_gp_test();
    ccdh_gp_ramp_exponent_test();
    ccdh_test_gp_lookup();
    ccdh_test_invalid_gp();
    return 0;
}
