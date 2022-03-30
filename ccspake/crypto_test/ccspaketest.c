/* Copyright (c) (2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/ccspake.h>
#include "ccspake_priv.h"

#include "cc_priv.h"
#include "testmore.h"

#include "ccec_internal.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>

static int generate_point(ccspake_const_cp_t scp, uint8_t *out)
{
    ccec_const_cp_t cp = ccspake_cp_ec(scp);

    ccec_full_ctx_decl_cp(cp, full);
    ccec_ctx_init(cp, full);

    is(ccecdh_generate_key(cp, global_test_rng, full), 0, "ccecdh_generate_key");
    ccec_export_pub(ccec_ctx_pub(full), out);

    ccec_full_ctx_clear_cp(cp, full);

    return 0;
}

static int test_2_rtt(ccspake_const_cp_t cp, ccspake_const_mac_t mac, size_t sk_len)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    // Passing the wrong w1 length must fail.
    is(ccspake_generate_L(cp, w_size + 1, w1, sizeof(L), L, rng),
        CCERR_PARAMETER, "Passing the wrong w1 length must fail");

    // Passing the wrong L length must fail.
    is(ccspake_generate_L(cp, sizeof(w1), w1, pt_size + 1, L, rng),
        CCERR_PARAMETER, "Passing the wrong L length must fail");

    // Passing the wrong w length must fail.
    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, w_size + 1, w0, w1),
        CCERR_PARAMETER, "Passing the wrong w length must fail");

    // Passing the wrong w0 length must fail.
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, w_size + 1, w0, sizeof(L), L),
        CCERR_PARAMETER, "Passing the wrong w0 length must fail");

    // Passing the wrong L length must fail.
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, pt_size + 1, L),
        CCERR_PARAMETER, "Passing the wrong L length must fail");

    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];

    // Passing a wrong key share buffer length must fail.
    is(ccspake_kex_generate(ctx_p, pt_size + 1, U),
        CCERR_PARAMETER, "Passing a wrong key share buffer length must fail");

    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[16], mac_v[16];

    // Passing an excessive tag length must fail.
    isnt(ccspake_mac_compute(ctx_p, mac->di->output_size + 1, mac_p), CCERR_OK, "Generate mac_p");

    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[sk_len], sk_v[sk_len];

    // Passing the wrong shared key length must fail.
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sk_len + 1, sk_p),
        CCERR_PARAMETER, "Passing the wrong shared key length must fail");

    // Passing an excessive tag length must fail.
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, mac->di->output_size + 1, mac_v, sizeof(sk_p), sk_p),
        CCERR_OK, "Passing an excessive tag length must fail");

    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p");

    ok_memcmp_or_fail(sk_p, sk_v, sizeof(sk_p), "Shared keys don't match");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);

    return 0;
}

static int test_1p5_rtt(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");

    uint8_t U[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");

    /* SEND FLIGHT 1/3 */

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t V[pt_size];
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    uint8_t mac_v[16];
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    /* SEND FLIGHT 2/3 */

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");

    uint8_t sk_p[16];
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v");

    uint8_t mac_p[16];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");

    /* SEND FLIGHT 3/3 */

    uint8_t sk_v[16];
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p");

    ok_memcmp_or_fail(sk_p, sk_v, sizeof(sk_p), "Shared keys don't match");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);

    return 0;
}

static int test_bogus_points(ccspake_const_cp_t cp)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx);
    ccspake_const_mac_t mac = ccspake_mac_hkdf_hmac_sha256();

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    uint8_t B[pt_size];
    memcpy(B, L, pt_size);
    B[pt_size - 1] ^= 0x55;

    // Reject points that aren't on the curve.
    isnt(ccspake_verifier_init(ctx, cp, mac, rng, 0, NULL, sizeof(w0), w0, sizeof(B), B), 0,
               "Initialize SPAKE2+ verifier should fail");

    uint8_t Z[pt_size];
    Z[0] = 0x04;
    cc_clear(pt_size - 1, Z + 1);

    // Reject the point at infinity.
    isnt(ccspake_verifier_init(ctx, cp, mac, rng, 0, NULL, sizeof(w0), w0, sizeof(Z), Z), 0,
               "Initialize SPAKE2+ verifier should fail");

    is(ccspake_verifier_init(ctx, cp, mac, rng, 0, NULL, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t V[pt_size];
    is(ccspake_kex_generate(ctx, sizeof(V), V), 0, "Generate V");

    // We shouldn't get the same point back.
    isnt(ccspake_kex_process(ctx, sizeof(V), V), 0, "Process V should fail");

    // Reject points that aren't on the curve.
    isnt(ccspake_kex_process(ctx, sizeof(B), B), 0, "Process B should fail");

    // Reject the point at infinity.
    isnt(ccspake_kex_process(ctx, sizeof(Z), Z), 0, "Process Z should fail");

    // Reject invalid point lengths.
    isnt(ccspake_kex_process(ctx, sizeof(Z) - 1, Z), 0, "Process Z-1 should fail");

    ccspake_ctx_clear(cp, ctx);

    return 0;
}

static int test_mac_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac1, ccspake_const_mac_t mac2)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_init(ctx_p, cp, mac1, rng, sizeof(aad), aad, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");

    w0[w_size - 1] ^= 0x55;
    is(ccspake_verifier_init(ctx_v, cp, mac2, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[16], mac_v[16];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);

    return 0;
}

static int test_w0_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");

    w0[w_size - 1] ^= 0x55;
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[16], mac_v[16];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);

    return 0;
}

static int test_w1_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    w1[w_size - 1] ^= 0x55;
    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[16], mac_v[16];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);

    return 0;
}

static int test_aad_mismatch(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad1[16], aad2[16];
    ccrng_generate(rng, sizeof(aad1), aad1);
    ccrng_generate(rng, sizeof(aad2), aad2);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad1), aad1, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad2), aad2, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[16], mac_v[16];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);

    return 0;
}

static int test_bogus_kex(ccspake_const_cp_t cp, ccspake_const_mac_t mac)
{
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    uint8_t U[pt_size], V[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");

    is(generate_point(cp, V), 0, "Override V");

    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");

    uint8_t mac_p[16], mac_v[16];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");

    uint8_t sk_p[16], sk_v[16];
    isnt(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v should fail");
    isnt(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p should fail");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);

    return 0;
}

static int test_state_machine()
{
    ccspake_const_cp_t cp = ccspake_cp_256();
    struct ccrng_state *rng = global_test_rng;

    ccspake_ctx_decl(cp, ctx_p);
    ccspake_ctx_decl(cp, ctx_v);

    ccspake_const_mac_t mac = ccspake_mac_hkdf_hmac_sha256();

    size_t w_size = ccspake_sizeof_w(cp);
    size_t pt_size = ccspake_sizeof_point(cp);

    uint8_t w0[w_size], w1[w_size];
    ccrng_generate(rng, sizeof(w0), w0);
    ccrng_generate(rng, sizeof(w1), w1);

    uint8_t aad[16];
    ccrng_generate(rng, sizeof(aad), aad);

    uint8_t L[pt_size];
    is(ccspake_generate_L(cp, sizeof(w1), w1, sizeof(L), L, rng), 0, "Generate L from w1");

    is(ccspake_prover_init(ctx_p, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, w1), 0, "Initialize SPAKE2+ prover");
    is(ccspake_verifier_init(ctx_v, cp, mac, rng, sizeof(aad), aad, sizeof(w0), w0, sizeof(L), L), 0, "Initialize SPAKE2+ verifier");

    // P=STATE_INIT, V=STATE_INIT

    uint8_t U[pt_size];
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), 0, "Generate U");
    is(ccspake_kex_generate(ctx_p, sizeof(U), U), CCERR_CALL_SEQUENCE, "Generate U twice should fail");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), 0, "Process U");
    is(ccspake_kex_process(ctx_v, sizeof(U), U), CCERR_CALL_SEQUENCE, "Process U twice should fail");

    // P=STATE_KEX_GENERATE, V=STATE_KEX_PROCESS

    uint8_t mac_p[16], mac_v[16];
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), CCERR_CALL_SEQUENCE, "Generate mac_p should fail");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), CCERR_CALL_SEQUENCE, "Generate mac_v should fail");

    uint8_t sk_p[16], sk_v[16];
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), CCERR_CALL_SEQUENCE, "Verify mac_v should fail");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), CCERR_CALL_SEQUENCE, "Verify mac_p should fail");

    uint8_t V[pt_size];
    is(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V");
    isnt(ccspake_kex_generate(ctx_v, sizeof(V), V), 0, "Generate V twice should fail");
    is(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V");
    isnt(ccspake_kex_process(ctx_p, sizeof(V), V), 0, "Process V twice should fail");

    // P=STATE_KEX_BOTH, V=STATE_KEX_BOTH

    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), 0, "Generate mac_p");
    is(ccspake_mac_compute(ctx_p, sizeof(mac_p), mac_p), CCERR_CALL_SEQUENCE, "Generate mac_p twice should fail");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), 0, "Verify mac_p");
    is(ccspake_mac_verify_and_get_session_key(ctx_v, sizeof(mac_p), mac_p, sizeof(sk_v), sk_v), CCERR_CALL_SEQUENCE, "Verify mac_p twice should fail");

    // P=STATE_MAC_GENERATE, V=STATE_MAC_VERIFY

    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), 0, "Generate mac_v");
    is(ccspake_mac_compute(ctx_v, sizeof(mac_v), mac_v), CCERR_CALL_SEQUENCE, "Generate mac_v twice should fail");
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), 0, "Verify mac_v");
    is(ccspake_mac_verify_and_get_session_key(ctx_p, sizeof(mac_v), mac_v, sizeof(sk_p), sk_p), CCERR_CALL_SEQUENCE, "Verify mac_v twice should fail");

    // P=STATE_MAC_BOTH, V=STATE_MAC_BOTH

    ok_memcmp_or_fail(sk_p, sk_v, sizeof(sk_p), "MACs don't match");

    ccspake_ctx_clear(cp, ctx_p);
    ccspake_ctx_clear(cp, ctx_v);

    return 0;
}

static void iterated_hash(const struct ccdigest_info *di, size_t seed_len, const uint8_t *seed, size_t n, uint8_t *out)
{
    ccdigest(di, seed_len, seed, out);

    for (size_t i = 1; i < n; i++) {
        ccdigest(di, di->output_size, out, out);
    }
}

static void bighash(size_t seed_len, const uint8_t *seed, uint16_t start, size_t sz, uint8_t *out)
{
    const struct ccdigest_info *di = ccsha256_di();

    size_t n = cc_ceiling(sz, di->output_size);
    uint8_t digest[di->output_size];

    for (size_t i = 0; i < n - 1; i++) {
        iterated_hash(di, seed_len, seed, i + start, digest);
        memcpy(out, digest, sizeof(digest));
        out += sizeof(digest);
    }

    iterated_hash(di, seed_len, seed, n - 1 + start, digest);
    memcpy(out, digest, sz - di->output_size * (n - 1));
}

static int test_fixed_point(ccec_const_cp_t cp, size_t seed_len, const uint8_t *seed, cc_unit *order, const cc_unit *xy)
{
    struct ccrng_state *rng = global_test_rng;

    cc_size n = ccec_cp_n(cp);
    uint8_t encoded[1 + ccec_cp_prime_size(cp)];

    ccec_point_decl_cp(cp, r);
    ccec_point_decl_cp(cp, s);

    for (uint16_t i = 1; i < 1000; i++) {
        // Derive a pseudo-random point.
        bighash(seed_len, seed, i, sizeof(encoded), encoded);

        // Turn the first byte into either 0x02 or 0x03 (compressed format).
        encoded[0] = (encoded[0] & 1) | 2;

        cc_unit x[n];
        is(ccn_read_uint(n, x, sizeof(encoded) - 1, encoded + 1), 0, "Reading x failed");

        // Try to reconstruct a point from the given x-coordinate.
        if (ccec_affine_point_from_x(cp, (ccec_affine_point_t)s, x) != 0) {
            continue;
        }

        if (ccec_validate_pub_and_projectify(cp, r, (ccec_const_affine_point_t)s, rng) != 0) {
            continue;
        }

        // Check that (r * #E) is a point on the curve.
        if (ccec_mult(cp, s, order, r, rng) != 0 || !ccec_is_point(cp, s)) {
            continue;
        }

        if (ccec_affinify(cp, (ccec_affine_point_t)r, r) != 0) {
            continue;
        }

        // Compare the x-coordinate to the curve parameters.
        is(ccn_cmp(n, xy, ccec_point_x(r, cp)), 0, "Wrong x-coordinate");

        cc_unit *y = ccec_point_y(r, cp);

        // Compute (p - y) if we have the wrong y.
        if ((encoded[0] == 0x02) != (ccn_bit(y, 0) == 0)) {
            ccn_sub(n, y, cczp_prime(ccec_cp_zp(cp)), y);
        }

        // Compare the y-coordinate to the curve parameters.
        is(ccn_cmp(n, xy + n, y), 0, "Wrong y-coordinate");

        return 0;
    }

    return -1;
}

/*
 * Points for common groups as defined by the CFRG spec.
 *
 * Ensure the fixed points given by the spec were derived as stated and match
 * the uncompressed versions listed in our SPAKE2+ curve parameter definitions.
 *
 * <https://tools.ietf.org/html/draft-irtf-cfrg-spake2-06#section-4>
 */

static int test_points_m_n()
{
    const uint8_t seed256_m[] = "1.2.840.10045.3.1.7 point generation seed (M)";
    const uint8_t seed256_n[] = "1.2.840.10045.3.1.7 point generation seed (N)";

    const uint8_t seed384_m[] = "1.3.132.0.34 point generation seed (M)";
    const uint8_t seed384_n[] = "1.3.132.0.34 point generation seed (N)";

    const uint8_t seed521_m[] = "1.3.132.0.35 point generation seed (M)";
    const uint8_t seed521_n[] = "1.3.132.0.35 point generation seed (N)";

    /* clang-format off */
    static cc_unit order256[CCN256_N] = {
        CCN256_C(ff,ff,ff,ff,00,00,00,00,ff,ff,ff,ff,ff,ff,ff,ff,bc,e6,fa,ad,a7,17,9e,84,f3,b9,ca,c2,fc,63,25,51)
    };

    static cc_unit order384[CCN384_N] = {
        CCN384_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,c7,63,4d,81,f4,37,2d,df,58,1a,0d,b2,48,b0,a7,7a,ec,ec,19,6a,cc,c5,29,73)
    };

    static cc_unit order521[CCN521_N] = {
        CCN528_C(00,7f,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,fd,15,b6,c6,47,46,fc,85,f7,36,b8,af,5e,7e,c5,3f,04,fb,d8,c4,56,9a,8f,1f,45,40,ea,24,35,f5,18,0d,6b)
    };
    /* clang-format on */

    ccspake_const_cp_t scp256 = ccspake_cp_256();
    ccec_const_cp_t cp256 = ccspake_cp_ec(scp256);
    const cc_unit *M256 = ccspake_cp_ccn(scp256);
    const cc_unit *N256 = M256 + CCN256_N * 2;

    is(test_fixed_point(cp256, sizeof(seed256_m) - 1, seed256_m, order256, M256), 0, "Verifying M for P-256 failed");
    is(test_fixed_point(cp256, sizeof(seed256_n) - 1, seed256_n, order256, N256), 0, "Verifying N for P-256 failed");

    ccspake_const_cp_t scp384 = ccspake_cp_384();
    ccec_const_cp_t cp384 = ccspake_cp_ec(scp384);
    const cc_unit *M384 = ccspake_cp_ccn(scp384);
    const cc_unit *N384 = M384 + CCN384_N * 2;

    is(test_fixed_point(cp384, sizeof(seed384_m) - 1, seed384_m, order384, M384), 0, "Verifying M for P-384 failed");
    is(test_fixed_point(cp384, sizeof(seed384_n) - 1, seed384_n, order384, N384), 0, "Verifying N for P-384 failed");

    ccspake_const_cp_t scp521 = ccspake_cp_521();
    ccec_const_cp_t cp521 = ccspake_cp_ec(scp521);
    const cc_unit *M521 = ccspake_cp_ccn(scp521);
    const cc_unit *N521 = M521 + CCN521_N * 2;

    is(test_fixed_point(cp521, sizeof(seed521_m) - 1, seed521_m, order521, M521), 0, "Verifying M for P-521 failed");
    is(test_fixed_point(cp521, sizeof(seed521_n) - 1, seed521_n, order521, N521), 0, "Verifying N for P-521 failed");

    return 0;
}

int ccspake_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    ccspake_const_cp_t curves[] = { ccspake_cp_256(), ccspake_cp_384(), ccspake_cp_521() };

    ccspake_const_mac_t hkdf_cmac_sha256 = ccspake_mac_hkdf_cmac_aes128_sha256();
    ccspake_const_mac_t hkdf_hmac_sha256 = ccspake_mac_hkdf_hmac_sha256();
    ccspake_const_mac_t hkdf_hmac_sha512 = ccspake_mac_hkdf_hmac_sha512();

    const struct ccspake_mac *macs[] = { hkdf_cmac_sha256, hkdf_hmac_sha256 };

    int num_tests = 0;
    num_tests += 13 * 2; // rtt tests
    num_tests += 12 * 3; // w0/w1/aad mismatch
    num_tests += 14;     // bogus KEX
    num_tests *= CC_ARRAY_LEN(curves) * CC_ARRAY_LEN(macs);
    num_tests += 9 * CC_ARRAY_LEN(curves);  // bogus points
    num_tests += 13 * CC_ARRAY_LEN(curves); // 256-bit 2-rtt
    num_tests += 12 * CC_ARRAY_LEN(curves); // mac mismatch
    num_tests += 25;                        // state machine
    num_tests += 742;                       // fixed point tests
    plan_tests(num_tests);

    for (size_t i = 0; i < CC_ARRAY_LEN(curves); i++) {
        ccspake_const_cp_t cp = curves[i];

        for (size_t j = 0; j < CC_ARRAY_LEN(macs); j++) {
            ccspake_const_mac_t mac = macs[j];

            is(test_2_rtt(cp, mac, 16), 0, "SPAKE2+ 2-RTT tests failed");
            is(test_1p5_rtt(cp, mac), 0, "SPAKE2+ 1.5-RTT tests failed");
            is(test_w0_mismatch(cp, mac), 0, "w0 mismatch tests failed");
            is(test_w1_mismatch(cp, mac), 0, "w1 mismatch tests failed");
            is(test_aad_mismatch(cp, mac), 0, "AAD mismatch tests failed");
            is(test_bogus_kex(cp, mac), 0, "Bogus KEX tests failed");
        }

        is(test_bogus_points(cp), 0, "Bogus point tests failed");
        is(test_2_rtt(cp, hkdf_hmac_sha512, 32), 0, "SPAKE2+ 256-bit 2-RTT tests failed");
        is(test_mac_mismatch(cp, hkdf_cmac_sha256, hkdf_hmac_sha256), 0, "MAC mismatch test failed");
    }

    is(test_state_machine(), 0, "State machine tests failed");
    is(test_points_m_n(), 0, "Deriving points M,N failed");

    return 0;
}
