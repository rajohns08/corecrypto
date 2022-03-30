/* Copyright (c) (2012,2013,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccsrp_priv.h"

/******************************************************************************
 *  Component Test Interface
 *****************************************************************************/

CC_INLINE bool ccsrp_ccn_component_equal(char *label, ccsrp_ctx_t srp, cc_unit *a, cc_unit *b)
{
    bool retval = ccn_cmp(ccsrp_ctx_n(srp), a, b) == 0;
    if (!retval) {
        cc_printf("ccsrp_test_calculations: mismatch for %s:\n", label);
        ccn_lprint(ccsrp_ctx_n(srp), "", a);
        ccn_lprint(ccsrp_ctx_n(srp), "", b);
        cc_printf("\n\n");
    }
    return retval;
}

CC_INLINE bool ccsrp_byte_component_equal(char *label, size_t len, const void *a, const void *b)
{
    bool retval = memcmp(a, b, len) == 0;
    if (!retval) {
        cc_printf("ccsrp_test_calculations: mismatch for %s:\n", label);
        cc_print("", len, a);
        cc_print("", len, b);
        cc_printf("\n");
    }
    return retval;
}

int ccsrp_test_calculations(const struct ccdigest_info *di,
                            ccsrp_const_gp_t gp,
                            struct ccrng_state *blinding_rng,
                            const char *username,
                            uint32_t options,
                            size_t password_len,
                            const void *password,
                            size_t salt_len,
                            const void *salt,
                            size_t k_len,
                            const void *k,
                            size_t x_len,
                            const void *x,
                            size_t v_len,
                            const void *v,
                            size_t a_len,
                            const void *a,
                            size_t b_len,
                            const void *b,
                            size_t A_len,
                            const void *A,
                            size_t B_len,
                            const void *B,
                            size_t u_len,
                            const void *u,
                            size_t S_len,
                            const void *S,
                            size_t K_len,
                            const void *K,
                            size_t M_len,
                            const void *M,
                            size_t HAMK_len,
                            const void *HAMK)
{
    ccsrp_ctx_decl(di, gp, srp_c);
    ccsrp_ctx_decl(di, gp, srp_s);
    ccsrp_ctx_init_option(srp_c, di, gp, options, blinding_rng);
    ccsrp_ctx_init_option(srp_s, di, gp, options, blinding_rng);
    cc_size n = ccsrp_ctx_n(srp_c);
    cc_unit input_k[n];            // vla
    cc_unit generated_k[n];        // vla
    cc_unit input_x[n];            // vla
    cc_unit generated_x[n];        // vla
    cc_unit input_v[n];            // vla
    cc_unit input_A[n];            // vla
    cc_unit input_B[n];            // vla
    cc_unit input_u[n];            // vla
    cc_unit generated_u[n];        // vla
    cc_unit input_S[n];            // vla
    cc_unit generated_server_S[n]; // vla
    cc_unit generated_client_S[n]; // vla

    ccsrp_import_ccn_with_len(srp_c, input_k, k_len, k);
    ccsrp_import_ccn_with_len(srp_c, input_x, x_len, x);
    ccsrp_import_ccn_with_len(srp_c, input_v, v_len, v);
    ccsrp_import_ccn_with_len(srp_c, ccsrp_ctx_private(srp_c), a_len, a);
    ccsrp_import_ccn_with_len(srp_c, ccsrp_ctx_private(srp_s), b_len, b);
    ccsrp_import_ccn_with_len(srp_c, input_A, A_len, A);
    ccsrp_import_ccn_with_len(srp_c, input_B, B_len, B);
    ccsrp_import_ccn_with_len(srp_c, input_u, u_len, u);
    ccsrp_import_ccn_with_len(srp_c, input_S, S_len, S);
    size_t session_key_len = 0;
    int retval = 0;

    // This requires x to be generated the same as the spec
    ccsrp_generate_x(srp_c, generated_x, username, salt_len, salt, password_len, password);
    if (!ccsrp_ccn_component_equal("x", srp_c, generated_x, input_x))
        retval = -1;

    // These need to work and are ready to try out.
    if (k_len) {
        ccsrp_generate_k(srp_c, generated_k);
        if (!ccsrp_ccn_component_equal("k", srp_c, generated_k, input_k))
            retval = -1;
    }
    ccsrp_generate_client_pubkey(srp_c);
    if (!ccsrp_ccn_component_equal("A", srp_c, ccsrp_ctx_public(srp_c), input_A))
        retval = -1;

    // since x might be whacked, we'll use the input x
    ccsrp_generate_v(srp_c, input_x);
    if (!ccsrp_ccn_component_equal("v", srp_c, ccsrp_ctx_v(srp_c), input_v))
        retval = -1;

    // since v might be whacked, we'll use the input v
    ccsrp_import_ccn_with_len(srp_s, ccsrp_ctx_v(srp_s), v_len, v);
    ccsrp_generate_server_pubkey(srp_s, input_k);
    if (!ccsrp_ccn_component_equal("B", srp_s, ccsrp_ctx_public(srp_s), input_B))
        retval = -1;

    // ccsrp_server_compute_session
    ccsrp_generate_u(srp_s, generated_u, input_A, input_B);
    if (!ccsrp_ccn_component_equal("u", srp_s, generated_u, input_u))
        retval = -1;

    ccsrp_generate_server_S(srp_s, generated_server_S, input_u, input_A);
    if (!ccsrp_ccn_component_equal("ServerS", srp_s, generated_server_S, input_S))
        retval = -1;

    ccsrp_generate_client_S(srp_c, generated_client_S, input_k, input_x, input_u, input_B);
    if (!ccsrp_ccn_component_equal("ClientS", srp_c, generated_client_S, input_S))
        retval = -1;

    // Derivation of the key
    session_key_len = ccsrp_get_session_key_length(srp_s);
    if (!(ccsrp_generate_K_from_S(srp_s, input_S) == 0 &&
          ccsrp_byte_component_equal(
              "K", K_len, ccsrp_get_session_key(srp_s, &session_key_len), K) &&
          K_len == session_key_len)) {
        retval = -1;
    }

    // Authentication token1 ccsrp_ctx_M
    ccsrp_generate_M(srp_s, username, salt_len, salt, input_A, input_B);
    if (!(M && ccsrp_byte_component_equal("M", M_len, ccsrp_ctx_M(srp_s), M))) {
        retval = -1;
    }

    // Authentication token2
    ccsrp_generate_H_AMK(srp_s, input_A);
    if (!(HAMK && ccsrp_byte_component_equal("HAMK", HAMK_len, ccsrp_ctx_HAMK(srp_s), HAMK))) {
        retval = -1;
    }
    ccsrp_ctx_clear(di, gp, srp_c);
    ccsrp_ctx_clear(di, gp, srp_s);
    return retval;
}
