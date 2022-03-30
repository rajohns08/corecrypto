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
#ifndef _CORECRYPTO_CCSAE_PRIV_H_
#define _CORECRYPTO_CCSAE_PRIV_H_

extern const char *SAE_KCK_PMK_LABEL;              // = "SAE KCK and PMK";
extern const char *SAE_HUNT_PECK_LABEL;            // = "SAE Hunting and Pecking";
extern const uint8_t SAE_HUNT_AND_PECK_ITERATIONS; // = 40;

extern const uint8_t CCSAE_STATE_INIT;
extern const uint8_t CCSAE_STATE_COMMIT_INIT;
extern const uint8_t CCSAE_STATE_COMMIT_UPDATE;
extern const uint8_t CCSAE_STATE_COMMIT_GENERATED;
extern const uint8_t CCSAE_STATE_COMMIT_VERIFIED;
extern const uint8_t CCSAE_STATE_COMMIT_BOTH;
extern const uint8_t CCSAE_STATE_CONFIRMATION_GENERATED;
extern const uint8_t CCSAE_STATE_CONFIRMATION_VERIFIED;
extern const uint8_t CCSAE_STATE_CONFIRMATION_BOTH;

#define CCSAE_STATE_NEQ(_st_) (ccsae_ctx_state(ctx) != CCSAE_STATE_##_st_)

#define CCSAE_EXPECT_STATE(_st_)    \
    if (CCSAE_STATE_NEQ(_st_)) {    \
        return CCERR_CALL_SEQUENCE; \
    }

#define CCSAE_EXPECT_STATES(_st_, _st2_)                   \
    if (CCSAE_STATE_NEQ(_st_) && CCSAE_STATE_NEQ(_st2_)) { \
        return CCERR_CALL_SEQUENCE;                        \
    }

#define CCSAE_ADD_STATE(_st_) ccsae_ctx_state(ctx) |= CCSAE_STATE_##_st_

/* clang-format off */
#define CCSAE_Y2_FROM_X_WORKSPACE_N(n)                                                    \
    (3 * n + CC_MAX_EVAL(CCZP_TO_WORKSPACE_N(n),                                          \
                         CC_MAX_EVAL(CCZP_MUL_WORKSPACE_N(n),                             \
                                     CC_MAX_EVAL(CCZP_SQR_WORKSPACE_N(n),                 \
                                                 CCZP_IS_QUADRATIC_RESIDUE_WORKSPACE_N(n) \
                                     )                                                    \
                         )                                                                \
             )                                                                            \
    )
/* clang-format on */

#define ccsae_ctx_cp(ctx) (ctx->cp)
#define ccsae_ctx_rng(ctx) (ctx->rng)
#define ccsae_ctx_di(ctx) (ctx->di)
#define ccsae_ctx_state(ctx) (ctx->state)
#define ccsae_ctx_max_loop_iterations(ctx) (ctx->iterations) // Number of hunt-and-peck iterations
#define ccsae_ctx_kck_pmk_label(ctx) (ctx->kck_pmk_label)
#define ccsae_ctx_hunt_peck_label(ctx) (ctx->hunt_peck_label)
#define ccsae_ctx_KCK_and_PMK(ctx) ctx->kck
#define ccsae_ctx_KCK(ctx) ctx->kck
#define ccsae_ctx_PMK(ctx) ctx->pmk

#define ccsae_ctx_ccn(ctx, n) (ctx->ccn + ccec_cp_n(ccsae_ctx_cp(ctx)) * n)

// PWE
#define ccsae_ctx_PWE(ctx) ccsae_ctx_ccn(ctx, 0)
#define ccsae_ctx_PWE_x(ctx) ccsae_ctx_ccn(ctx, 0)
#define ccsae_ctx_PWE_y(ctx) ccsae_ctx_ccn(ctx, 1)
// Peer Commit Scalar
#define ccsae_ctx_peer_commitscalar(ctx) ccsae_ctx_ccn(ctx, 2)
// Commit Scalar
#define ccsae_ctx_commitscalar(ctx) ccsae_ctx_ccn(ctx, 3)
// Rand
#define ccsae_ctx_rand(ctx) ccsae_ctx_ccn(ctx, 4)
// Commit-Element
#define ccsae_ctx_CE(ctx) ccsae_ctx_ccn(ctx, 5)
#define ccsae_ctx_CE_x(ctx) ccsae_ctx_ccn(ctx, 5)
#define ccsae_ctx_CE_y(ctx) ccsae_ctx_ccn(ctx, 6)
// Peer commit-element
#define ccsae_ctx_peer_CE(ctx) ccsae_ctx_ccn(ctx, 7)
#define ccsae_ctx_peer_CE_x(ctx) ccsae_ctx_ccn(ctx, 7)
#define ccsae_ctx_peer_CE_y(ctx) ccsae_ctx_ccn(ctx, 8)

/*
    Scratch Space
 */
// If P192 & SHA-512 is used, we will overwrite values within peer_CE, but that's fine at this stage.
#define ccsae_ctx_S_PWD_SEED(ctx) (uint8_t *)(ccsae_ctx_CE(ctx))
#define ccsae_ctx_S_PWD_SEED_LSB(ctx, di) *(ccsae_ctx_S_PWD_SEED(ctx) + di->output_size - 1)
#define ccsae_ctx_S_PWD_VALUE(ctx) (ccsae_ctx_peer_CE_y(ctx))
#define ccsae_ctx_S_PWE_ym1(ctx) (ccsae_ctx_peer_CE_x(ctx))
#define ccsae_ctx_S_mask(ctx) (ccsae_ctx_peer_commitscalar(ctx))
#define ccsae_ctx_temp_lsb(ctx) *((uint8_t *)(ccsae_ctx_PWE_y(ctx)) + 0)
#define ccsae_ctx_current_loop_iteration(ctx) *((uint8_t *)(ccsae_ctx_PWE_y(ctx)) + 1)

/*! @function ccsae_gen_password_seed
 @abstract Generates the password seed (see 12.4.4.3.2 of IEEE P802.11-REVmdTM/D1.6 Part 11)

 @param di                 Digest paramaters
 @param key                Buffer containing lexographically ordered identities
 @param key_nbytes         Length of key buffer
 @param password           The input password
 @param password_nbytes    Length of the input password
 @param identifier         Optional password identifier
 @param identifier_nbytes  Length of the input password identifier
 @param counter            Counter value for hunting and pecking loop
 @param output             Output buffer for the password seed
 */
void ccsae_gen_password_seed(const struct ccdigest_info *di,
                             const uint8_t *key,
                             size_t key_nbytes,
                             const uint8_t *password,
                             size_t password_nbytes,
                             const uint8_t *identifier,
                             size_t identifier_nbytes,
                             uint8_t counter,
                             uint8_t *output);

/*! @function ccsae_gen_password_value
 @abstract Generates the password value (see 12.4.4.3.2 of IEEE P802.11-REVmdTM/D1.6 Part 11)

 @param ctx       SAE context
 @param pwd_seed  The generated password seed
 @param output    Output buffer for the password value

 @return 0 on success, non-zero on failure.
 */
int ccsae_gen_password_value(ccsae_ctx_t ctx, const uint8_t *pwd_seed, cc_unit *output);

/*! @function ccsae_gen_kck_and_pmk
 @abstract Generates the KCK and PMK (see 12.4.5.4 of IEEE P802.11-REVmdTM/D1.6 Part 11)

 @param ctx      SAE context
 @param keyseed  The generated keyseed
 @param context  Context information binding the keys to this run of the protocol

 @return 0 on success, non-zero on failure.
 */
int ccsae_gen_kck_and_pmk(ccsae_ctx_t ctx, const uint8_t *keyseed, const cc_unit *context);

/*! @function ccsae_lexographic_order_key
 @abstract Lexographically orders the input parameters.

 @param A         Identity of the first participating party
 @param A_nbytes  Length of input A
 @param B         Identity of the second participating party
 @param B_nbytes  Length of input B
 @param output    Output buffer of size A_nbytes + B_nbytes
 */
void ccsae_lexographic_order_key(const uint8_t *A, size_t A_nbytes, const uint8_t *B, size_t B_nbytes, uint8_t *output);

/*! @function ccsae_y2_from_x
 @abstract Generates the square of the 'y' coordinate, if it exists, given an `x` coordinate and curve parameters.

 @param cp    ECC parameters
 @param ws    Workspace of size CCSAE_Y2_FROM_X_WORKSPACE_N(ccec_cp_n(cp))
 @param y2     Output 'y^2'
 @param x_in  Input 'x' coordinate

 @return true on success, false on failure.
 */
bool ccsae_y2_from_x_ws(cc_ws_t ws, ccec_const_cp_t cp, cc_unit *y2, const cc_unit *x_in);

#endif /* _CORECRYPTO_CCSAE_PRIV_H_ */
