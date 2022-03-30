/* Copyright (c) (2010,2011,2012,2013,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCEC_INTERNAL_H_
#define _CORECRYPTO_CCEC_INTERNAL_H_

#include <corecrypto/ccec_priv.h>
#include <corecrypto/cc_priv.h>
#include "cczp_internal.h"
#include <corecrypto/cczp.h>
#include <corecrypto/cc_fault_canary.h>

/* Configuration */
#define CCEC_MASKING 1

#ifndef CCEC_VERIFY_ONLY
#define CCEC_VERIFY_ONLY 0
#endif

// In general, CCEC_USE_TWIN_MULT is set when CC_SMALL_CODE is unset.
//
// When would we set CCEC_USE_TWIN_MULT and CC_SMALL_CODE at the same
// time? It's possible we would do this when only public-key
// operations (i.e. verification) are required. Although this does
// increase code size by 1.5-2k, it is significantly faster. This may
// be enabled manually in configuration on a per-target basis by
// setting CCEC_VERIFY_ONLY. CCEC_USE_TWIN_MULT should not be set
// directly.

#define CCEC_USE_TWIN_MULT (!CC_SMALL_CODE || CCEC_VERIFY_ONLY)

#define CCEC_DEBUG 0

/* Low level ec functions and types. */

/* Macros for accessing X and Y in an ccec_affine_point and X Y and Z in
   an ccec_projective_point. */

#define ccec_const_point_x(EP, _cp_)  ((const cc_unit *)((EP)->xyz + ccec_cp_n(_cp_) * 0))
#define ccec_const_point_y(EP, _cp_)  ((const cc_unit *)((EP)->xyz + ccec_cp_n(_cp_) * 1))
#define ccec_const_point_z(EP, _cp_)  ((const cc_unit *)((EP)->xyz + ccec_cp_n(_cp_) * 2))

#define ccec_point_x(EP, _cp_)  ((EP)->xyz + ccec_cp_n(_cp_) * 0)
#define ccec_point_y(EP, _cp_)  ((EP)->xyz + ccec_cp_n(_cp_) * 1)
#define ccec_point_z(EP, _cp_)  ((EP)->xyz + ccec_cp_n(_cp_) * 2)

/* Macro to define a struct for a ccec_cp of _n_ units. This is
   only to be used for static initializers of curve parameters.
   Note that _n_ is evaluated multiple times. */
#define ccec_cp_decl_n(_n_)  struct { \
    struct cczp_hd hp; \
    cc_unit p[(_n_)]; \
    cc_unit pr[(_n_) + 1]; \
    cc_unit b[(_n_)]; \
    cc_unit gx[(_n_)]; \
    cc_unit gy[(_n_)]; \
    struct cczp_hd  hq; \
    cc_unit q[(_n_)];\
    cc_unit qr[(_n_) + 1];\
}

/* Macro to define a struct for a ccec_cp of _bits_ bits. This is
   only to be used for static initializers of curve parameters. */
#define ccec_cp_decl(_bits_) ccec_cp_decl_n(ccn_nof(_bits_))

/* accept an affine point S and set R equal to its projective representation. */
int ccec_projectify(ccec_const_cp_t cp, ccec_projective_point_t r, ccec_const_affine_point_t s,
                    struct ccrng_state *masking_rng);

/* accept a projective point S and set R equal to its affine representation. */
int ccec_affinify(ccec_const_cp_t cp, ccec_affine_point_t r, ccec_const_projective_point_t s);

/* accept a projective point S and output the x coordinate only of its affine representation. */
int ccec_affinify_x_only(ccec_const_cp_t cp, cc_unit* sx, ccec_const_projective_point_t s);

/* Take a x coordinate a recompute the point. No particular convention for y */
int ccec_affine_point_from_x(ccec_const_cp_t cp, ccec_affine_point_t r, const cc_unit *x);

/*Function to determine the size of workspace necessary for computation of ccec_affine_point_from_x_ws*/
cc_size ccec_affine_point_workspace_n(cc_size n);

/* Take an x coordinate and recompute the corresponding point. No particular convention for y.  */
int ccec_affine_point_from_x_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_affine_point_t r, const cc_unit *x);

/* Return true if the point is on the curve. Requires curve with a=-3 */
/* Z must be initialized. Set to 1 for points in affine representation */
bool ccec_is_point(ccec_const_cp_t cp, ccec_const_projective_point_t s);

/* accept an affine point S = (Sx,Sy) and return true if it is on the curve, (i.e., if SY2 = SX3 − 3SX.SZ^4 + bSZ^6 (mod p)), otherwise return false. */
bool ccec_is_point_projective(ccec_const_cp_t cp, ccec_const_projective_point_t s);

/* Validate the public key with respect to the curve information */
int ccec_validate_pub_and_projectify(ccec_const_cp_t cp,
                                     ccec_projective_point_t r,
                                     ccec_const_affine_point_t public_point,
                                     struct ccrng_state *masking_rng);

/* Validate the private scalar with respect to the curve information */
int ccec_validate_scalar(ccec_const_cp_t cp, const cc_unit* k);

/* accept a projective point S and set R equal to the projective point 2S. Routine 2.2.6 performs no checks on its inputs. */
#define CCEC_DOUBLE_WORKSPACE_SIZE(n)(6*(n))
void ccec_double_ws(cc_ws_t ws, ccec_const_cp_t cp, ccec_projective_point_t r, ccec_const_projective_point_t s);

/* accept two projective points S, T and set R equal to the projective point S + T. S and T must not be point at infinity.
 Require r!=t. Ok with r==s */
#define T_NORMALIZED    1  // expect T to be normalized (Z=1)
#define T_NEGATIVE      2  // use -T (point substration)
#define CCEC_ADD_SUB_WORKSPACE_SIZE(n) (7*(n))
void ccec_add_ws(cc_ws_t ws, ccec_const_cp_t cp,
              ccec_projective_point_t r,
              ccec_const_projective_point_t s,
              ccec_const_projective_point_t t,
              uint32_t t_flags);

/* accept two projective points S, T and set R equal to the projective point S + T . Routine 2.2.8 checks whether one of S or T is the point at infinity or whether S == T, and if so, takes the appropriate action.

 Require r!=t. Ok with r==s */
void ccec_full_add_ws(cc_ws_t ws, ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   ccec_const_projective_point_t s,
                   ccec_const_projective_point_t t);

/* accept two projective points S, T and set R equal to the projective point S + T . Routine 2.2.8 checks whether one of S or T is the point at infinity or whether S == T, and if so, takes the appropriate action.

 Require r!=t. Ok with r==s */
void ccec_full_add(ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   ccec_const_projective_point_t s,
                   ccec_const_projective_point_t t);

/* accept two projective points S, T and set R equal to the projective point S + T . Routine 2.2.8 checks whether one of S or T is the point at infinity or whether S == T, and if so, takes the appropriate action.
    T is required to be the neutral element (1 or R if Montgomery) */
void ccec_full_add_normalized_ws(cc_ws_t ws, ccec_const_cp_t cp,
                              ccec_projective_point_t r,
                              ccec_const_projective_point_t s,
                              ccec_const_projective_point_t t);

/* accept two projective points S, T and set R equal to the projective point S − T . Routine 2.2.9 checks whether one of S or T is the point at infinity or whether S == T, and if so, takes the appropriate action. */
void ccec_full_sub_ws(cc_ws_t ws, ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   ccec_const_projective_point_t s,
                   ccec_const_projective_point_t t);

/* accept two projective points S, T and set R equal to the projective point S − T . Routine 2.2.9 checks whether one of S or T is the point at infinity or whether S == T, and if so, takes the appropriate action. */
void ccec_full_sub(ccec_const_cp_t cp,
                   ccec_projective_point_t r,
                   ccec_const_projective_point_t s,
                   ccec_const_projective_point_t t);

/* accept two projective points S, T and set R equal to the projective point S − T . Routine 2.2.9 checks whether one of S or T is the point at infinity or whether S == T, and if so, takes the appropriate action.
    T is required to be the neutral element (1 or R if Montgomery)*/
void ccec_full_sub_normalized_ws(cc_ws_t ws, ccec_const_cp_t cp,
                              ccec_projective_point_t r,
                              ccec_const_projective_point_t s,
                              ccec_const_projective_point_t t);


/* accept a projective point S, an integer 1 ≤ d < q and 2 set R equal to the projective point dS.
    Requires the point s to have been generated by "ccec_projectify" */
int ccec_mult(ccec_const_cp_t cp, ccec_projective_point_t r, const cc_unit *d,
                            ccec_const_projective_point_t s,
                            struct ccrng_state *masking_rng);

/* accept two projective points S, T , two integers 0 ≤ d0, d1 < p, and set R equal to the projective point d0S + d1T. */
int ccec_twin_mult(ccec_const_cp_t cp, ccec_projective_point_t r, const cc_unit *d0,
                    ccec_const_projective_point_t s,
                    const cc_unit *d1,
                    ccec_const_projective_point_t t);

/* Debugging */
void ccec_alprint(ccec_const_cp_t cp, const char *label, ccec_const_affine_point_t s);
void ccec_plprint(ccec_const_cp_t cp, const char *label, ccec_const_projective_point_t s);

void ccec_print_sig(const char *label, size_t count, const uint8_t *s);

/*
 * EC key generation
 */

/*!
 @function   ccec_generate_scalar_fips_retry
 @abstract   Generate a random scalar k (private key) per FIPS "TestingCandidates" methodology
    Faster than the extra bit generation

 @param      cp             Curve parameters
 @param      rng            For the scalar k
 @param      k              scalar of size ccec_cp_n(cp)
 @returns    0 if no error, an error code otherwise.
 */
int
ccec_generate_scalar_fips_retry(ccec_const_cp_t cp, struct ccrng_state *rng, cc_unit *k);

/*!
 @function   ccec_generate_scalar_legacy
 @abstract   Generate a random scalar k (private key) with legacy method
    Used for legacy purpose to reconstruct existing keys.
    Behavior can not be changed

 @param      cp             Curve parameters
 @param      entropy_len    Byte length of entropy
 @param      entropy        Entropy for the scalar k
 @param      k              scalar of size ccec_cp_n(cp)
 @returns    0 if no error, an error code otherwise.
 */
int
ccec_generate_scalar_legacy(ccec_const_cp_t cp,
                            size_t entropy_len, const uint8_t *entropy,
                            cc_unit *k);

/*!
 @function   ccec_generate_scalar_fips_extrabits
 @abstract   Generate a random scalar k (private key) per FIPS methodology
        Slower than the "TestingCandidates" method
 Behavior can not be changed

 @param      cp             Curve parameters
 @param      entropy_len    Byte length of entropy
 @param      entropy        Entropy for the scalar k
 @param      k              scalar of size ccec_cp_n(cp)
 @returns    0 if no error, an error code otherwise.
 */
int
ccec_generate_scalar_fips_extrabits(ccec_const_cp_t cp, size_t entropy_len,
                                    const uint8_t *entropy, cc_unit *k);

/*!
 @function   ccec_scalar_fips_extrabits_min_entropy_len
 @abstract   Return the minimum size of the entropy to be passed to
        ccec_generate_scalar_fips_extrabits

 @param      cp             Curve parameters
 @returns    minimal value for entropy_len
 */
size_t ccec_scalar_fips_extrabits_min_entropy_len(ccec_const_cp_t cp);

/*!
 @function   ccec_generate_scalar_pka
 @abstract   Generate a random scalar k (private key) per FIPS methodology
    Similar to PKA behavior
 Behavior can not be changed

 @param      cp             Curve parameters
 @param      entropy_len    Byte length of entropy
 @param      entropy        Entropy for the scalar k
 @param      k              scalar of size ccec_cp_n(cp)
 @returns    0 if no error, an error code otherwise.
 */
int ccec_generate_scalar_pka(ccec_const_cp_t cp, size_t entropy_len,
                             const uint8_t *entropy, cc_unit *k);

/*!
 @function   ccec_make_pub_from_priv
 @abstract   The public key from the input scalar k (private key)
         This internal function does not perform the consistent check
         Which guarantees that the key is valid.
 @param      cp             Curve parameters
 @param      masking_rng    For internal countermeasures
 @param      k              scalar of size ccec_cp_n(cp), in range [1..q-1] and with no statistical bias.
 @param      key            Resulting public key
 @param      generator      Generator point / NULL if default
 @returns    0 if no error, an error code otherwise.
 */
int
ccec_make_pub_from_priv(ccec_const_cp_t cp,
                        struct ccrng_state *masking_rng,
                        const cc_unit *k,
                        ccec_const_affine_point_t generator,
                        ccec_pub_ctx_t key);

/*!
 @function   ccec_generate_key_internal_legacy
 @abstract   Generate key pair for compatiblity purposes or deterministic keys
            NOT RECOMMENDED. This internal function does not perform the consistent check
            Which guarantees that the key is valid.
 @param      cp     Curve parameters
 @param      rng    For internal countermeasures
 @param      key    Resulting key pair
 @returns    0 if no error, an error code otherwise.
 */
int
ccec_generate_key_internal_legacy(ccec_const_cp_t cp, struct ccrng_state *rng,
                           ccec_full_ctx_t key);

/*!
 @function   ccecdh_pairwise_consistency_check
 @abstract   Does a DH with a constant key to confirm the newly generated key is
    correct.
 @param      full_key            Resulting key pair
 @param      base           Base point (Pass NULL for generator)
 @param      rng            For key generation and internal countermeasures
 @returns    true if no error, false otherwise.
 */
CC_NONNULL((1, 3))
bool ccecdh_pairwise_consistency_check(ccec_full_ctx_t full_key,
                                       ccec_const_affine_point_t base,
                                       struct ccrng_state *rng);

/*
 * EC Digital Signature - ECDSA
 */

/*!
 @function   ccec_verify_internal
 @abstract   ECDSA signature verification, writing to fault_canary_out.

 @param      key                Public key
 @param      digest_len         Byte length of the digest
 @param      digest             Pointer to the digest
 @param      r                  Pointer to input buffer for r
 @param      s                  Pointer to input buffer for s
 @param      fault_canary_out  Output of type cc_fault_canary_t
 in big-endian format.

 @returns    CCERR_VALID_SIGNATURE if signature is valid.
            CCERR_INVALID_SIGNATURE if signature is invalid.
            Other error codes indicating verification failure.
 */
CC_NONNULL_ALL
int ccec_verify_internal(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                         const cc_unit *r, const cc_unit *s, cc_fault_canary_t fault_canary_out);

/*!
 @function   ccec_sign_internal
 @abstract   ECDSA signature creation.
 @param      key            Public key
 @param      digest_len     Byte length of the digest
 @param      digest         Pointer to the digest
 @param      r              Pointer to output buffer for r
 @param      s              Pointer to output buffer for s
 @returns    0 if no error, an error code otherwise.
 */
int ccec_sign_internal(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest,
                       cc_unit *r, cc_unit *s, struct ccrng_state *rng);

/*!
 @function   ccec_diversify_twin_scalars
 @abstract   Derives to scalars u,v from the given entropy.

 entropy_len must be a multiple of two, greater or equal to
 2 * ccec_diversify_min_entropy_len(). The entropy must be
 chosen from a uniform distribution, e.g. random bytes,
 the output of a DRBG, or the output of a KDF.

 @param  cp          Input:  Curve parameters
 @param  u           Output: Scalar u
 @param  v           Output: Scalar v
 @param  entropy_len Input:  Length of entropy
 @param  entropy     Input:  Entropy used to derive scalars u,v

 @result 0 iff successful

 */
CC_NONNULL((1, 2, 3, 5))
int ccec_diversify_twin_scalars(ccec_const_cp_t cp, cc_unit *u, cc_unit *v, size_t entropy_len, const uint8_t *entropy);


/*
 * RFC6637 wrap/unwrap
 */

#define ccec_rfc6637_ecdh_public_key_id    18
#define ccec_rfc6637_ecdsa_public_key_id   19

#define ccpgp_digest_sha256            8
#define ccpgp_digest_sha384            9
#define ccpgp_digest_sha512            10

#define ccpgp_cipher_aes128            7
#define ccpgp_cipher_aes192            8
#define ccpgp_cipher_aes256            9

struct ccec_rfc6637 {
    const char *name;
    const uint8_t kdfhash_id;
    const struct ccdigest_info * (*difun)(void);
    const uint8_t kek_id;
    const size_t keysize;
};

struct ccec_rfc6637_curve {
    const uint8_t *curve_oid;
    uint8_t public_key_alg;
};

extern struct ccec_rfc6637 ccec_rfc6637_sha256_kek_aes128;
extern struct ccec_rfc6637 ccec_rfc6637_sha512_kek_aes256;

void
ccec_rfc6637_kdf(const struct ccdigest_info *di,
                 const struct ccec_rfc6637_curve *curve,
                 const struct ccec_rfc6637 *wrap,
                 size_t epkey_size, const void *epkey,
                 size_t fingerprint_size, const void *fingerprint,
                 void *hash);

size_t
ccec_rfc6637_wrap_pub_size(ccec_pub_ctx_t public_key,
                           unsigned long flags);

int
ccec_rfc6637_wrap_core(ccec_pub_ctx_t  public_key,
                       ccec_full_ctx_t ephemeral_key,
                       void *wrapped_key,
                       unsigned long flags,
                       uint8_t symm_alg_id,
                       size_t key_len,
                       const void *key,
                       const struct ccec_rfc6637_curve *curve,
                       const struct ccec_rfc6637_wrap *wrap,
                       const uint8_t *fingerprint, /* 20 bytes */
                       struct ccrng_state *rng);

uint16_t
pgp_key_checksum(size_t key_len, const uint8_t *key);

/*
 * Modular multiplication/reduction assembly routines.
 */

#if CCN_MULMOD_224_ASM
void ccn_mul_224_montgomery(cc_unit *r, const cc_unit *a, const cc_unit *b);
void ccn_sqr_224_montgomery(cc_unit *r, const cc_unit *a);
void ccn_mod_224_montgomery(cc_unit *r, const cc_unit *a);
#endif

#if CCN_MULMOD_256_ASM
void ccn_mul_256_montgomery(cc_unit *r, const cc_unit *a, const cc_unit *b) __asm__("_ccn_mul_256_montgomery");
void ccn_sqr_256_montgomery(cc_unit *r, const cc_unit *a) __asm__("_ccn_sqr_256_montgomery");
void ccn_mod_256_montgomery(cc_unit *r, const cc_unit *a) __asm__("_ccn_mod_256_montgomery");
#endif


/*!
 @function   ccec_verify_strict
 @abstract   ECDSA signature verification using strict parsing DER signature.
 @param      key         Public key
 @param      digest_len  Byte length of the digest
 @param      digest      Pointer to the digest
 @param      sig_len     Byte length of the signature
 @param      sig         Pointer to signature
 @param      valid       Pointer to output boolean.
 *valid=true if the input {r,s} is valid.
 @returns    0 if no error, an error code otherwise.
 */
int ccec_verify_strict(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                       size_t sig_len, const uint8_t *sig, bool *valid);

#endif /* _CORECRYPTO_CCEC_INTERNAL_H_ */
