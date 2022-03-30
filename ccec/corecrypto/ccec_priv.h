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

#ifndef _CORECRYPTO_CCEC_PRIV_H_
#define _CORECRYPTO_CCEC_PRIV_H_

#include <corecrypto/ccec.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cczp.h>

/*!
@function   ccec_generate_blinding_keys
@abstract   Generate a blinding and unblinding key.
           unblinding_key * (blinding_key * A)) == A, where A is a public key.

@param      cp               Curve parameters
@param      rng              RNG instance
@param      blinding_key     Result ccec_full_ctx_t blinding key
@param      unblinding_key   Result ccec_full_ctx_t unblinding key
@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL_ALL
int ccec_generate_blinding_keys(ccec_const_cp_t cp, struct ccrng_state *rng, ccec_full_ctx_t blinding_key, ccec_full_ctx_t unblinding_key);

/*!
@function   ccec_blind
@abstract   Blind an input public key
 
@param      rng              RNG instance
@param      blinding_key     ccec_full_ctx_t blinding key
@param      pub              Input public key to blind
@param      blinded_pub      Output blinded public key
@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL_ALL
int ccec_blind(struct ccrng_state *rng, const ccec_full_ctx_t blinding_key, const ccec_pub_ctx_t pub, ccec_pub_ctx_t blinded_pub);

/*!
@function   ccec_unblind
@abstract   Unblind an input public key
 
@param      rng                RNG instance
@param      unblinding_key     ccec_full_ctx_t unblinding key
@param      pub                Input public key to unblind
@param      unblinded_pub      Output unblinded public key
@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL_ALL
int ccec_unblind(struct ccrng_state *rng, const ccec_full_ctx_t unblinding_key, const ccec_pub_ctx_t pub, ccec_pub_ctx_t unblinded_pub);

/* Debugging */
void ccec_print_full_key(const char *label, ccec_full_ctx_t key);
void ccec_print_public_key(const char *label, ccec_pub_ctx_t key);

/*
 * EC key generation
 */

/* FIPS compliant and more secure */
/*!
 @function   ccec_generate_key_internal_fips
 @abstract   Follows FIPS guideline and more secure.
    This internal function does not perform the consistent check
    which guarantees that the key is valid (required by FIPS).
 @param      cp      Curve parameters
 @param      rng     key generation and internal countermeasures
 @param      key     Resulting key pair
 @return    0 if no error, an error code otherwise.
 */
int
ccec_generate_key_internal_fips(ccec_const_cp_t cp,  struct ccrng_state *rng,
                                ccec_full_ctx_t key);

/*!
 @function   ccec_compact_transform_key
 @abstract   Follow instructions from https://datatracker.ietf.org/doc/draft-jivsov-ecc-compact/
  to make a key compatible with the compact export format.
 @param      key     Input/Output full key
 @return    0 if no error, an error code otherwise.
 */
int ccec_compact_transform_key(ccec_full_ctx_t key);

//imports the x and y from the in array in big-endian, sets z to 1
CC_NONNULL((1, 3, 4))
int ccec_raw_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);
//imports the ecc private key k, and sets x an y to all ones.
CC_NONNULL((1, 3, 4))
int ccec_raw_import_priv_only(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key);

/*!
@function   ccec_extract_rs
@abstract   Extract the r and/or s components from a signature.
@param      key      Public EC key
@param      sig_len  Length of the signature buffer
@param      sig      Input signature buffer
@param      r        Optional output buffer of size ccec_signature_r_s_size(key)
@param      s        Optional output buffer of size ccec_signature_r_s_size(key)
@discussion Either `r` or `s` may be NULL and will not be output when this is the case.
@return     CCERR_OK if no error, an error code otherwise.
*/
CC_NONNULL((1,3))
int ccec_extract_rs(ccec_pub_ctx_t key, size_t sig_len, const uint8_t *sig, uint8_t *r, uint8_t *s);

#endif /* _CORECRYPTO_CCEC_PRIV_H_ */
