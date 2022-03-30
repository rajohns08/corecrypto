/* Copyright (c) (2011,2015-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDH_INTERNAL_H_
#define _CORECRYPTO_CCDH_INTERNAL_H_

#include <corecrypto/ccdh.h>
#include "cczp_internal.h"

#define ccdh_gp_decl_n(_n_)                                 \
struct {                                                    \
    struct cczp_hd hp;                                         \
    cc_unit p[(_n_)];         /* Prime */                   \
    cc_unit recip[((_n_)+1)]; /* precomp for field ops */   \
    cc_unit g[(_n_)];         /* Generator */               \
    cc_unit q[(_n_)];         /* Order */                   \
    cc_size l;                /* Size of the private key */ \
}

#define ccdh_gp_decl_static(_bits_) ccdh_gp_decl_n(ccn_nof(_bits_))
#define CCDH_MIN_GROUP_EXPONENT_BIT_LENGTH (cc_size)160
#define CCDH_MAX_GROUP_EXPONENT_BIT_LENGTH (cc_size)0 // 0 represents the largest possible exponent size

int ccdh_generate_private_key(ccdh_const_gp_t gp, cc_unit *x,
                              struct ccrng_state *rng);

int ccdh_check_pub(ccdh_const_gp_t gp, ccdh_pub_ctx_t public_key);

int ccdh_power_blinded(struct ccrng_state *blinding_rng,
               ccdh_const_gp_t gp,
               cc_unit *r, const cc_unit *s, const cc_unit *e);

/*!
 @function   ccdh_pairwise_consistency_check
 @abstract   Does a DH with a constant key to confirm the newly generated key is
 correct.
 @param      gp             Group parameters
 @param      rng            For key generation and internal countermeasures
 @param      key            DH key pair
 @return     true if no error, false otherwise.
 */
bool ccdh_pairwise_consistency_check(ccdh_const_gp_t gp,
                                     struct ccrng_state *rng,
                                     ccdh_full_ctx_t key);

/*!
 * @function ccdh_copy_gp
 *
 *  Function to copy a source group to a pre-declared dest group of the same size.
 *
 * @param dest
 * ccdh_gp_t of size n where you'd like the group copied.
 *
 * @param src
 * ccdh_gp_t of size n which you would like copied from
 *
 * @return CCDH_DOMAIN_PARAMETER_MISMATCH on non-matching group sizes or CCERROK otherwise.
 */
int ccdh_copy_gp(ccdh_gp_t dest, const ccdh_const_gp_t src);

/*!
 * @function ccdh_gp_ramp_exponent
 *
 *  Function to ramp a groups exponent bit-length to at least l. More precisely,
 *  If the group secret-key bit-length is already set to max-length, or a value greater than l, the current is maintained
 *  If the group secret-key bit length is less than l, the value is set to l
 *  Finally, regardless of value, if the secret-key bit-length returned would be less than a predefined secure value (currently 160),
 *  then the value is set to 160.
 
 * @param l
 * The number of bits in DH secret-keys
 *
 * @param gp
 * The group whose exponent you would like to ramp.
 */
void ccdh_ramp_gp_exponent(cc_size l, ccdh_gp_t gp);

/*!
 * @function ccdh_gp_ccn_lookup
 *
 *   Lookup a list of known `ccdh_const_gp_t` structs given prime `p` and generator `g`.
 *   Function to verify that group parameters prime p and generator g are on a list of known DH group paramters.
 *   Returns the known group if it exists, or NULL otherwise.
 *
 * @param pn
 * Length of prime `p` in cc_unit
 *
 * @param p
 * Pointer to cc_unit array containing the group prime. Prime p is provisioned in corecrypto cc_unit format.
 *
 * @param gn
 * Length of generator `g` in cc_unit
 *
 * @param g
 * Pointer to cc_unit array containing the group generator. Generator g is provisioned in cc_unit format.
 *
 * @return `ccdh_const_gp_t` if `p` and `g` are from a known group, and NULL otherwise.
 */
CC_NONNULL((2,4))

ccdh_const_gp_t ccdh_ccn_lookup_gp (cc_size pn, cc_unit *p, cc_size gn, cc_unit *g);

/*!
 * @function ccdh_valid_shared_secret
 *
 *  Function to ensure a computed DH shared secret is not 0,1 or p-1 for the prime p defining the modulus in which operations are performed.
 
 * @param n
 * The size of the shared secret s
 *
 * @param s
 * The computed shared secret.
 *
 * @param gp
 * The group defining arithment for the DH operation
 *
 * @return true if p is not 0, 1 or p-1, false otherwise.
 */
CC_NONNULL_ALL
bool ccdh_valid_shared_secret(cc_size n, const cc_unit *s, ccdh_const_gp_t gp);

#endif /* _CORECRYPTO_CCDH_GP_INTERNAL_H_ */
