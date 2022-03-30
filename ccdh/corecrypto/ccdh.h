/* Copyright (c) (2011-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDH_H_
#define _CORECRYPTO_CCDH_H_

#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <stdbool.h>

struct ccdh_gp {
    __CCZP_ELEMENTS_DEFINITIONS()
} CC_ALIGNED(CCN_UNIT_SIZE);

/* A ccdh_gp_t is a pointer to a set of DH parameters.
 The first entry is a (short) prime field. */
typedef struct ccdh_gp *ccdh_gp_t;

/* A ccdh_const_gp_t is a const pointer to a set of DH parameters.
 The first entry is a const prime field. */
typedef const struct ccdh_gp *ccdh_const_gp_t;

/* The ccdh_full_ctx_decl macro allocates an array of ccdh_full_ctx */
struct  ccdh_full_ctx {
    ccdh_const_gp_t     gp;
    uint8_t             pad[16 - sizeof(ccdh_const_gp_t *)];
    cc_unit             xy[];
} CC_ALIGNED(16) ;

/* The ccdh_pub_ctx_decl macro allocates an array of ccdh_pub_ctx */
struct  ccdh_pub_ctx {
    ccdh_const_gp_t     gp;
    uint8_t             pad[16 - sizeof(ccdh_const_gp_t *)];
    cc_unit             xy[];
} CC_ALIGNED(16) ;

/* A ccdh_full_ctx_t is a pointer to a dh key pair.  It should be
 allocated to be sizeof(ccdh_full_ctx_decl()) bytes. Each of the
 ccns within a dh key is always ccdh_ctx_n() cc_units long. */

typedef struct ccdh_full_ctx *ccdh_full_ctx_t;
typedef struct ccdh_pub_ctx *ccdh_pub_ctx_t;


/* Return the size of an ccdh_full_ctx where each ccn is _size_ bytes. */
/* Full has x and y */
#define ccdh_full_ctx_size(_size_)  (sizeof(struct ccdh_full_ctx) + 2 * (_size_))
/* Pub has only y */
#define ccdh_pub_ctx_size(_size_)   (sizeof(struct ccdh_pub_ctx) + 1 * (_size_))

/* Declare a fully scheduled dh key.  Size is the size in bytes each ccn in
   the key.  For example to declare (on the stack or in a struct) a 1024 bit
   dh public key named foo use ccdh_pub_ctx_decl(ccn_sizeof(1024), foo). */
#define ccdh_full_ctx_decl(_size_, _name_)  cc_ctx_decl(struct ccdh_full_ctx, ccdh_full_ctx_size(_size_), _name_)
#define ccdh_pub_ctx_decl(_size_, _name_)   cc_ctx_decl(struct ccdh_pub_ctx, ccdh_pub_ctx_size(_size_), _name_)


#define ccdh_pub_ctx_clear(_size_, _name_)   cc_clear(ccdh_pub_ctx_size(_size_), _name_)
#define ccdh_full_ctx_clear(_size_, _name_)  cc_clear(ccdh_full_ctx_size(_size_), _name_)
/* Declare storage for a fully scheduled dh key for a given set of dh parameters. */
#define ccdh_full_ctx_decl_gp(_gp_, _name_) ccdh_full_ctx_decl(ccdh_ccn_size(_gp_), _name_)
#define ccdh_pub_ctx_decl_gp(_gp_, _name_)  ccdh_pub_ctx_decl(ccdh_ccn_size(_gp_), _name_)

/* Return the length of the prime for gp in bits. */
#define ccdh_gp_prime_bitlen(GP)  (cczp_bitlen((cczp_const_t)(GP)))

/* Return the sizeof the prime for gp. */
#define ccdh_gp_prime_size(GP)  (ccdh_ccn_size(GP))

/* Group parameters accessors */
/* If you set the structure manually, you must set it to zero to be
 future proof */
#define CCDH_GP_N(_gp_)         (CCZP_N(_gp_))
#define CCDH_GP_PRIME(_gp_)     (CCZP_PRIME(_gp_))
#define CCDH_GP_ZP(_gp_)        ((cczp_t)(_gp_))
static inline cczp_const_t ccdh_gp_zp(ccdh_const_gp_t gp) { return (cczp_const_t) gp;}
#define CCDH_GP_RECIP(_gp_)     (CCZP_RECIP((_gp_)))

#define CCDH_GP_G(_gp_)         (CCDH_GP_RECIP(_gp_) + 1 + ccdh_gp_n(_gp_))  // recip size is n+1
#define CCDH_GP_L(_gp_)         (*((CCDH_GP_Q(_gp_) + ccdh_gp_n(_gp_)))) // Size of the private key in bit.
#define CCDH_GP_Q(_gp_)         (CCDH_GP_G(_gp_) + ccdh_gp_n(_gp_))          // generator size is n
/* l must be chosen wisely to avoid the private key to be recoverable with the Pohlig-Hellman algorithm for example. "Small" l is only possible for special groups for example when p is a safe prime. */

/* Return the size of a ccdh_gp where the prime is of _size_ bytes. */
#define ccdh_gp_size(_size_) (cczp_size(_size_) + 2 * (_size_) + ccn_sizeof_n(1))

/* Declare a gp  */
#define ccdh_gp_decl(_size_, _name_)  cc_ctx_decl(struct ccdh_gp, ccdh_gp_size(_size_), _name_)

/* lvalue accessors to ccdh_ctx fields. (only a ccdh_full_ctx_t has y). */
/* gp: group parameter */
#define ccdh_ctx_gp(KEY)     (((ccdh_pub_ctx_t)(KEY))->gp)
/* n: size of group */
#define ccdh_ctx_n(KEY)      (ccdh_gp_n(ccdh_ctx_gp(KEY)))
/* prime: group prime */
#define ccdh_ctx_prime(KEY)  (ccdh_gp_prime(ccdh_ctx_gp(KEY)))
/* y: the public key */
#define ccdh_ctx_y(KEY)    ((KEY)->xy)
/* x: the private key */
#define ccdh_ctx_x(KEY)    (ccdh_ctx_y(KEY) + 1 * ccdh_ctx_n(KEY))  

CC_INLINE
ccdh_pub_ctx_t ccdh_ctx_public(ccdh_full_ctx_t key) {
    return (ccdh_pub_ctx_t)key;
}

/* Callers must call this function to initialze a ccdh_full_ctx or
 ccdh_pub_ctx before using most of the macros in this file. */
CC_INLINE CC_NONNULL((1))
void ccdh_ctx_init(ccdh_const_gp_t gp, ccdh_pub_ctx_t key) {
    key->gp = gp;
}

/* rvalue accessors to ccdh_ctx fields. */

/* Return count (n) of a ccn for gp. */
CC_INLINE CC_NONNULL((1))
cc_size ccdh_gp_n(ccdh_const_gp_t gp) {
    return cczp_n((cczp_const_t)gp);
}

CC_INLINE CC_NONNULL((1))
const cc_unit *ccdh_gp_prime(ccdh_const_gp_t gp) {
    return cczp_prime((cczp_const_t)gp);
}

CC_INLINE CC_NONNULL((1))
const cc_unit *ccdh_gp_recip(ccdh_const_gp_t gp) {
    return cczp_recip((cczp_const_t)gp);
}

CC_INLINE CC_NONNULL((1))
const cc_unit *ccdh_gp_g(ccdh_const_gp_t gp) {
    return CCDH_GP_G(gp);
}

CC_INLINE CC_NONNULL((1))
const cc_unit *ccdh_gp_order(ccdh_const_gp_t gp) {
    return CCDH_GP_Q(gp);
}

CC_INLINE CC_NONNULL((1))
size_t ccdh_gp_l(ccdh_const_gp_t gp) {
    return (size_t)CCDH_GP_L((ccdh_const_gp_t)gp);
}

/* Return sizeof a ccn for gp. */
CC_INLINE CC_NONNULL((1))
size_t ccdh_ccn_size(ccdh_const_gp_t gp) {
    return ccn_sizeof_n(CCZP_N(gp));
}

CC_INLINE CC_NONNULL((1))
size_t ccdh_gp_order_bitlen(ccdh_const_gp_t gp) {
    return ccn_bitlen(ccdh_gp_n(gp),ccdh_gp_order(gp));
}



/* DH group parameter initialization */

/*
 * Group paramters must be well chosen to avoid serious security issues.
 *  a) ccdh_init_gp with l>0 is to be used for group parameter where p is a safe prime.
 *     l should be at least twice the security level desired (128bit security => l=256).
 *     If you are not sure, set l=0, it is slow but it is safe against attacks using the
 *     Pohlig-Hellman algorithm for example.
 *  b) ccdh_init_gp_with_order is to be used when the group prime is not a safe prime:
 *     the order is necessary to avoid small subgroup attacks and generate the private key
 *     efficiently
 *  c) ccdh_init_gp_with_order to set the group from byte.
 *           If the group prime is not a safe prime, the order MUST be provided to avoid small subgroup attacks
 *           If the group prime is a safe prime, l should be at least twice the security level desired (128bit security => l=256).
 *                  If you are not sure, set l=0, it is slow but it is safe against attacks using the
 *                  Pohlig-Hellman algorithm for example.
 */
CC_NONNULL((1, 3, 4))
int ccdh_init_gp(ccdh_gp_t gp, cc_size n,
                 const cc_unit *p,
                 const cc_unit *g,
                 cc_size l);

CC_NONNULL((1, 3, 4, 5))
int ccdh_init_gp_with_order(ccdh_gp_t gp, cc_size n,
                            const cc_unit *p,
                            const cc_unit *g,
                            const cc_unit *q);

CC_NONNULL((1, 4, 6))
int ccdh_init_gp_from_bytes(ccdh_gp_t gp, cc_size n,
                            size_t p_len, const uint8_t *p,
                            size_t g_len, const uint8_t *g,
                            size_t q_len, const uint8_t *q,
                            cc_size l);

/*!
 * @function ccdh_gp_lookup
 *
 *   Lookup a list of known `ccdh_const_gp_t` structs given prime `p` and generator `g`.
 *   Function to verify that group parameters prime p and generator g past with length in bytes, and
 *   assumed to be in hex in *Big Endian* are on a list of known DH group paramters.
 *   Returns the known group if it exists, or NULL otherwise.
 *
 * @param p_nbytes
 * Length of prime `p` in bytes.
 *
 * @param p
 * Pointer to byte array containing the group prime. Prime p is provisioned in Big Endian format.
 *
 * @param g_nbytes
 * Length of generator `g` in bytes.
 *
 * @param g
 * Pointer to byte array containing the group generator. Generator g is provision in Big Endian format.
 *
 * @return `ccdh_const_gp_t` if `p` and `g` are from a known group, and NULL otherwise.
 */
CC_NONNULL((2,4))
ccdh_const_gp_t ccdh_lookup_gp(size_t p_nbytes, uint8_t *p, size_t g_nbytes, uint8_t *g);

/* 
 * Generate a DH private/public key pair from the group parameter 
 */
CC_NONNULL((1, 2))
int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng,
                      ccdh_full_ctx_t key);

/* 
 * Compute an DH shared secret between private_key and public_key after validation the public key.
 * Returns the result in computed_key, which must be an array of ccdh_ctx_n(private_key) cc_units
 * DEPRECATED - use ccdh_compute_shared_secret
 */

CC_NONNULL((1, 2, 3))
int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key,
                     cc_unit *computed_key)
cc_deprecate_with_replacement("ccdh_compute_shared_secret", 13.0, 10.15, 13.0, 6.0, 4.0);

/* Leading bytes of computed_shared_secret (a.k.a. Z) that contain all zero bits 
 are stripped before it is used as the shared secret. Match common specs such as TLS */
CC_NONNULL((1, 2, 4))
int ccdh_compute_shared_secret(ccdh_full_ctx_t private_key,
                               ccdh_pub_ctx_t public_key,
                               size_t *computed_shared_secret_len,
                               uint8_t *computed_shared_secret,
                               struct ccrng_state *blinding_rng);

/* Import a public key. The imported key is an Octet String, as defined in PKCS#3 */
CC_NONNULL((1, 3))
int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in,
                    ccdh_pub_ctx_t key);

/* Import a private key. The imported key is an Octet String, as defined in PKCS#3 */
CC_NONNULL((1, 3))
int ccdh_import_priv(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in,
                     ccdh_full_ctx_t key);

/* Import a private key. The imported key is an Octet String, as defined in PKCS#3 */
CC_NONNULL((1, 3))
int ccdh_import_full(ccdh_const_gp_t gp,
                     size_t in_priv_len, const uint8_t *in_priv,
                     size_t in_pub_len,  const uint8_t *in_pub,
                     ccdh_full_ctx_t key);

/* Return the sizeof a buffer needed to exported public key to. */
CC_INLINE CC_NONNULL((1))
size_t ccdh_export_pub_size(ccdh_pub_ctx_t key) {
    return ccdh_gp_prime_size(ccdh_ctx_gp(key));
}

/* Export public key to out. Out must be ccdh_export_pub_size(key) bytes long.
   The key is exported as an Octet String, as defined in PKCS#3 */
CC_NONNULL((1, 2))
void ccdh_export_pub(ccdh_pub_ctx_t key, void *out);

/* 
 * ASN.1/DER glue from PKCS #3 :
 * prime p, generator g, and optional privateValueLength l
 */

CC_NONNULL((1))
size_t ccder_encode_dhparams_size(const ccdh_const_gp_t gp);

CC_NONNULL((1, 2, 3))
uint8_t * ccder_encode_dhparams(const ccdh_const_gp_t gp, uint8_t *der, uint8_t *der_end);

/* CCZP_N(gpfoo.zp) must be set before decoding */
CC_NONNULL((1, 2))
const uint8_t *ccder_decode_dhparams(ccdh_gp_t gp, const uint8_t *der, const uint8_t *der_end);

/* returns the n needed for ccdh_gp_decl/heap allocation of a ccdh_gp_t, can be larger then the actual size used */
CC_NONNULL((1))
cc_size ccder_decode_dhparam_n(const uint8_t *der, const uint8_t *der_end);

#endif /* _CORECRYPTO_CCDH_H_ */
