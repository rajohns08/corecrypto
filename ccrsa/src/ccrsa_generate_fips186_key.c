/* Copyright (c) (2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>
#include "ccrsa_internal.h"
#include "cc_debug.h"
#include <corecrypto/ccrng_rsafips_test.h>
#include <corecrypto/cc_macros.h>
#include "ccprime_internal.h"
#include "cczp_internal.h"
#include "ccn_internal.h"

// Utility macros.
#define ccn_cleartop(N,r,partial_n) \
    if((N)>(partial_n)) ccn_zero((N)-(partial_n), (r)+(partial_n))

// Configuration
#define SEED_X_MAX_RETRIES          100
#define RESEED_MAX_RETRIES          100
#define GENERATE_Q_MAX_RETRIES      100

#if !CC_DISABLE_RSAKEYGEN
// Use approximation for sqrt[2]:
// We precompute Sqrt(2)*2^255. Mathematica code snippet:
//  mySqrt2 = IntegerPart[N[Sqrt[2]*2^255, 40]];
//  Print[IntegerString[IntegerDigits[mySqrt2, 256], 16, 2]]

static const cc_unit sqrt_2_n = CCN256_N;
static const cc_unit sqrt_2[] = {CCN256_C(b5,04,f3,33,f9,de,64,84,59,7d,89,b3, \
                75,4a,be,9f,1d,6f,60,ba,89,3b,a8,4c,ed,17,ac,85,83,33,99,15)};

//==============================================================================
//                              Internal functions
//==============================================================================

// Determinate how many iterations of Miller-Rabin must be perform to achieve
// primality provablity in case primality testing relies solely on Miller-Rabin
// testing.
// Based on FIPS 186-4, combination of Table C2 and C3.
// C3 table for p and q being 512bits (2^-100 minium security)
// C2 table for p and q being 1024, 1536 (respectively 2^-112 and 2^128).
static cc_size
ccrsa_fips186_MR_only_iteration_number(cc_size bitlen) {
    cc_size iteration_nb=0;
    // for p1, p2, q1, q2
    if (bitlen<=170) {
        iteration_nb=38;
    }
    else if (bitlen<512) {
        iteration_nb=41;
    }
    // for p, q: 512
    else if (bitlen<1024) {
        iteration_nb=7;
    }
    // for p, q: 1024
    else if (bitlen<1536) {
        iteration_nb=5;
    }
    // for p, q: 1536 and above
    else {
        iteration_nb=4;
    }
    return iteration_nb;
}

// Determinate the bit length of p1, p2 for bit length of p.
// Per FIPS186-4, table Table B.1., p52
static cc_size
ccrsa_fips186_auxiliary_prime_length(cc_size plen) {
    cc_size auxiliary_prime_bitlen;
    // p,q bitlength <= 512: 1024 RSA key size (and below)
    if (plen<=512) {
        auxiliary_prime_bitlen=101;
    }
    // p,q bitlength [512,1024]: 2048 RSA key size
    else if (plen<=1024) {
        auxiliary_prime_bitlen=141;
    }
    // p,q bitlength>1024: 3072 RSA key size (and above)
    else {
        auxiliary_prime_bitlen=171;
    }
    return auxiliary_prime_bitlen;
}

// Check absolute value against delta
// -1,0 => |p-q| or | | <= 2^(plen-100)
// 1    => |u-v| > delta
static int
cczp_check_delta_100bits(cc_size n,
                         const cc_unit *p, const cc_unit *q,
                         const cc_unit *Xp, const cc_unit *Xq)
{
    CC_DECL_WORKSPACE_OR_FAIL(ws, 2 * n + CCN_ABS_WORKSPACE_N(n));
    CC_DECL_BP_WS(ws, bp);

    cc_unit *tmp = CC_ALLOC_WS(ws, n);
    cc_unit *delta = CC_ALLOC_WS(ws, n);
    cc_size pbits=ccn_bitlen(n,p);
    int r1,r2;

    // 2^(plen-100)
    ccn_zero(n,delta);
    ccn_set_bit(delta,pbits-100, 1);

    // Abs(p,q)
    ccn_abs_ws(ws, n, tmp, p, q);
    r1=ccn_cmp(n,tmp,delta);

    // Abs(Xp,Xq)
    ccn_abs_ws(ws, n, tmp, Xp, Xq);
    r2=ccn_cmp(n,tmp,delta);

    CC_FREE_BP_WS(ws,bp);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);

    if (r1 + r2 == 2) {
        return CCERR_OK;
    }

    return CCRSA_KEYGEN_PQ_DELTA_ERROR;
}

// Provided a value, find the next prime by increment.
static int
cczp_find_next_prime(cczp_t p, struct ccrng_state *rng_mr) {
    cc_size n = cczp_n(p);
    cc_size MR_iterations=ccrsa_fips186_MR_only_iteration_number(ccn_bitlen(n,cczp_prime(p)));

    // Substract by two, check the value was >= 2.
    if(ccn_sub1(n, CCZP_PRIME(p), cczp_prime(p), 2) != 0) return CCRSA_KEYGEN_NEXT_PRIME_ERROR;

    // Make it odd
    CCZP_PRIME(p)[0] |= 1;

    // Increment until probably prime according to Miller-Rabin.
    do
    {
        // Increment to try again
        if(ccn_add1(n, CCZP_PRIME(p), cczp_prime(p), 2) != 0) return CCRSA_KEYGEN_NEXT_PRIME_ERROR;
        // Exit if we get a carry (integer can't be represented over n units.
    } while (ccprime_rabin_miller(n, cczp_prime(p), MR_iterations, rng_mr) == 0);

    return cczp_init(p);
}

// Generate a random number X such that
// (Sqrt(2)*(2^(pbits-1))<= X <= (2^(pbits)-1)
static int
ccn_seed_X(cc_size n, cc_unit *X, cc_size pbits, struct ccrng_state *rng) {
    int status=CCRSA_KEYGEN_SEED_X_ERROR;
    ccn_zero(n, X);
    cc_unit tmp[n];//vla
    ccn_zero(n,X);

    for (size_t i=0;i<SEED_X_MAX_RETRIES;i++) {
        // Generate a random number X
        cc_require(ccn_random_bits(pbits, X, rng)==0,cleanup);

        // Set most significant bit
        ccn_set_bit(X,(pbits-1), 1); // must be pbits long

        // Compare to an approximation of sqrt2:
        // copy X to tmp, bit-shift tmp to compare against sqrt_2
        ccn_shift_right_multi(n, tmp, X, pbits-ccn_bitsof_n(sqrt_2_n));
        if ((ccn_cmp(sqrt_2_n,tmp,sqrt_2)!=-1))
        {
            status=0;
            break;
        }
    }

cleanup:
    ccn_clear(n,tmp);
    return status;
}

// Generate the two auxiliary primes r1 and r2 from rng provided specified sizes.
static int
cczp_generate_auxiliary_primes(cc_size r1bits, cczp_t r1, cc_size r2bits, cczp_t r2, struct ccrng_state *rng, struct ccrng_state *rng_mr, struct ccrsa_fips186_trace *trace) {
    int status=CCRSA_KEYGEN_SEED_r_ERROR;
    // Take seeds for r1 and r2
    ccn_zero(CCZP_N(r1),CCZP_PRIME(r1));
    ccn_zero(CCZP_N(r2),CCZP_PRIME(r2));
    if(ccn_random_bits(r1bits, CCZP_PRIME(r1), rng)) goto errOut;
    if(ccn_random_bits(r2bits, CCZP_PRIME(r2), rng)) goto errOut;

    // Set MSbit to guarantee bitsize
    ccn_set_bit(CCZP_PRIME(r1), r1bits-1, 1); // must be rxbits long
    ccn_set_bit(CCZP_PRIME(r2), r2bits-1, 1); // must be rxbits long

    if (trace) {
        cc_assert((CCZP_N(r1) * sizeof(cc_unit)) <= sizeof(trace->xp1));
        cc_assert((CCZP_N(r2) * sizeof(cc_unit)) <= sizeof(trace->xp2));

        trace = trace + trace->curr;
        trace->bitlen1 = cczp_bitlen(r1);
        trace->bitlen2 = cczp_bitlen(r2);
        cc_memcpy(trace->xp1, cczp_prime(r1), CCZP_N(r1) * sizeof(cc_unit));
        cc_memcpy(trace->xp2, cczp_prime(r2), CCZP_N(r2) * sizeof(cc_unit));
        trace->xp1[0] |= 1; //these two operations are done in cczp_find_next_prime();
        trace->xp2[0] |= 1; //but I cannot catch r1 & r2 there.
    }

    // Transform seed into primes
    status=cczp_find_next_prime(r1, rng_mr);
    if (status!=0) goto errOut;

    status=cczp_find_next_prime(r2, rng_mr);
    if (status!=0) goto errOut;

    if (trace) {
        cc_assert((CCZP_N(r1) * sizeof(cc_unit)) <= sizeof(trace->p1));
        cc_assert((CCZP_N(r2) * sizeof(cc_unit)) <= sizeof(trace->p2));

        cc_memcpy(trace->p1, cczp_prime(r1), CCZP_N(r1) * sizeof(cc_unit));
        cc_memcpy(trace->p2, cczp_prime(r2), CCZP_N(r2) * sizeof(cc_unit));
    }

errOut:
    return status;
}

// R = ((r2^–1 mod 2r1) * r2) – (((2r1)^–1 mod r2) * 2r1).
// Output is {R, r1r2x2}
static int cczp_compute_R(cc_size n, cc_unit *R, cczp_t r1r2x2, cczp_const_t r1, cczp_const_t r2)
{
    cc_assert(cczp_n(r1) == cczp_n(r2));

    // Per spec, defined as the CRT so that R=1 (mod 2*r1) and R=-1 (mod r2)
    // This can be rewritten using Garner recombination (HAC p613)
    // R = 1 + 2*r1[r2 - ((r1)^-1 mod r2)]

    cc_size r1_bitsize=cczp_bitlen(r1);
    cc_size r2_bitsize=cczp_bitlen(r2);
    cc_size r_n = ((1+r1_bitsize) > r2_bitsize) ? ccn_nof((1+r1_bitsize)):ccn_nof(r2_bitsize);
    cc_assert(2*r_n<=n);

    // All intermediary variables normalized to fit on r_n cc_units
    cc_unit tmp1[r_n];//vla
    cc_unit tmp2[r_n];//vla

    // Calculate tmp1 = (r1^{-1} mod r2)
    int rv = cczp_inv(r2, tmp1, cczp_prime(r1));
    ccn_cleartop(r_n, tmp1, cczp_n(r2));
    if (rv) {
        return rv;
    }

    // Go on with Garner's recombination
    ccn_setn(r_n, R, ccn_nof(r2_bitsize), cczp_prime(r2));  // normalize r2 (R as temp)
    ccn_sub(r_n,tmp1,R,tmp1);                               // r2 - ((r1)^-1 mod r2)
    ccn_setn(r_n, tmp2, ccn_nof(r1_bitsize), cczp_prime(r1)); // normalize r1
    ccn_add(r_n, tmp2, tmp2, tmp2);                         // 2*r1

    // r1*r2*2
    ccn_mul(r_n, CCZP_PRIME(r1r2x2), tmp2, R);
    ccn_cleartop(n, CCZP_PRIME(r1r2x2), 2*r_n);
    rv = cczp_init(r1r2x2);
    if (rv) {
        return rv;
    }

    // R = 1 + 2*r1*(r2 - ((r1)^-1 mod r2))
    ccn_mul(r_n, R, tmp2, tmp1);
    ccn_add1(2*r_n, R, R, 1); // can't overflow since ((r1)^-1 mod r2) > 0)
    ccn_cleartop(n, R, 2*r_n);

    // Clear temporary buffers
    ccn_clear(r_n, tmp1);
    ccn_clear(r_n, tmp2);

    return CCERR_OK;
}

// Generate {p, X} from primes r1 and r2.
// Follows FIPS186-4, B.3.6
// "n" of both p and X must have been set
static int
ccrsa_generate_probable_prime_from_auxilary_primes(cc_size pbits, cczp_t p, cc_unit *X,
                                                   cczp_const_t  r1,  cczp_const_t  r2,
                                                   const cc_size e_n, const cc_unit *e,
                                                   struct ccrng_state *rng,
                                                   struct ccrng_state *rng_mr,
                                                   struct ccrsa_fips186_trace *trace)
{
    cc_size i;

    int prime_status=CCRSA_KEYGEN_PRIME_NEED_NEW_SEED;
    cc_size n = cczp_n(p);
    cc_size MR_iterations=ccrsa_fips186_MR_only_iteration_number(pbits);
    cc_size r1r2x2max_bitsize;

    // Temp variable for the main loop
    cc_unit R[n];//vla
    cczp_decl_n(n, r1r2x2);
    CCZP_N(r1r2x2) = n;

    // Pre-requisite: Check log2(r1.r2) <= pbits - log2(pbits) - 6
    // Equivalent to Check log2(2.r1.r2) <= pbits - log2(pbits) - 5
    R[0]=pbits;
    r1r2x2max_bitsize=pbits-ccn_bitlen(1,R)-5;

    // This constraint met by ccrsa_fips186_auxiliary_prime_length
    // Therefore no need to check here.

    // 1) Check GCD(2r1,r2)!=1
    // r1 and r2 are prime and >2 so this check is not needed.

    // 2) R = ((r2^–1 mod 2r1) * r2) – (((2r1)^–1 mod r2) * 2r1).
    // and compute 2.r1.r2
    int rv = cczp_compute_R(n, R, r1r2x2, r1, r2);
    if (rv) {
        prime_status = CCRSA_KEYGEN_PRIME_SEED_GENERATION_ERROR;
    } else if (cczp_bitlen(r1r2x2) > r1r2x2max_bitsize) {
        prime_status = CCRSA_KEYGEN_R1R2_SIZE_ERROR;
    }

    // Outter loop for reseeding (rare case)
    for (size_t ctr=0; (ctr<RESEED_MAX_RETRIES) && (prime_status==CCRSA_KEYGEN_PRIME_NEED_NEW_SEED);ctr++)
    {
        cc_unit c; // carry

        // 3) Generate random X
        if (ccn_seed_X(n,X,pbits,rng)!=0) {
            prime_status=CCRSA_KEYGEN_PRIME_SEED_GENERATION_ERROR;
            break;
        }

        if (trace) {
            cc_assert((n * sizeof(cc_unit)) <= sizeof(trace->xp));

            trace = trace + trace->curr;
            cc_memcpy(trace->xp, X, n * sizeof(cc_unit));
        }

        // 4) Y = X+((R–X) mod 2r1r2)
        {
            cc_unit tmp[n];//vla
            cczp_modn(r1r2x2,tmp,n,X); // X mod 2r1r2
            cczp_sub(r1r2x2,CCZP_PRIME(p),R,tmp);  // (R-X) mod 2r1r2
            c=ccn_add(n,CCZP_PRIME(p),X,CCZP_PRIME(p));
            cc_clear(sizeof(tmp),tmp);
            // c is used for 1st iteration of for loop
        }

        // Inner loop for incremental search.
        // Candidate is now in p.
        // 5,8,9) Increment p until a good candidate is found
        // Iterate a maximum of 5*pbits
        prime_status=CCRSA_KEYGEN_PRIME_TOO_MANY_ITERATIONS;
        for (i=0;i<5*pbits;i++)
        {
            // 6) Check p >= 2^pbits
            if ((c>0) || (pbits<ccn_bitlen(cczp_n(p), cczp_prime(p)))) {
                // Candidate is too large, needs new seed
                prime_status=CCRSA_KEYGEN_PRIME_NEED_NEW_SEED;
                break;
            }

            /* Check that p is a prime and gcd(p-1,e) == 1. */
            rv = ccrsa_is_valid_prime(n, cczp_prime(p), e_n, e, MR_iterations, rng_mr);
            if (rv < 0) {
                prime_status = CCRSA_KEYGEN_PRIME_SEED_GENERATION_ERROR;
                break;
            }
            if (rv == 1) {
                prime_status=0; // Prime found
                break;
            }

            // 10) p=p+2.r1.r2
            c=ccn_add(n,CCZP_PRIME(p),CCZP_PRIME(p),CCZP_PRIME(r1r2x2));
        }
    }

    // Prepare exit
    if (prime_status!=0) {
        ccn_clear(n,CCZP_PRIME(p));
        ccn_clear(n,X);
    } else {
        CCZP_N(p) = ccn_n(n, cczp_prime(p));
        prime_status=cczp_init(p);
    }

    if (trace) {
        cc_assert((CCZP_N(p) * sizeof(cc_unit)) <= sizeof(trace->p));

        // XXX This was present but increments past the end of the array
        //
        // If the FIPS test fails, examine this carefully:
        //    trace = trace + trace->curr;
        cc_memcpy(trace->p, cczp_prime(p), CCZP_N(p) * sizeof(cc_unit));
    }

    // Clean working memory
    cc_clear(sizeof(R),R);
    cc_clear(sizeof(r1r2x2),r1r2x2);
    return prime_status;
}

// Generate {p, X} from rng and the size of the arbitrary primes to use
static int
ccrsa_generate_probable_prime(cc_size pbits, cczp_t p, cc_unit *X,
                              cc_size r1_bitsize, cc_size r2_bitsize,
                              const cc_size e_n, const cc_unit *e,
                              struct ccrng_state *rng,
                              struct ccrng_state *rng_mr,
                              struct ccrsa_fips186_trace *trace)
{
    int ret;
    cc_size n_alpha=ccn_nof(CC_MAX(r1_bitsize,r2_bitsize));
    cczp_decl_n(n_alpha, r1);
    cczp_decl_n(n_alpha, r2);
    CCZP_N(r1) = n_alpha;
    CCZP_N(r2) = n_alpha;
    cc_require((ret=cczp_generate_auxiliary_primes(r1_bitsize,r1,r2_bitsize,r2,rng,rng_mr,trace))==0,cleanup);
    cc_require((ret=ccrsa_generate_probable_prime_from_auxilary_primes(pbits, p, X,
                                                                       r1, r2, e_n, e, rng, rng_mr, trace))==0,cleanup);
cleanup:
    cc_clear(sizeof(r1),r1);
    cc_clear(sizeof(r2),r2);
    return ret;
}


// Fill out a ccrsa context given e, p, and q.  The "n" of the key context is expected
// to be set prior to this call.  p and q are cczps with no assumption as to their
// relative values.
// D is calculated per ANS 9.31 / FIPS 186 rules.
static int
ccrsa_crt_make_fips186_key(size_t nbits, ccrsa_full_ctx_t fk, cc_size e_n,
                           const cc_unit *e, cczp_t p, cczp_t q)
{
    int status = CCRSA_INVALID_INPUT;
    cc_size n = ccrsa_ctx_n(fk);
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);

    if (cczp_bitlen(p) + cczp_bitlen(q) > ccn_bitsof_n(n)) {
        return CCRSA_INVALID_INPUT;
    }

    ccn_setn(n, ccrsa_ctx_e(pubk), e_n, e);

    // Swap p and q, if necessary.
    if (ccn_cmpn(ccn_n(cczp_n(p), cczp_prime(p)), cczp_prime(p),
                 ccn_n(cczp_n(q), cczp_prime(q)), cczp_prime(q)) < 0) {
        CC_SWAP(p, q);
    }

    // Initialize zp before zq, otherwise ccrsa_ctx_private_zq()
    // won't point to the right place in memory.
    CCZP_N(ccrsa_ctx_private_zp(fk)) = cczp_n(p);
    CCZP_N(ccrsa_ctx_private_zq(fk)) = ccn_nof(cczp_bitlen(q));

    cczp_t zm = ccrsa_ctx_zm(pubk);
    cczp_t zp = ccrsa_ctx_private_zp(fk);
    cczp_t zq = ccrsa_ctx_private_zq(fk);

    ccn_set(cczp_n(p), CCZP_PRIME(zp), cczp_prime(p));
    ccn_set(cczp_n(q), CCZP_PRIME(zq), cczp_prime(q));

    if ((status = cczp_init(zp))) {
        return status;
    }

    if ((status = cczp_init(zq))) {
        return status;
    }

    status = ccrsa_crt_makekey(fk);
    if (status) {
        return status;
    }

    if (cczp_bitlen(zm) + 1 < nbits) {
        return CCRSA_INVALID_INPUT;
    }

    return CCERR_OK;
}

// This is pretty much the same interface as the "stock" RSA keygen except that
// two rng descriptors need to be provided.  You *can* call it with the same
// descriptor if you really want to.
// rng is used for the prime factors, rng_mr for Miller-Rabin.
// Note that "e" is expressed in pointer and length of bytes, not cc_units.

static int
ccrsa_generate_fips186_prime_factors(size_t nbits, cczp_t p, cczp_t q,
                                     cc_size e_n, const cc_unit *e,
                                     struct ccrng_state *rng,
                                     struct ccrng_state *rng_mr,
                                     struct ccrsa_fips186_trace *trace)
{
    if ((nbits < 512)) return CCRSA_KEY_ERROR;
    int ret;
    cc_size pbits = (nbits+1) >> 1, qbits = nbits - pbits;
    cc_size alpha=ccrsa_fips186_auxiliary_prime_length(pbits);
    size_t ebitlen = (ccn_bitlen(e_n,e));

    // Space to generate P and Q
    cc_size n_pq = ccn_nof(pbits);
    CCZP_N(p) = CCZP_N(q) = n_pq;

    // Auxiliary-Primes space to generate P & Q
    cc_unit xp[n_pq];
    cc_unit xq[n_pq];

    // e must be odd && e must verify 2^16 < e < 2^256
    cc_require_action( ((e[0] & 1)==1)
                      && (ebitlen>16)
                      && (ebitlen<256),
                      cleanup,ret=CCRSA_KEY_ERROR);

    // Generate P
    if (trace) {
        cc_clear(2 * sizeof(trace[0]), trace);
        trace[0].curr = trace[1].curr = 0;
    }

    cc_require((ret=ccrsa_generate_probable_prime(pbits, p, xp,
                                        alpha,  alpha, e_n, e, rng, rng_mr, trace))==0,cleanup);

    // Now, do the same for q. But repeat until q,p and Xp, Xq are
    // sufficiently far apart, and d is sufficiently large
    ret=CCRSA_KEYGEN_PQ_DELTA_ERROR;
    for (size_t i = 0; i < GENERATE_Q_MAX_RETRIES && ret == CCRSA_KEYGEN_PQ_DELTA_ERROR; i++) {
        // Generate Q - we're going to check for a large enough delta in various steps of this.
        if (trace) {
            trace[0].curr = trace[1].curr = 1;
        }

        cc_require((ret=ccrsa_generate_probable_prime(qbits, q, xq,
                                        alpha,  alpha, e_n, e, rng, rng_mr, trace))==0,cleanup);

        // If (|p-q|<= 2^(plen-100)) or If (|Xp-Xq|<= 2^(plen-100)) retry
        // (Make sure the seed P and Q were far enough apart)
        ret = cczp_check_delta_100bits(n_pq,cczp_prime(p),cczp_prime(q),xp,xq);
    }

cleanup:
    // Clear stack stuff
    ccn_clear(n_pq, xp);
    ccn_clear(n_pq, xq);
    return ret;
}
#endif //CC_DISABLE_RSAKEYGEN

//==============================================================================
//                              External functions
//==============================================================================

int
ccrsa_generate_fips186_key_trace(size_t nbits, ccrsa_full_ctx_t fk,
                                 size_t e_nbytes, const void *e_bytes,
                                 struct ccrng_state *rng, struct ccrng_state *rng_mr,
                                 struct ccrsa_fips186_trace *trace)
{
#if CC_DISABLE_RSAKEYGEN
    (void)nbits;    (void)fk;
    (void)e_nbytes; (void)e_bytes;
    (void)rng;      (void)rng_mr;
    (void)trace;
    return CCRSA_FIPS_KEYGEN_DISABLED;
#else
    // key generation takes a lot of stack space
    // therefore sanity check the key size
    if (nbits > CCRSA_KEYGEN_MAX_NBITS) {
        return CCRSA_INVALID_INPUT;
    }

    int ret;
    cc_size pqbits = (nbits >> 1);
    cc_size n = ccn_nof(nbits);
    cc_size n_pq = ccn_nof(pqbits)+1;
    ccrsa_ctx_n(fk) = n;
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    cczp_decl_n(n_pq, p);
    cczp_decl_n(n_pq, q);

    // Use the RSA key area to hold e as a ccn_unit.  Get e_n so we don't
    // need to roll on the full ccn_unit if we don't have to.
    if (ccn_read_uint(n, ccrsa_ctx_e(pubk), e_nbytes, e_bytes)) return CCRSA_KEY_ERROR;
    cc_size e_n = ccn_nof_size(e_nbytes);
    cc_unit *e = ccrsa_ctx_e(pubk);
    ccrsa_ctx_n(fk) = n;
    CCZP_N(p) = CCZP_N(q) = n_pq;

    // Prime factors
    cc_require((ret=ccrsa_generate_fips186_prime_factors(nbits, p, q, e_n, e,
                                                         rng, rng_mr, trace))==0,cleanup);

    // Generate the key
    cc_require((ret=ccrsa_crt_make_fips186_key(nbits, fk, e_n, e, p, q))==0,cleanup);

    // Check that the key works
    ret=(ccrsa_pairwise_consistency_check(fk,rng) ? 0 : CCRSA_KEYGEN_KEYGEN_CONSISTENCY_FAIL);

cleanup:
    cc_clear(sizeof(p),p);
    cc_clear(sizeof(q),q);
    return ret;
#endif
}

// This interface is primarily here for FIPS testing.  It creates an RSA key with the various "random" numbers
// supplied as parameters; calling the same routines as the "generate" function in the same sequence.  It
// doesn't test the suitability of the numbers since the FIPS KAT tests provide "good" numbers from which to
// make keys.
//
// In addition this routine passes back the RSA key components if space is passed in to return the values.
// This is done here so that the proper "P" and "Q" values are returned, since we'll always put the largest
// value into P to work with the remainder of the math in this package.  Keys constructed in this manner
// behave the same as keys with no ordering for P & Q.
//
int
ccrsa_make_fips186_key_trace(size_t nbits,
                   const cc_size e_n, const cc_unit *e,
                   const cc_size xp1Len, const cc_unit *xp1, const cc_size xp2Len, const cc_unit *xp2,
                   const cc_size xpLen, const cc_unit *xp,
                   const cc_size xq1Len, const cc_unit *xq1, const cc_size xq2Len, const cc_unit *xq2,
                   const cc_size xqLen, const cc_unit *xq,
                   ccrsa_full_ctx_t fk,
                   cc_size *np, cc_unit *r_p,
                   cc_size *nq, cc_unit *r_q,
                   cc_size *nm, cc_unit *r_m,
                   cc_size *nd, cc_unit *r_d,
                   struct ccrsa_fips186_trace *trace)
{
#if CC_DISABLE_RSAKEYGEN
    (void)nbits;
    (void)e_n;    (void)e;
    (void)xp1Len; (void)xp1; (void)xp2Len; (void)xp2;
    (void)xpLen;  (void)xp;
    (void)xq1Len; (void)xq1; (void)xq2Len; (void)xq2;
    (void)xqLen;  (void)xq;
    (void)fk;
    (void)np;     (void)r_p,
    (void)nq;     (void)r_q,
    (void)nm;     (void)r_m,
    (void)nd;     (void)r_d,
    (void)trace;
    return CCRSA_FIPS_KEYGEN_DISABLED;
#else
    // key generation takes a lot of stack space
    // therefore sanity check the key size
    if (nbits > CCRSA_KEYGEN_MAX_NBITS) {
        return CCRSA_INVALID_INPUT;
    }
    
    cc_size pqbits = (nbits >> 1);
    cc_size n = ccn_nof(nbits);
    cc_size n_pq = ccn_nof(pqbits)+1;
    ccrsa_pub_ctx_t pubk = ccrsa_ctx_public(fk);
    cczp_decl_n(n_pq, p);
    cczp_decl_n(n_pq, q);

    struct ccrng_rsafips_test_state rng;
    cc_size x1_bitsize;
    cc_size x2_bitsize;
    int ret;

    ccrsa_ctx_n(fk) = n;
    CCZP_N(p) = CCZP_N(q) = n_pq;
    cc_unit xpp[n_pq];
    cc_unit xqq[n_pq];

    struct ccrng_state *rng_mr = ccrng(&ret);
    cc_require(rng_mr != NULL, cleanup);

    // e must be > 2 and odd.
    cc_require_action((e[0] & 1) == 1 && ccn_bitlen(e_n, e) > 1, cleanup, ret=CCRSA_KEY_ERROR);

    // Generate P
    ccrng_rsafips_test_init(&rng,xp1Len,xp1,xp2Len,xp2,xpLen,xp);
    x1_bitsize = ccn_bitlen(xp1Len, xp1);
    x2_bitsize = ccn_bitlen(xp2Len, xp2);
    cc_require((ret=ccrsa_generate_probable_prime(pqbits, p, xpp,
                            x1_bitsize,  x2_bitsize, e_n, e, (struct ccrng_state *)&rng, rng_mr, trace))==0,cleanup);

    // Generate Q
    ccrng_rsafips_test_init(&rng,xq1Len,xq1,xq2Len,xq2,xqLen,xq);
    x1_bitsize = ccn_bitlen(xq1Len, xq1);
    x2_bitsize = ccn_bitlen(xq2Len, xq2);
    cc_require((ret=ccrsa_generate_probable_prime(pqbits, q, xqq,
                            x1_bitsize,  x2_bitsize, e_n, e, (struct ccrng_state *)&rng, rng_mr, trace))==0,cleanup);

    // Check delta between P and Q, XP, XQ
    ret = cczp_check_delta_100bits(n_pq, cczp_prime(p), cczp_prime(q), xpp, xqq);
    cc_require(ret == CCERR_OK, cleanup);

    // Return P&Q if requested now since we might assigned them in reverse in the CRT routine.
    if(np && r_p) { *np = cczp_n(p); ccn_set(*np, r_p, cczp_prime(p)); }
    if(nq && r_q) { *nq = cczp_n(q); ccn_set(*nq, r_q, cczp_prime(q)); }

    // Construct the key from p and q
    cc_require((ret=ccrsa_crt_make_fips186_key(nbits, fk, e_n, e, p, q))==0,cleanup);

    // Return m and d if requested.
    if(nm && r_m) { *nm = cczp_n(ccrsa_ctx_zm(pubk)); ccn_set(cczp_n(ccrsa_ctx_zm(pubk)), r_m, cczp_prime(ccrsa_ctx_zm(pubk))); }
    if(nd && r_d) { *nd = n; ccn_set(n, r_d, ccrsa_ctx_d(fk)); }

cleanup:
    cc_clear(sizeof(p),p);
    cc_clear(sizeof(q),q);
    return ret;
#endif // CC_DISABLE_RSAKEYGEN
}

int
ccrsa_generate_fips186_key(size_t nbits, ccrsa_full_ctx_t fk,
                           size_t e_nbytes, const void *e_bytes,
                           struct ccrng_state *rng, struct ccrng_state *rng_mr)
{
    return ccrsa_generate_fips186_key_trace(nbits, fk, e_nbytes, e_bytes, rng, rng_mr, NULL);
}

int
ccrsa_make_fips186_key(size_t nbits, const cc_size e_n, const cc_unit *e,
                       const cc_size xp1Len, const cc_unit *xp1,
                       const cc_size xp2Len, const cc_unit *xp2,
                       const cc_size xpLen, const cc_unit *xp,
                       const cc_size xq1Len, const cc_unit *xq1,
                       const cc_size xq2Len, const cc_unit *xq2,
                       const cc_size xqLen, const cc_unit *xq,
                       ccrsa_full_ctx_t fk,
                       cc_size *np, cc_unit *r_p,
                       cc_size *nq, cc_unit *r_q,
                       cc_size *nm, cc_unit *r_m,
                       cc_size *nd, cc_unit *r_d)
{
    return ccrsa_make_fips186_key_trace(nbits, e_n, e, xp1Len, xp1, xp2Len, xp2,
                                        xpLen, xp, xq1Len, xq1, xq2Len, xq2,
                                        xqLen, xq, fk, np, r_p, nq, r_q,
                                        nm, r_m, nd, r_d, NULL);
}

//================================ EOF =======================================//
