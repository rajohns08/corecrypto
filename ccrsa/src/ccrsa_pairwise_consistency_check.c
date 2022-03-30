/* Copyright (c) (2011,2012,2013,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

bool ccrsa_pairwise_consistency_check(const ccrsa_full_ctx_t full_key, struct ccrng_state *rng)
{
	ccrsa_full_ctx_t fk = full_key;
	ccrsa_pub_ctx_t pub_key = ccrsa_ctx_public(fk);
    size_t digest_size=CCSHA256_OUTPUT_SIZE;
	unsigned char fake_digest[digest_size];//vla
	cc_memset(fake_digest, 0xa, digest_size);
 	size_t n = ccrsa_ctx_n(full_key);
	size_t nbits = cczp_bitlen(ccrsa_ctx_zm(pub_key));

    // Verify the key is valid for signature / verification
    {
        uint8_t sig[(nbits+7)/8];//vla
        size_t siglen=sizeof(sig);
        bool ok;
        cc_require(0 == ccrsa_sign_pkcs1v15_blinded(rng,full_key, ccoid_sha256, digest_size, fake_digest,  &siglen, sig),errOut);

        cc_require((0 == ccrsa_verify_pkcs1v15(pub_key, ccoid_sha256, digest_size, fake_digest, siglen, sig, &ok) && ok),errOut);
    }

    // Verify the key is valid for encryption / decryption
    {
        cc_unit r[n], s[n], t[n];//vla
        ccn_seti(n, s, 42);

        ccn_set_bit(s, nbits-9, 1);

        // Encrypt
        cc_require(ccrsa_pub_crypt(pub_key, r, s)==0,errOut);

        // Make sure that the input does not match the output
        cc_require(0 != ccn_cmp(n, s, r),errOut);

        // Decrypt
        cc_require(ccrsa_priv_crypt_blinded(rng, fk, t, r)==0,errOut);

        // Make sure that output makes plain text
        cc_require(0 == ccn_cmp(n, t, s),errOut);
    }
	return true;

errOut:
    return false;
}
