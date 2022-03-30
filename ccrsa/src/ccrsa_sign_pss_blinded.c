/* Copyright (c) (2015,2016,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccrsa_internal.h"

int ccrsa_sign_pss_blinded(struct ccrng_state *blinding_rng,
                   const ccrsa_full_ctx_t key,
                   const struct ccdigest_info* hashAlgorithm,
                   const struct ccdigest_info* MgfHashAlgorithm,
                   size_t saltSize,struct ccrng_state *rng,
                   size_t hSize, const uint8_t *mHash,
                   size_t *sigSize, uint8_t *sig)
{
    const cc_size modBits =ccn_bitlen(ccrsa_ctx_n(key), ccrsa_ctx_m(key));
    const cc_size modBytes = cc_ceiling(modBits, 8);
    const cc_size emBits = modBits-1; //as defined in §8.1.1 of PKCS1-V2
    const cc_size emLen = cc_ceiling(emBits, 8); //In theory, emLen can be one byte less than modBytes
    int rc=0;
    
    //two FIPS 186-4 imposed conditions
    if(modBits==1024 && hashAlgorithm->output_size==512 && saltSize>hSize-2) return CCRSA_INVALID_INPUT;
    if(saltSize>hSize) return CCRSA_INVALID_INPUT;
    
    //input validation checks
    if(*sigSize<modBytes) return CCRSA_INVALID_INPUT;
    if(hSize!= hashAlgorithm->output_size)return CCRSA_INVALID_INPUT;
    
    *sigSize=modBytes;
    
    uint8_t salt[saltSize];//vla
    int rc_rng;
    if (saltSize>0) {
        rc_rng=ccrng_generate(rng, saltSize, salt); //continue, although we know there is an error
    } else {
        rc_rng=0; // no error
    }
    
    const cc_size modWords=ccrsa_ctx_n(key);
    //max length of EM in bytes is emLen. But since we pass EM to RSA exponentiation routine, we must have the length in modWords. In 64 bit machine, EM can be 7 bytes longer than what is needed in theory
    cc_unit EM[modWords]; //vla
    
    cc_assert(modWords*sizeof(cc_unit)>=emLen);
    EM[0]=EM[modWords-1] = 0; //in case emLen<modWord* sizeof(cc_unit), zeroize
    const size_t ofs = modWords*sizeof(cc_unit)-emLen;
    cc_assert(ofs<=sizeof(cc_unit)); //EM can only be one cc_unit larger
    rc|=ccrsa_emsa_pss_encode(hashAlgorithm, MgfHashAlgorithm, saltSize, salt, hSize, mHash, emBits, (uint8_t *)EM+ofs);     //let it continue, although we know there might be an error
    ccn_swap(modWords, EM);

    rc|=ccrsa_priv_crypt_blinded(blinding_rng,key, EM, EM);
    
    /* we need to write leading zeroes if necessary */
    if(rc==0 && rc_rng==0)
        ccn_write_uint_padded_ct(modWords,  EM, *sigSize, sig);
    else{
        ccn_clear(modWords, EM); //ccrsa_emsa_pss_encode() directly writes to EM. EM is cleared incase there is an error
        if(rc_rng!=0)
            rc = rc_rng;
    }
    
    return rc;
}


