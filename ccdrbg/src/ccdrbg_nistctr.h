/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDRBG_NISTCTR_H_
#define _CORECRYPTO_CCDRBG_NISTCTR_H_

/*!
    @header     ccdrbg_nistctr.h
    @abstract   Interface to a NIST SP 800-90 AES-CTR DRBG
    @discussion This is an implementation of the NIST SP 800-90 AES-CTR DRBG
 */

#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccmode.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NO_OF_INTS(size)              ((size)/sizeof(uint32_t))
    
#define CCADRBG_KEYLEN(drbg)          ((drbg)->keylen)
#define CCADRBG_KEYLEN_INTS(drbg)     NO_OF_INTS(CCADRBG_KEYLEN(drbg))
    
#define CCADRBG_CTRLEN                8

#define CCADRBG_BLOCKSIZE(drbg)       ((drbg)->ctr_info->ecb_block_size)
#define CCADRBG_BLOCKSIZE_INTS(drbg)  NO_OF_INTS(CCADRBG_BLOCKSIZE(drbg))
    
#define CCADRBG_OUTLEN(drbg)          CCADRBG_BLOCKSIZE(drbg)
#define CCADRBG_OUTLEN_INTS(drbg)	  NO_OF_INTS(CCADRBG_OUTLEN(drbg))

#define CCADRBG_SEEDLEN(drbg)         (CCADRBG_KEYLEN(drbg)+CCADRBG_OUTLEN(drbg))
#define CCADRBG_SEEDLEN_INTS(drbg)    NO_OF_INTS(CCADRBG_SEEDLEN(drbg))
   
#define CCADRBG_TEMPLEN_BLOCKS(drbg)  cc_ceiling(CCADRBG_SEEDLEN(drbg)+CCADRBG_OUTLEN(drbg),CCADRBG_OUTLEN(drbg))
#define CCADRBG_TEMPLEN(drbg)         CCADRBG_TEMPLEN_BLOCKS(drbg)*CCADRBG_OUTLEN(drbg)
#define CCADRBG_TEMPLEN_INTS(drbg)	  NO_OF_INTS(CCADRBG_TEMPLEN(drbg))
    
//limits
#define CCADRBG_MAX_KEYBITS		256
#define CCADRBG_MAX_KEYLEN	(CCADRBG_MAX_KEYBITS / 8)
    
//required memory size
#define CCDRBG_NISTCTR_SIZE(ctr_info, keylen)    \
    ((ctr_info)->ecb_block_size +                    \
    (((keylen)+(ctr_info)->ecb_block_size*2-1)/(ctr_info)->ecb_block_size)*(ctr_info)->ecb_block_size +            \
    (ctr_info)->ecb_block_size +                     \
    (2*(ctr_info)->size))

typedef struct {
	uint8_t *S; /*[CCADRBG_OUTLEN_BYTES]; */
	size_t index;
} _CCADRBG_BCC;

struct ccdrbg_nistctr_state {
    const struct ccmode_ctr *ctr_info;
    size_t   keylen;
	uint8_t			*encryptedIV; /* [CCADRBG_SEEDLEN / CCADRBG_OUTLEN][CCADRBG_OUTLEN_BYTES]; */
	uint8_t		*V;           /* [CCADRBG_OUTLEN]; */
    ccctr_ctx       *key;
    ccctr_ctx       *df_key;
	_CCADRBG_BCC	bcc;
	uint64_t		reseed_counter; //fits max NIST requirement of 2^48
	int             strictFIPS;
    int             use_df;
};

#ifdef __cplusplus
}
#endif
#endif /*  _CORECRYPTO_CCDRBG_NISTCTR_H_ */
