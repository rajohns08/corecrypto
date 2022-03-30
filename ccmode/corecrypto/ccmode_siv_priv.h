/* Copyright (c) (2015,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMODE_SIV_PRIV_H_
#define _CORECRYPTO_CCMODE_SIV_PRIV_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccmode_siv.h>

#include <corecrypto/cccmac.h>

// Maximum size for the key is 512
#define CCSIV_MAX_BLOCK_BYTESIZE 128/8

// Maximum size for the key is 512
#define CCSIV_MAX_KEY_BYTESIZE   512/8

struct _ccmode_siv_ctx {
    const struct ccmode_siv *siv;
    size_t  key_bytesize;
    cc_unit state;
    cc_unit k1[ccn_nof_size(CCSIV_MAX_KEY_BYTESIZE/2)]; // cmac key
    cc_unit k2[ccn_nof_size(CCSIV_MAX_KEY_BYTESIZE/2)]; // ctr key
    cc_unit block[ccn_nof_size(CCSIV_MAX_BLOCK_BYTESIZE)];
};

/*!
  @function ccmode_factory_siv_encrypt
  @abstract Do not call this function.
*/
void ccmode_factory_siv_encrypt(struct ccmode_siv *siv,
                                const struct ccmode_cbc *cbc,
                                const struct ccmode_ctr *ctr);

/*!
  @function ccmode_factory_siv_decrypt
  @abstract Do not call this function.
 */
void ccmode_factory_siv_decrypt(struct ccmode_siv *siv,
                                const struct ccmode_cbc *cbc,
                                const struct ccmode_ctr *ctr);

#endif /* _CORECRYPTO_CCMODE_SIV_PRIV_H_ */
