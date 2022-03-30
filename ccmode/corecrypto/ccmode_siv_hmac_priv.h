/* Copyright (c) (2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
//  Created by Apple on 12/10/18.
//

#ifndef ccmode_siv_hmac_priv_h
#define ccmode_siv_hmac_priv_h

#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include <corecrypto/ccmode_siv_hmac.h>
#include <corecrypto/cchmac.h>

// Provide current maximum sizes for block and state in order to prevent the need for dynamic
// allocation of context or many macro accessor functions.
#define MAX_DIGEST_BLOCK_SIZE 128
#define MAX_DIGEST_STATE_SIZE 64

// Maximum size for the key is 512
#define CCSIV_HMAC_MAX_KEY_BYTESIZE   512/8

struct _ccmode_siv_hmac_ctx {
    const struct ccmode_siv_hmac *siv_hmac;
    size_t key_bytesize;
    size_t tag_length;
    cc_unit state;
    cc_unit mac_key[ccn_nof_size(CCSIV_HMAC_MAX_KEY_BYTESIZE/2)]; // hmac key
    cc_unit ctr_key[ccn_nof_size(CCSIV_HMAC_MAX_KEY_BYTESIZE/2)]; // ctr key
    cc_ctx_decl_field(struct cchmac_ctx, cchmac_ctx_size(MAX_DIGEST_BLOCK_SIZE, MAX_DIGEST_STATE_SIZE), hmac_ctx);
};


#endif /* ccmode_siv_hmac_priv_h */
