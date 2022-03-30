/* Copyright (c) (2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"

#include "corecrypto/fipspost_trace.h"

int ccgcm_one_shot(const struct ccmode_gcm *mode,
                             size_t key_nbytes, const void *key,
                             size_t iv_nbytes, const void *iv,
                             size_t adata_nbytes, const void *adata,
                             size_t nbytes, const void *in, void *out,
                             size_t tag_nbytes, void *tag)
{
    FIPSPOST_TRACE_EVENT;

    int rc = 0;

    ccgcm_ctx_decl(mode->size, ctx);
    rc=ccgcm_init (mode, ctx, key_nbytes   ,key); cc_require(rc==0, errOut);
    rc=ccgcm_set_iv(mode, ctx, iv_nbytes ,iv); cc_require(rc==0, errOut);
    rc=ccgcm_aad     (mode, ctx, adata_nbytes ,adata); cc_require(rc==0, errOut);
    rc=ccgcm_update  (mode, ctx, nbytes    , in, out); cc_require(rc==0, errOut);
    rc=ccgcm_finalize(mode, ctx, tag_nbytes   ,tag); cc_require(rc==0, errOut);

errOut:
    ccgcm_ctx_clear(mode->size, ctx);
    return rc;

}


//ccgcm_one_shot_legacy() is created because in the previous implementation of aes-gcm
//set_iv() could be skipped.
//In the new version of aes-gcm set_iv() cannot be skipped and IV length cannot
//be zero, as specified in FIPS.
//do not call ccgcm_one_shot_legacy() in any new application
int ccgcm_set_iv_legacy(const struct ccmode_gcm *mode, ccgcm_ctx *key, size_t iv_nbytes, const void *iv)
{
    int rc = -1;

    if(iv_nbytes == 0 || iv == NULL){
        /* must be in IV state */
        cc_require(_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_IV, errOut); /* CRYPT_INVALID_ARG */
        
        // this is the net effect of setting IV to the empty string
        cc_clear(CCGCM_BLOCK_NBYTES, CCMODE_GCM_KEY_Y(key));
        ccmode_gcm_update_pad(key);
        cc_clear(CCGCM_BLOCK_NBYTES, CCMODE_GCM_KEY_Y_0(key));
        
        _CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_AAD;
        rc = 0;
    }else
        rc = ccgcm_set_iv(mode, key, iv_nbytes, iv);

errOut:
    return rc;
}

int ccgcm_one_shot_legacy(const struct ccmode_gcm *mode,
                              size_t key_nbytes, const void *key,
                              size_t iv_nbytes, const void *iv,
                              size_t adata_nbytes, const void *adata,
                              size_t nbytes, const void *in, void *out,
                              size_t tag_nbytes, void *tag)
{
    int rc = 0;

    ccgcm_ctx_decl(mode->size, ctx);
    rc=ccgcm_init (mode, ctx, key_nbytes   ,key); cc_require(rc==0, errOut);
    rc=ccgcm_set_iv_legacy (mode, ctx, iv_nbytes ,iv); cc_require(rc==0, errOut);
    rc=ccgcm_aad     (mode, ctx, adata_nbytes ,adata); cc_require(rc==0, errOut);
    rc=ccgcm_update  (mode, ctx, nbytes    , in, out); cc_require(rc==0, errOut);
    rc=ccgcm_finalize(mode, ctx, tag_nbytes   ,tag);  cc_require(rc==0, errOut);

errOut:
    ccgcm_ctx_clear(mode->size, ctx);
    return rc;
}

