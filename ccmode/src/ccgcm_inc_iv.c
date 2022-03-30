/* Copyright (c) (2016,2018,2019) Apple Inc. All rights reserved.
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

int ccgcm_inc_iv(CC_UNUSED const struct ccmode_gcm *mode, ccgcm_ctx *ctx, void *iv)
{
    uint8_t *Y0 = CCMODE_GCM_KEY_Y_0(ctx);
    
    cc_require(_CCMODE_GCM_KEY(ctx)->state == CCMODE_GCM_STATE_IV, errOut);
    cc_require(_CCMODE_GCM_KEY(ctx)->flags & CCGCM_FLAGS_INIT_WITH_IV, errOut);
    
    inc_uint(Y0 + 4, 8);
    cc_memcpy(iv, Y0, CCGCM_IV_NBYTES);
    cc_memcpy(CCMODE_GCM_KEY_Y(ctx), Y0, CCGCM_BLOCK_NBYTES);
    ccmode_gcm_update_pad(ctx);
    
    _CCMODE_GCM_KEY(ctx)->state = CCMODE_GCM_STATE_AAD;
    
    return 0;

errOut:
    return CCMODE_INVALID_CALL_SEQUENCE;
}
