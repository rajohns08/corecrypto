/* Copyright (c) (2016,2019) Apple Inc. All rights reserved.
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

int ccgcm_init_with_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
                       size_t key_nbytes, const void *key,
                       const void *iv)
{
    int rc;
    
    rc = ccgcm_init(mode, ctx, key_nbytes, key);
    if (rc == 0) rc = ccgcm_set_iv(mode, ctx, CCGCM_IV_NBYTES, iv);
    if (rc == 0) _CCMODE_GCM_KEY(ctx)->flags |= CCGCM_FLAGS_INIT_WITH_IV;
    return rc;
}
