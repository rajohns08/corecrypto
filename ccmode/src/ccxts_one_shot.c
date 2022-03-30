/* Copyright (c) (2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
//  Copyright (c) 2016 Apple Inc. All rights reserved.
//
//

#include <corecrypto/cc_macros.h>
#include "ccmode_internal.h"

#include "corecrypto/fipspost_trace.h"

int ccxts_one_shot(const struct ccmode_xts *mode,
                   size_t key_nbytes, const void *data_key,
                   const void *tweak_key, const void *iv,
                   size_t nblocks, const void *in, void *out)
{
    FIPSPOST_TRACE_EVENT;

    int rc;
    ccxts_ctx_decl(mode->size, ctx);
    ccxts_tweak_decl(mode->tweak_size, tweak);

    if ((rc = ccxts_init(mode, ctx, key_nbytes, data_key, tweak_key))) {
        goto cleanup;
    }

    if ((rc = mode->set_tweak(ctx, tweak, iv))) {
        goto cleanup;
    }

    if (mode->xts(ctx, tweak, nblocks, in, out) == NULL) {
        rc = CCERR_PARAMETER;
    }

cleanup:
    ccxts_ctx_clear(mode->size, ctx);
    ccxts_tweak_clear(mode->tweak_size, tweak);

    return rc;
}
