/* Copyright (c) (2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"

bool ccec_validate_pub(ccec_pub_ctx_t key) {
    ccec_const_cp_t cp = ccec_ctx_cp(key);
    ccec_point_decl_cp(cp, Q);
    return (ccec_validate_pub_and_projectify(cp, Q,
                                         (ccec_const_affine_point_t)ccec_ctx_point(key),
                                         NULL) == 0)?true:false;
}
