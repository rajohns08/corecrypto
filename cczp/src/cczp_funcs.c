/* Copyright (c) (2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

#include "cczp_internal.h"

cczp_funcs_decl(cczp_default_funcs,
    cczp_mul_default_ws,
    cczp_sqr_default_ws,
    cczp_mod_default_ws,
    cczp_inv_default_ws,
    cczp_sqrt_default_ws,
    cczp_to_default_ws,
    cczp_from_default_ws,
    cczp_is_one_default_ws);
