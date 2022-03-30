/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/ccspake.h>
#include "ccspake_priv.h"

/*
 Points for common groups as defined by the CFRG spec.

 <https://tools.ietf.org/html/draft-irtf-cfrg-spake2-06#section-4>
 */

/* clang-format off */
static ccspake_cp_decl(384) ccspake_cp384 =
{
    .mx = {
        CCN384_C(0f,f0,89,5a,e5,eb,f6,18,70,80,a8,2d,82,b4,2e,27,65,e3,b2,f8,74,9c,7e,05,eb,a3,66,43,4b,36,3d,3d,c3,6f,15,31,47,39,07,4d,2e,b8,61,3f,ce,ec,28,53)
    },
    .my = {
        CCN384_C(97,59,2c,55,79,7c,dd,77,c0,71,5c,b7,df,21,50,22,0a,01,19,86,64,86,af,42,34,f3,90,aa,d1,f6,ad,dd,e5,93,09,09,ad,c6,7a,1f,c0,c9,9b,a3,d5,2d,c5,dd)
    },

    .nx = {
        CCN384_C(c7,2c,f2,e3,90,85,3a,1c,1c,4a,d8,16,a6,2f,d1,58,24,f5,60,78,91,8f,43,f9,22,ca,21,51,8f,9c,54,3b,b2,52,c5,49,02,14,cf,9a,a3,f0,ba,ab,4b,66,5c,10)
    },
    .ny = {
        CCN384_C(c3,8b,7d,7f,4e,7f,32,03,17,cd,71,73,15,a7,97,c7,e0,29,33,ae,f6,8b,36,4c,bf,84,eb,c6,19,be,db,e2,1f,f5,c6,9e,a0,f1,fe,d5,d7,e3,20,04,18,07,3f,40)
    },
};
/* clang-format on */

ccspake_const_cp_t ccspake_cp_384()
{
    ccspake_cp384.cp = ccec_cp_384();
    return (ccspake_const_cp_t)&ccspake_cp384;
}
