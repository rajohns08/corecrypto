/* Copyright (c) (2012,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* Autogenerated file - Use scheme ccdh_gen_gp to regenerate */
#include "ccdh_internal.h"
#include <corecrypto/ccsrp_gp.h>

static ccdh_gp_decl_static(1024) _ccsrp_gp_rfc5054_1024 =
{
    .hp = {
        .n = ccn_nof(1024),
        .bitlen = 1024,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .p = {
        /* prime */
        CCN64_C(9f,c6,1d,2f,c0,eb,06,e3),CCN64_C(fd,51,38,fe,83,76,43,5b),
        CCN64_C(2f,d4,cb,f4,97,6e,aa,9a),CCN64_C(68,ed,bc,3c,05,72,6c,c0),
        CCN64_C(c5,29,f5,66,66,0e,57,ec),CCN64_C(82,55,9b,29,7b,cf,18,85),
        CCN64_C(ce,8e,f4,ad,69,b1,5d,49),CCN64_C(5d,c7,d7,b4,61,54,d6,b6),
        CCN64_C(8e,49,5c,1d,60,89,da,d1),CCN64_C(e0,d5,d8,e2,50,b9,8b,e4),
        CCN64_C(38,3b,48,13,d6,92,c6,e0),CCN64_C(d6,74,df,74,96,ea,81,d3),
        CCN64_C(9e,a2,31,4c,9c,25,65,76),CCN64_C(60,72,61,87,75,ff,3c,0b),
        CCN64_C(9c,33,f8,0a,fa,8f,c5,e8),CCN64_C(ee,af,0a,b9,ad,b3,8d,d6)
    },
    .recip = {
        /* recip */
        CCN64_C(fb,9a,6d,ce,50,c7,02,b2),CCN64_C(62,82,f7,1f,43,4b,2d,33),
        CCN64_C(19,06,35,15,e2,55,53,64),CCN64_C(91,c3,be,7b,f0,b0,a1,ec),
        CCN64_C(fe,e7,e9,24,72,57,7c,14),CCN64_C(8e,99,ff,fb,1c,ed,29,e1),
        CCN64_C(ab,2a,0e,6e,52,63,81,e1),CCN64_C(31,b2,61,36,ff,62,2e,ed),
        CCN64_C(22,ef,4c,82,07,d4,99,f7),CCN64_C(ca,99,c7,b1,b9,56,b8,19),
        CCN64_C(dd,a3,bf,2a,7f,ff,38,31),CCN64_C(23,52,f4,8b,e2,b9,87,26),
        CCN64_C(7f,c5,06,dc,cb,06,85,8e),CCN64_C(45,28,08,a3,53,ec,97,28),
        CCN64_C(e8,64,2c,dd,3a,c1,f2,d3),CCN64_C(12,92,90,76,b7,ea,13,1e),
        CCN8_C(01)
    },
    .g = {
        /* g */
        CCN64_C(00,00,00,00,00,00,00,02),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN8_C(00)
    },
    .q = {
        /* q */
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN8_C(00)
    },
    .l = 160,
};

ccdh_const_gp_t ccsrp_gp_rfc5054_1024(void)
{
    return (ccdh_const_gp_t)&_ccsrp_gp_rfc5054_1024;
}
