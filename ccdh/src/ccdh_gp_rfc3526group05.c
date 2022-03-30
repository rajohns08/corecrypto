/* Copyright (c) (2011,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccdh_gp.h>

static ccdh_gp_decl_static(1536) _ccdh_gp_rfc3526group05 =
{
    .hp = {
        .n = ccn_nof(1536),
        .bitlen = 1536,
        .funcs = CCZP_FUNCS_DEFAULT
    },
    .p = {
        /* prime */
        CCN64_C(ff,ff,ff,ff,ff,ff,ff,ff),CCN64_C(f1,74,6c,08,ca,23,73,27),
        CCN64_C(67,0c,35,4e,4a,bc,98,04),CCN64_C(9e,d5,29,07,70,96,96,6d),
        CCN64_C(1c,62,f3,56,20,85,52,bb),CCN64_C(83,65,5d,23,dc,a3,ad,96),
        CCN64_C(69,16,3f,a8,fd,24,cf,5f),CCN64_C(98,da,48,36,1c,55,d3,9a),
        CCN64_C(c2,00,7c,b8,a1,63,bf,05),CCN64_C(49,28,66,51,ec,e4,5b,3d),
        CCN64_C(ae,9f,24,11,7c,4b,1f,e6),CCN64_C(ee,38,6b,fb,5a,89,9f,a5),
        CCN64_C(0b,ff,5c,b6,f4,06,b7,ed),CCN64_C(f4,4c,42,e9,a6,37,ed,6b),
        CCN64_C(e4,85,b5,76,62,5e,7e,c6),CCN64_C(4f,e1,35,6d,6d,51,c2,45),
        CCN64_C(30,2b,0a,6d,f2,5f,14,37),CCN64_C(ef,95,19,b3,cd,3a,43,1b),
        CCN64_C(51,4a,08,79,8e,34,04,dd),CCN64_C(02,0b,be,a6,3b,13,9b,22),
        CCN64_C(29,02,4e,08,8a,67,cc,74),CCN64_C(c4,c6,62,8b,80,dc,1c,d1),
        CCN64_C(c9,0f,da,a2,21,68,c2,34),CCN64_C(ff,ff,ff,ff,ff,ff,ff,ff)
    },
    .recip = {
        /* recip */
        CCN64_C(f1,15,d2,7d,32,c6,95,e0),CCN64_C(bf,23,31,e9,c9,42,97,73),
        CCN64_C(2b,ce,3e,51,90,b8,91,ab),CCN64_C(11,15,f0,24,a6,e9,76,bd),
        CCN64_C(f5,e4,f0,7a,b8,b2,86,e4),CCN64_C(e7,50,2d,2f,5f,6a,7b,65),
        CCN64_C(6f,c7,fa,a8,b2,bd,ca,9b),CCN64_C(a8,8d,0d,2f,78,a7,7a,8a),
        CCN64_C(c4,b8,73,9c,be,a0,38,aa),CCN64_C(19,fc,25,8d,79,bc,21,7a),
        CCN64_C(8e,db,2d,e1,89,93,41,37),CCN64_C(7a,a5,cc,40,e0,20,35,58),
        CCN64_C(86,c5,81,76,47,b0,88,d1),CCN64_C(5c,0e,13,d1,68,04,9b,bc),
        CCN64_C(54,75,db,33,db,7b,83,bb),CCN64_C(c8,c9,d3,d9,22,ee,ce,9a),
        CCN64_C(d4,80,2f,b8,d3,29,55,0d),CCN64_C(96,89,fc,09,03,a8,01,e3),
        CCN64_C(b1,f9,fb,b5,bf,16,fb,e7),CCN64_C(64,cf,ca,c5,f1,87,2e,51),
        CCN64_C(a6,db,0f,58,84,48,b6,11),CCN64_C(47,03,ce,7e,2e,81,51,97),
        CCN64_C(36,f0,25,5d,de,97,3d,cb),CCN64_C(00,00,00,00,00,00,00,00),
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
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN64_C(00,00,00,00,00,00,00,00),
        CCN64_C(00,00,00,00,00,00,00,00),CCN8_C(00)
    },
    .l = 240,
};

ccdh_const_gp_t ccdh_gp_rfc3526group05(void)
{
    return (ccdh_const_gp_t)&_ccdh_gp_rfc3526group05;
}
