/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "cc_debug.h"
#include "ccec_internal.h"

void ccec_alprint(ccec_const_cp_t cp, const char *label, ccec_const_affine_point_t s) {
    cc_printf("%s { x -> ", label);
    ccn_print(ccec_cp_n(cp), ccec_const_point_x(s, cp));
    cc_printf(", y -> ");
    ccn_print(ccec_cp_n(cp), ccec_const_point_y(s, cp));
    cc_printf("}\n");
}

void ccec_plprint(ccec_const_cp_t cp, const char *label, ccec_const_projective_point_t s) {
    cc_printf("%s { x -> ", label);
    ccn_print(ccec_cp_n(cp), ccec_const_point_x(s, cp));
    cc_printf(", y -> ");
    ccn_print(ccec_cp_n(cp), ccec_const_point_y(s, cp));
    cc_printf(", z -> ");
    ccn_print(ccec_cp_n(cp), ccec_const_point_z(s, cp));
    cc_printf("}\n");
}

void ccec_print_full_key(const char *label, ccec_full_ctx_t key)
{
    cc_printf("full key %s { \n", label);
    ccec_plprint(ccec_ctx_cp(key), "pubkey:", ccec_ctx_point(key));
    cc_printf("priv: {");
    ccn_print(ccec_cp_n(ccec_ctx_cp(key)), ccec_ctx_k(key));
    cc_printf("}\n");
}

void ccec_print_public_key(const char *label, ccec_pub_ctx_t key)
{
    cc_printf("public key ");
    ccec_plprint(ccec_ctx_cp(key), label, ccec_ctx_point(key));
}


void ccec_print_sig(const char *label, size_t count, const uint8_t *s) {
    cc_printf("%s { %zu, ",label, count);
    for (size_t ix = count; ix--;) {
        cc_printf("%.02x", s[ix]);
    }
    cc_printf("\n");
}
