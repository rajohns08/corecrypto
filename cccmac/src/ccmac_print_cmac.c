/* Copyright (c) (2013,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cccmac_internal.h"
#include "cc_debug.h"

static void pr16(uint8_t *v) {
    for(int i = 0; i < 16; i++) cc_printf("%02x", v[i]);
    cc_printf("\n");
}

void ccmac_print_cmac(cccmac_ctx_t hc) {
    struct cccmac_ctx *hdr = hc;
    cc_printf("=============CMAC Structure BEGIN==============\n");
    
    cc_printf("K1 Subkey: ");
    pr16(hdr->k1);
    
    cc_printf("K2 Subkey: ");
    pr16(hdr->k2);

    cc_printf("IV: ");
    pr16((uint8_t*)cccmac_mode_iv(cccmac_cbc(hc), hc));

    cc_printf("=============CMAC Structure END==============\n");
}
