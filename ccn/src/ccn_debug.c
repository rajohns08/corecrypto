/* Copyright (c) (2010,2011,2012,2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccn.h>
#include "cc_debug.h"

#if 0
void ccn_print_r(cc_size count, const cc_unit *s, cc_size radix) {
    cc_size bits = (count * sizeof(cc_unit) * 8);
    uint8_t buf[bits];
    for (cc_size ix = 0; ix < count; ++ix) {
        cc_unit v = s[ix];

    }
}
#endif

void ccn_print(cc_size count, const cc_unit *s) {
    for (cc_size ix = count; ix--;) {
        cc_printf("%" CCPRIx_UNIT, s[ix]);
    }
}

void ccn_lprint(cc_size count, const char *label, const cc_unit *s) {
    cc_printf("%s { %zu, ",label, count);
    ccn_print(count, s);
    cc_printf("}\n");
}
