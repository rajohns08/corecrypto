/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#include <corecrypto/ccec.h>

ccec_const_cp_t ccec_curve_for_length_lookup(size_t keylen, ...)
{
    cc_size bitlen;
    cczp_const_t zp=NULL;

	va_list argp;
	va_start(argp, keylen);
    while((zp = va_arg(argp, cczp_const_t)) !=  NULL) {
        bitlen = cczp_bitlen(zp);
        // Match exact bitsize or rounded to multiple of 8.
        if ((bitlen == keylen) || (((bitlen+7) & ~(cc_size)7) == keylen)) {
            break;
        }
    }
	va_end(argp);
    return (ccec_const_cp_t)zp;
}
