/* Copyright (c) (2010,2011,2012,2015,2016,2019,2020) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>

size_t ccec_x963_import_pub_size(size_t in_len) {
    switch (in_len) {
        case 49: return 192;
        case 57: return 224;
        case 65: return 256;
        case 97: return 384;
        case 133: return 521;
        default: return 0;
    }
}

int ccec_x963_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key)
{
    /* Type byte must be 0(unit element),2 or 3 (Compressed Point)4, 6 or 7 (with 6 and 7 being legacy). */
    switch(in[0]){
        case 0:
        case 2:
        case 3:
            return ccec_compressed_x962_import_pub(cp, in_len, in, key);
        case 4:
        case 6:
        case 7:
            return ccec_raw_import_pub(cp, in_len-1, in+1, key);
        default:
            return CCERR_PARAMETER;
    }
    return CCERR_PARAMETER;
}

