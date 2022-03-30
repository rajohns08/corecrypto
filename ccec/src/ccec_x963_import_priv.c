/* Copyright (c) (2011,2012,2015,2016,2019) Apple Inc. All rights reserved.
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

size_t ccec_x963_import_priv_size(size_t in_len) {
    switch (in_len) {
        case 73: return 192;
        case 85: return 224;
        case 97: return 256;
        case 145: return 384;
        case 199: return 521;
        default: return 0;
    }
}

int ccec_x963_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key) {
    size_t step = (in_len - 1)/3;
    /* Type byte must be 4, 6 or 7 (with 6 and 7 being legacy). */
    if (in[0] != 4 && in[0] != 6 && in[0] != 7) return -1;
    ccec_ctx_init(cp, key);
    in++;
    if (ccn_read_uint(ccec_cp_n(cp), ccec_ctx_x(key), step, in)) return -1;
    in+=step;
    if (ccn_read_uint(ccec_cp_n(cp), ccec_ctx_y(key), step, in)) return -1;
    ccn_seti(ccec_cp_n(cp), ccec_ctx_z(key), 1);
    in+=step;
    if (ccn_read_uint(ccec_cp_n(cp), ccec_ctx_k(key), step, in)) return -1;
    return 0;
}
