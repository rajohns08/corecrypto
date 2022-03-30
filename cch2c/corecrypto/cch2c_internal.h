/* Copyright (c) (2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCH2C_INTERNAL_H_
#define _CORECRYPTO_CCH2C_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccec.h>
#include <corecrypto/cch2c.h>

#define CCH2C_MAX_DATA_NBYTES (255)

struct cch2c_info {
    const char *name;
    unsigned l;
    unsigned z;
    ccec_const_cp_t (*CC_SPTR(cch2c_info, curve_params))(void);
    const struct ccdigest_info *(*CC_SPTR(cch2c_info, digest_info))(void);
    int (*CC_SPTR(cch2c_info, hash_to_base))(const struct cch2c_info *info,
                        size_t dst_nbytes, const void *dst,
                        size_t data_nbytes, const void *data,
                        uint8_t n,
                        cc_unit *u);
    int (*CC_SPTR(cch2c_info, map_to_curve))(const struct cch2c_info *info,
                        cc_unit *u,
                        ccec_pub_ctx_t q);
    int (*CC_SPTR(cch2c_info, clear_cofactor))(const struct cch2c_info *info,
                          ccec_pub_ctx_t q);
    int (*CC_SPTR(cch2c_info, encode_to_curve))(const struct cch2c_info *info,
                           size_t dst_nbytes, const void *dst,
                           size_t data_nbytes, const void *data,
                           ccec_pub_ctx_t q);
};

#endif /* _CORECRYPTO_CCH2C_INTERNAL_H_ */
