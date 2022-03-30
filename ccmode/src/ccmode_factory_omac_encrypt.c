/* Copyright (c) (2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccmode_internal.h"

void ccmode_factory_omac_encrypt(struct ccmode_omac *omac,
                                 const struct ccmode_ecb *ecb) {
    struct ccmode_omac omac_encrypt = CCMODE_FACTORY_OMAC_ENCRYPT(ecb);
    *omac = omac_encrypt;
}
