/* Copyright (c) (2013,2015,2016,2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_internal.h>
#include "ccaes_vng_ccm.h"

static CC_READ_ONLY_LATE(struct ccmode_ccm) ccm_decrypt;

const struct ccmode_ccm *ccaes_ccm_decrypt_mode(void)
{
    if (!CC_CACHE_DESCRIPTORS || NULL == ccm_decrypt.init) {
#if CCMODE_CCM_VNG_SPEEDUP
        ccaes_vng_ccm_decrypt_mode_setup(&ccm_decrypt);
#else
        ccmode_factory_ccm_decrypt(&ccm_decrypt, ccaes_ecb_encrypt_mode());
#endif
    }
    return &ccm_decrypt;
}
