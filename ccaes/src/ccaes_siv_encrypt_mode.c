/* Copyright (c) (2015,2017-2020) Apple Inc. All rights reserved.
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
#include "ccmode_siv_internal.h"

static CC_READ_ONLY_LATE(struct ccmode_siv) siv_encrypt;

const struct ccmode_siv *ccaes_siv_encrypt_mode(void)
{
    if (!CC_CACHE_DESCRIPTORS || NULL == siv_encrypt.init) {
        ccmode_factory_siv_encrypt(&siv_encrypt, ccaes_cbc_encrypt_mode(), ccaes_ctr_crypt_mode());
    }
    return &siv_encrypt;
}
