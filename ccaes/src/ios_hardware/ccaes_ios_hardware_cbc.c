/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>

#if CCAES_MUX
#include "ccaes_ios_hardware.h"
#include "cc_debug.h"

int
ccaes_ios_hardware_cbc_init(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *key,
                            size_t rawkey_len, const void *rawkey)
{
    ccaes_hardware_aes_ctx_t ctx = (ccaes_hardware_aes_ctx_t) key;
    return ccaes_ios_hardware_common_init(CCAES_HW_CBC, ctx,rawkey_len,rawkey);
}

#endif /* CCAES_MUX */

