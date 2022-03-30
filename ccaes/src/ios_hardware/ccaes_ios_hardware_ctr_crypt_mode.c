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

const struct ccmode_ctr ccaes_ios_hardware_ctr_crypt_mode = {
    .size = sizeof(struct ccaes_hardware_aes_ctx),
    .block_size = 1,
    .ecb_block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_ios_hardware_ctr_init,
    .setctr = ccaes_ios_hardware_ctr_setctr,
    .ctr = ccaes_ios_hardware_ctr_crypt,
    .custom = NULL,
};

#endif /* CCAES_MUX */
