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

#ifndef _CORECRYPTO_CCAES_IOS_MUX_CTR_H_
#define _CORECRYPTO_CCAES_IOS_MUX_CTR_H_

#include <corecrypto/cc_config.h>

#if CCAES_MUX

#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_priv.h>
#include "ccaes_ios_hardware.h"

#define AES_CTR_SWHW_CUTOVER (16384 / CCAES_BLOCK_SIZE)

#endif /* CCAES_MUX */

#endif /* _CORECRYPTO_CCAES_IOS_MUX_CTR_H_ */
