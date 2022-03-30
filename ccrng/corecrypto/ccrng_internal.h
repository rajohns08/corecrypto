/* Copyright (c) (2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCRNG_INTERNAL_H_
#define _CORECRYPTO_CCRNG_INTERNAL_H_

#include <corecrypto/ccrng.h>
#if CC_KERNEL
 #include <sys/types.h>
#else
 #include <stddef.h>
#endif

int cc_get_entropy(size_t entropy_size, void *entropy);


#endif /* _CORECRYPTO_CCRNG_INTERNAL_H_ */
