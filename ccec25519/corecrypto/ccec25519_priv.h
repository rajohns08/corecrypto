/* Copyright (c) (2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCEC25519_PRIV_H_
#define _CORECRYPTO_CCEC25519_PRIV_H_

#include <corecrypto/ccec25519.h>

/*!
 @function    cced25519_make_pub
 @abstract    Creates a montgomery curve 25519 public key from a private key.

 @param      di    A valid descriptor for a 512 bit hash function for the platform
 @param      pk    Output 32-byte public key.
 @param      sk    Input 32-byte secret key.

 @discussion Not safe for general use. For internal use only (eg. FIPS CAVS):
     - Public key must be stored along side the private key, private key should not
     be stored alone.
     - It may be unsafe to use a same private key with different digests
 */

int cced25519_make_pub(const struct ccdigest_info *di, ccec25519pubkey pk, const ccec25519secretkey sk);

#endif /* _CORECRYPTO_CCEC25519_PRIV_H_ */
