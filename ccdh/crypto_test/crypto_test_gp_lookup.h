/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#ifndef crypto_test_gp_lookup_h
#define crypto_test_gp_lookup_h

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/*!
 * @function test_ccdh_gp_lookup
 *
 * @abstract Test the ccdh_gp_lookup function to ensure that it validates all approved DH groups that Apple supports.
 */
void ccdh_test_gp_lookup(void);
#endif /* crypto_test_gp_lookup_h */
