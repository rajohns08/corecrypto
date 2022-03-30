/* Copyright (c) (2010,2011,2012,2014,2015,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#import "HMACValidation.h"

#import <corecrypto/cchmac.h>
#import <corecrypto/ccmd5.h>
#import <corecrypto/ccsha1.h>
#import <corecrypto/ccsha2.h>
#import "cchmac_internal.h"

@implementation HMACValidation


/* Nist CAVP vectors specifies the hash as L=xx - those are the matching hashes implementations */
/* We use implementations that are available on all platforms, it does not matter which as we are not testing the hash implementation here */
#define hmac_di_20 &ccsha1_eay_di
#define hmac_di_28 &ccsha224_ltc_di
#define hmac_di_32 &ccsha256_ltc_di
#define hmac_di_48 &ccsha384_ltc_di
#define hmac_di_64 &ccsha512_ltc_di

const struct cchmac_test_input hmac_vectors[] ={
{
    &ccmd5_ltc_di,
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    16, "\x9a\x26\xc2\x30\x1f\x0c\xb0\x9c\x5c\xea\x0d\xdb\x43\xf6\x50\x34"
},
{
    &ccsha1_ltc_di,
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    20, "\x2f\x74\x92\xb9\x39\xb3\x97\x44\x39\xa9\xdc\x2e\xab\xcc\x69\x9c\xec\xc2\x3b\x02"
},
{
    &ccsha224_ltc_di,
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    28, "\xef\xf1\xcd\xa4\x3e\xe4\x0d\x65\x1a\xfa\x9f\x41\x19\xc1\xde\x45\x4c\x49\xfd\xbc\x21\x4d\x6e\x9e\x29\xc4\x06\x89",
},
{
    &ccsha256_ltc_di,
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    32, "\x80\x93\x01\xb1\x80\x58\x78\x2e\xc6\x61\x46\x3b\xdd\x77\x8e\x3c\xea\x82\x65\xff\x10\xac\xf7\x1d\x3f\x6d\x5b\x8f\xbf\xbd\xb5\x8a"
},
{
    &ccsha384_ltc_di,
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    48, "\xbe\x3c\x3e\x8e\x91\xd4\x71\x5e\xb4\x8f\x3d\x10\x28\xcd\x0e\xb2\x8c\xa5\x17\x10\x67\xef\x68\xc0\x1f\x0e\x53\xc5\xbb\x77\xa8\xce\xd6\x51\xe0\xdf\x0f\x82\xbd\x53\xf6\x2e\x82\xea\x07\x23\x9e\x7b"
},
{
    &ccsha512_ltc_di,
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    10, "\xfe\x34\x67\xf6\xbe\xdc\x12\x04\x6a\x5c",
    64, "\xb3\x7a\xaa\x28\xc4\xea\xd6\xa5\xa1\x1c\xc9\xb3\xbb\x47\x1d\x47\x1f\x0c\x43\xb6\x31\x2f\x76\x57\x07\xed\x67\xce\xfa\x81\x6b\xf6\xd7\xc6\xb7\xbc\x1f\x3e\x51\xfe\xd8\xe4\x86\x4b\x4e\xca\x3b\x59\x6b\xb7\xc3\x45\x74\x8a\x9d\x45\x49\x7e\xd6\x7d\x53\x8a\x22\x3f"
},
{
    &ccsha1_eay_di,
    80, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    6, "abcdef",
    20, "\x37\x5d\xee\xf8\x45\xd7\x46\x58\xb1\xdc\xd4\xd5\x77\x26\xba\x86\x78\xe8\x61\xdc",
},

#include "HMAC.inc"

};

- (void) testOneShot {
    for (size_t i=0; i < sizeof(hmac_vectors)/sizeof(hmac_vectors[0]); i++) {
        const struct cchmac_test_input *v=&hmac_vectors[i];
        XCTAssertEqual(0, cchmac_test(v), @"Vectors %u", (unsigned int)i);
    }
}

- (void) testChunks {
    for (size_t i=0; i < sizeof(hmac_vectors)/sizeof(hmac_vectors[0]); i++) {
        const struct cchmac_test_input *v=&hmac_vectors[i];
        XCTAssertEqual(0, cchmac_test_chunks(v, 1), @"Vectors %u", (unsigned int)i);
    }
}
@end
