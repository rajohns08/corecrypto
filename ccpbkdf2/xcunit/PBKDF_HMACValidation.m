/* Copyright (c) (2010,2011,2012,2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#import "PBKDF_HMACValidation.h"
#import <corecrypto/ccdigest.h>
#import <corecrypto/ccsha1.h>
#import <corecrypto/ccpbkdf2.h>

@implementation PBKDF_HMACValidation

#define kMaxExpectedSize 128

struct pbkdf2_hmac_test_info {
    const struct ccdigest_info*   di;
    const char*                   password;
    const char*                   salt;
    const size_t           iterations;
    const size_t           resultSize;
    const uint8_t                 expected[kMaxExpectedSize];
};

const struct pbkdf2_hmac_test_info unitTests[] = {
    {
        .di         = &ccsha1_eay_di,
        .password   = "password",
        .salt       = "salt",
        .iterations = 1,
        .resultSize = 20,
        .expected   = { 0x0c, 0x60, 0xc8, 0x0f,
                        0x96, 0x1f, 0x0e, 0x71,
                        0xf3, 0xa9, 0xb5, 0x24,
                        0xaf, 0x60, 0x12, 0x06, 
                        0x2f, 0xe0, 0x37, 0xa6 }
    },
    {
        .di         = &ccsha1_eay_di,
        .password   = "password",
        .salt       = "salt",
        .iterations = 2,
        .resultSize = 20,
        .expected   = { 0xea, 0x6c, 0x01, 0x4d,
                        0xc7, 0x2d, 0x6f, 0x8c,
                        0xcd, 0x1e, 0xd9, 0x2a,
                        0xce, 0x1d, 0x41, 0xf0,
                        0xd8, 0xde, 0x89, 0x57 }
    },
    {
        .di         = &ccsha1_eay_di,
        .password   = "password",
        .salt       = "salt",
        .iterations = 4096,
        .resultSize = 20,
        .expected   = { 0x4b, 0x00, 0x79, 0x01,
                        0xb7, 0x65, 0x48, 0x9a,
                        0xbe, 0xad, 0x49, 0xd9,
                        0x26, 0xf7, 0x21, 0xd0,
                        0x65, 0xa4, 0x29, 0xc1 }
    },
    {
        .di         = &ccsha1_eay_di,
        .password   = "ThisPasswordIsMoreThan100BytesLongThisPasswordIsMoreThan100BytesLongThisPasswordIsMoreThan100BytesLongThisPasswordIsMoreThan100BytesLongThisPasswordIsMoreThan100BytesLongThisPasswordIsMoreThan100BytesLongThisPasswordIsMoreThan100BytesLongThisPasswordIsMoreThan100BytesLong",
        .salt       = "salt",
        .iterations = 1000,
        .resultSize = 8,
        .expected   = { 0xd9, 0xef, 0xed, 0xda, 0x5a, 0xba, 0x3d, 0xb9 }
    },    
    /* test vectors with big salt and keylen > hash_size */
    /* generated from : http://anandam.name/pbkdf2/ */
    {
        .di         = &ccsha1_eay_di,
        .password   = "passwordPASSWORDpassword", /* (24 octets) */
        .salt       = "saltSALTsaltSALTsaltSALTsaltSALTsalt", /* (36 octets) */
        .iterations = 4096,
        .resultSize = 25,
        .expected   = { 0x3d, 0x2e, 0xec, 0x4f,
                        0xe4, 0x1c, 0x84, 0x9b,
                        0x80, 0xc8, 0xd8, 0x36,
                        0x62, 0xc0, 0xe4, 0x4a,
                        0x8b, 0x29, 0x1a, 0x96,
                        0x4c, 0xf2, 0xf0, 0x70,
                        0x38 }
    },
    {
        .di         = &ccsha1_eay_di,
        .password   = "password",
        .salt       = "saltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALTsaltSALT", /* (128octets) */
        .iterations = 1,
        .resultSize = 4,
        .expected   = { 0x34, 0x3b, 0x6c, 0x04 }
    },
#if USE_SLOW_TEST
    {
        .di         = &ccsha1_eay_di,
        .password   = "password",
        .salt       = "salt",
        .iterations = 16777216,
        .resultSize = 20,
        .expected   = { 0xee, 0xfe, 0x3d, 0x61,
                        0xcd, 0x4d, 0xa4, 0xe4,
                        0xe9, 0x94, 0x5b, 0x3d,
                        0x6b, 0xa2, 0x15, 0x8c,
                        0x26, 0x34, 0xe9, 0x84 }
    }
#endif
};
    
#define kTotalTests (sizeof(unitTests)/sizeof(unitTests[0]))


- (void) testPBKDF_HMAC {
    for (size_t testNumber = 0; testNumber < kTotalTests; ++testNumber) {
        const struct pbkdf2_hmac_test_info* currentTest = unitTests + testNumber;
        uint8_t result[currentTest->resultSize];

        ccpbkdf2_hmac(currentTest->di,
                      strlen(currentTest->password), currentTest->password,
                      strlen(currentTest->salt), currentTest->salt,
                      currentTest->iterations,
                      currentTest->resultSize, result);
        
        XCAssertMemEquals(currentTest->resultSize, (const unsigned char *)result,
                          (const unsigned char *)currentTest->expected, @"pbkdf failed");
    }
}

@end
