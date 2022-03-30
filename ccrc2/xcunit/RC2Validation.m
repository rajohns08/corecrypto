/* Copyright (c) (2010,2011,2014,2015,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#import "RC2Validation.h"
#include <corecrypto/ccmode.h>
#include <corecrypto/ccrc2.h>
#include "ccrc2_internal.h"
#import <xcunit/ccmode_test.h>

static const struct ccmode_ecb_vector tests[] = {
    {
        8,
        "\x30\x00\x00\x00\x00\x00\x00\x00",
        1,
        "\x10\x00\x00\x00\x00\x00\x00\x01",
        "\x30\x64\x9e\xdf\x9b\xe7\xd2\xc2"
    },
    {
        8,
        "\x30\x00\x00\x00\x00\x00\x00\x00",
        2,
        "\x10\x00\x00\x00\x00\x00\x00\x01\x10\x00\x00\x00\x00\x00\x00\x01",
        "\x30\x64\x9e\xdf\x9b\xe7\xd2\xc2\x30\x64\x9e\xdf\x9b\xe7\xd2\xc2"
    },
    {
        16,
        "\x88\xbc\xa9\x0e\x90\x87\x5a\x7f\x0f\x79\xc3\x84\x62\x7b\xaf\xb2",
        1,
        "\x00\x00\x00\x00\x00\x00\x00\x00",
        "\x22\x69\x55\x2a\xb0\xf8\x5c\xa6"
    }
};

@implementation RC2Validation

- (void) testRC2
{
    int x;
    const struct ccmode_ecb *enc=&ccrc2_ltc_ecb_encrypt_mode;
    const struct ccmode_ecb *dec=&ccrc2_ltc_ecb_decrypt_mode;

    for (x = 0; x < (int)(sizeof(tests) / sizeof(tests[0])); x++) {
        XCTAssertEqual(0, ccmode_ecb_test_one_vector(enc, &tests[x],0), @"Encrypt %d", x);
        XCTAssertEqual(0, ccmode_ecb_test_one_vector(dec, &tests[x],1), @"Decrypt %d", x);
        XCTAssertEqual(0, ccmode_ecb_test_key_self(enc, dec, 2, tests[x].keylen, tests[x].key, 1000), @"Self Test Key %d", x);
    }
}

@end
