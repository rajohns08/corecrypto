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

#import "RC4Validation.h"
#include <corecrypto/ccrc4.h>
#include "ccrc4_internal.h"

/* some simple test vectors from wikipedia...

 Key, keystream, plaintext, cipher text

 Key
 eb9f7781b734ca72a719...
 Plaintext
 BBF316E8D940AF0AD3

 Wiki
 6044db6d41b7...
 pedia
 1021BF0420

 Secret
 04d46b053ca87b59...
 Attack at dawn
 45A01F645FC35B383552544B9BF5

 */

static struct ccrc4_vector vectors[] = {
    {
        3,
        "Key",
        9,
        "Plaintext",
        "\xBB\xF3\x16\xE8\xD9\x40\xAF\x0A\xD3",
    },{
        4,
        "Wiki",
        5,
        "pedia",
        "\x10\x21\xBF\x04\x20",
    },{
        6,
        "Secret",
        14,
        "Attack at dawn",
        "\x45\xA0\x1F\x64\x5F\xC3\x5B\x38\x35\x52\x54\x4B\x9B\xF5",
    },
};

@implementation RC4Validation

- (void) testRC4 {
    const struct ccrc4_info *rc4 = &ccrc4_eay;

    for(size_t i=0; i<sizeof(vectors)/sizeof(vectors[0]); i++)
    {
        XCTAssertEqual(0, ccrc4_test(rc4, &vectors[i]), @"vector %d", (unsigned int)i);
    }
}

@end
