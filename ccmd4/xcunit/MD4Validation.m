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

#import "MD4Validation.h"

#import <corecrypto/ccmd4.h>
#import "ccdigest_test.h"

static const struct ccdigest_vector md4_vectors[] = {
	{
		0,
		"",
		"\x31\xd6\xcf\xe0\xd1\x6a\xe9\x31\xb7\x3c\x59\xd7\xe0\xc0\x89\xc0"
	},
	{
		43,
		"The quick brown fox jumps over the lazy dog",
		"\x1b\xee\x69\xa4\x6b\xa8\x11\x18\x5c\x19\x47\x62\xab\xae\xae\x90"
	},
	{
		175,
		"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog",
		"\x98\x39\x84\x09\xbc\xce\x60\x46\xaf\x73\x99\x99\x2a\x15\xad\x41"
	},
	{
		351,
		"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog",
		"\xae\x6e\xb5\x4d\xff\xd2\xbd\x55\x9e\x73\x91\xa0\x52\xc9\x09\x6f"
	},
	{
		111,
		"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901",
		"\xf2\x0d\xf5\x9b\x03\x82\x74\xce\x6b\x34\x62\x02\x03\x3f\x60\xfe"
	},
};
#define N_VECTORS (sizeof(md4_vectors)/sizeof(md4_vectors[0]))

@implementation MD4Validation

static const struct ccdigest_info *di[]={
    &ccmd4_ltc_di,
};

#define N_IMPL (sizeof(di)/sizeof(struct ccdigest_info *))

static NSString *impl[N_IMPL]={
    @"ltc (libtomcrypt)",
};

- (void) testOneShot {
    for(unsigned int j=0; j<N_IMPL; j++) {
        for(unsigned int i=0; i<N_VECTORS; i++) {
            XCTAssertEqual(0, ccdigest_test_vector(di[j], &md4_vectors[i]),@"Vector %d (%@)", i, impl[j]);
        }
    }
}

- (void) testChunks {
    for(unsigned int j=0; j<N_IMPL; j++) {
        for(unsigned int i=0; i<N_VECTORS; i++) {
            XCTAssertEqual(0, ccdigest_test_chunk_vector(di[j], &md4_vectors[i], 1),@"Vector %d (%@)", i, impl[j]);
        }
    }
}

@end
