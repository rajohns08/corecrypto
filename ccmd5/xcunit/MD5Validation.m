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

#import "MD5Validation.h"

#import <corecrypto/ccmd5.h>
#import "ccdigest_test.h"

static const struct ccdigest_vector md5_vectors[] = {
	{
		0,
		"",
		"\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"
	},
	{
		43,
		"The quick brown fox jumps over the lazy dog",
		"\x9e\x10\x7d\x9d\x37\x2b\xb6\x82\x6b\xd8\x1d\x35\x42\xa4\x19\xd6"
	},
	{
		175,
		"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog",
		"\x9b\xef\x81\x00\x15\xc2\xed\x23\x99\x03\x93\x37\xbc\x33\x05\x51"
	},
	{
		351,
		"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog",
		"\x72\x3c\x4d\xab\x40\x35\xa7\xef\x3d\x19\xda\x98\x89\xfa\x79\xf6"
	},
	{
		111,
		"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901",
		"\x68\x57\xb4\x7b\x0c\xed\x34\xe4\xf9\x5f\xa3\xfa\x3f\x89\xa7\x93"
	},
};
#define N_VECTORS (sizeof(md5_vectors)/sizeof(md5_vectors[0]))


@implementation MD5Validation

static const struct ccdigest_info *di[]={
    &ccmd5_ltc_di,
};

#define N_IMPL (sizeof(di)/sizeof(struct ccdigest_info *))

static NSString *impl[N_IMPL]={
    @"ltc (libtomcrypt)",
};

- (void) testOneShot {
    for(unsigned int j=0; j<N_IMPL; j++) {
        for(unsigned int i=0; i<N_VECTORS; i++) {
            XCTAssertEqual(0, ccdigest_test_vector(di[j], &md5_vectors[i]),@"Vector %d (%@)", i, impl[j]);
        }
    }
}

- (void) testChunks {
    for(unsigned int j=0; j<N_IMPL; j++) {
        for(unsigned int i=0; i<N_VECTORS; i++) {
            XCTAssertEqual(0, ccdigest_test_chunk_vector(di[j], &md5_vectors[i], 1),@"Vector %d (%@)", i, impl[j]);
        }
    }
}

@end
