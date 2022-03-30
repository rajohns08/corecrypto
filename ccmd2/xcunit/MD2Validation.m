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

#import "MD2Validation.h"

#import <corecrypto/ccmd2.h>
#import "ccdigest_test.h"

@implementation MD2Validation

static const struct ccdigest_info *di[]={
    &ccmd2_ltc_di,
};

#define N_IMPL (sizeof(di)/sizeof(struct ccdigest_info *))

static NSString *impl[N_IMPL]={
    @"ltc (libtomcrypt)",
};

static const struct ccdigest_vector md2_vectors[] = {
	{
		0,
		"",
		"\x83\x50\xe5\xa3\xe2\x4c\x15\x3d\xf2\x27\x5c\x9f\x80\x69\x27\x73"
	},
	{
		43,
		"The quick brown fox jumps over the lazy dog",
		"\x03\xd8\x5a\x0d\x62\x9d\x2c\x44\x2e\x98\x75\x25\x31\x9f\xc4\x71"
	},
	{
		175,
		"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog",
		"\xfb\x63\x68\x24\x0d\xbe\xa2\x3e\x91\x72\xba\x79\x41\x20\x4a\xcf"
	},
	{
		351,
		"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog",
		"\x20\x66\x59\x05\x50\x86\x39\xaa\xf2\x06\x24\x11\xab\x6d\x08\x05"
	},
	{
		111,
		"123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901",
		"\xe3\x08\x94\x1a\xfb\x38\x27\x8c\x13\xe5\xa9\xa4\x8c\xf8\x5b\xdd"
	},
};
#define N_VECTORS (sizeof(md2_vectors)/sizeof(md2_vectors[0]))

- (void) testOneShot {
    for(unsigned int j=0; j<N_IMPL; j++) {
        for(unsigned int i=0; i<N_VECTORS; i++) {
            XCTAssertEqual(0, ccdigest_test_vector(di[j], &md2_vectors[i]),@"Vector %d (%@)", i, impl[j]);
        }
    }
}

- (void) testChunks {
    for(unsigned int j=0; j<N_IMPL; j++) {
        for(unsigned int i=0; i<N_VECTORS; i++) {
            XCTAssertEqual(0, ccdigest_test_chunk_vector(di[j], &md2_vectors[i], 1),@"Vector %d (%@)", i, impl[j]);
        }
    }
}

@end
