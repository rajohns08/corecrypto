/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#import "SHA1Validation.h"

#include <corecrypto/ccsha1.h>
#include "ccsha1_internal.h"
#include "ccdigest_test.h"
#include <corecrypto/cc_config.h>
#include "cc_unit.h"

@implementation SHA1Validation

static const struct ccdigest_info *di[]={
    &ccsha1_eay_di,
    &ccsha1_ltc_di,
#if  CCSHA1_VNG_INTEL
    &ccsha1_vng_intel_SupplementalSSE3_di, // Assumes SupplementalSSE3
#endif
#if  CCSHA1_VNG_ARM
    &ccsha1_vng_arm_di,
#endif
};

#define N_IMPL (sizeof(di)/sizeof(di[0]))

static NSString *impl[N_IMPL]={
    @"eay (openssl)",
    @"ltc (libtomcrypt)",
#if  CCSHA1_VNG_INTEL
    @"vng_intel (vector numerics group)",
#endif
#if  CCSHA1_VNG_ARM
    @"vng_arm (vector numerics group)",
#endif
};

static const struct ccdigest_vector sha1_vectors[]=
{
    {
        0,
        "",
        "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09"
    },
    {
        43,
        "The quick brown fox jumps over the lazy dog",
        "\x2f\xd4\xe1\xc6\x7a\x2d\x28\xfc\xed\x84\x9e\xe1\xbb\x76\xe7\x39\x1b\x93\xeb\x12"
    },
    {
        175,
        "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog",
        "\xbe\xfa\xa0\x1d\x4d\x6d\x1e\x09\xbc\x96\x6e\x81\x0d\xb6\xf7\xc5\x67\x23\xf8\x2a"
    },
    {
        351,
        "The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog",
        "\xbe\x29\x0f\xc5\xf6\x4c\xec\x43\x55\xf5\x57\x9f\x6a\x7b\xb1\x97\x48\x4f\x76\x77"
    },
    {
        111,
        "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901",
        "\xf5\xd1\xcd\xda\xd8\x54\x63\x60\x81\x76\x53\xc2\xf5\xee\x58\xde\xb9\x21\x79\xcb"
    },
#include "SHA1ShortMsg.inc"
#include "SHA1LongMsg.inc"
};

#define N_VECTORS (sizeof(sha1_vectors)/sizeof(sha1_vectors[0]))

/* Test vectors for the compress function only */

#if  CCSHA1_VNG_ARM
- (void) testCompressArmv7 {
    const struct ccdigest_info *ref = &ccsha1_eay_di;
    const struct ccdigest_info *vng = &ccsha1_vng_arm_di;

    unsigned char vector[CCSHA1_BLOCK_SIZE]; 
    
    for(unsigned int i=0; i<CCSHA1_BLOCK_SIZE; i++) {
        cc_ctx_decl(struct ccdigest_state, CCSHA1_STATE_SIZE, state_ref);
        cc_ctx_decl(struct ccdigest_state, CCSHA1_STATE_SIZE, state_vng);
        cc_clear(sizeof(state_ref),state_ref);
        cc_clear(sizeof(state_vng),state_vng);
        cc_clear(sizeof(vector),vector);

        vector[i]=0x80;

        ref->compress(state_ref, 1, vector);
        vng->compress(state_vng, 1, vector);

        XCAssertMemEquals(20, state_ref, state_vng, @"%d\n", i);
        cc_clear(CCSHA1_STATE_SIZE, state_ref);
        cc_clear(CCSHA1_STATE_SIZE, state_vng);
    }
}
#endif

- (void) testOneShot {
    for(unsigned int j=0; j<N_IMPL; j++) {
        for(unsigned int i=0; i<N_VECTORS; i++) {
            XCTAssertEqual(0, ccdigest_test_vector(di[j], &sha1_vectors[i]),@"Vector %d (%@)", i, impl[j]);
        }
    }
}

- (void) testChunks {
    for(unsigned int j=0; j<N_IMPL; j++) {
        for(unsigned int i=0; i<N_VECTORS; i++) {
            XCTAssertEqual(0, ccdigest_test_chunk_vector(di[j], &sha1_vectors[i], 1),@"Vector %d (%@)", i, impl[j]);
        }
    }
}

@end
