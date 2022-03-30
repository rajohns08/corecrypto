/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdrbg.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_drbg_ctr.h"

// Test CTR DRBG
int fipspost_post_drbg_ctr(uint32_t fips_mode)
{
	int result = CCPOST_GENERIC_FAILURE;

    unsigned char*  entropyInputBuffer;
    entropyInputBuffer = POST_FIPS_RESULT_STR("\x74\x7a\xe6\x1f\x3d\xb3\x31\x52\x9a\x13\xc3\x6d\xc6\xeb\xd2\xef");


	size_t entropyInputBufferLength = 16;
	unsigned char* nonceBuffer = (unsigned char *)"\xff\xbd\xdc\xdf\x7f\xdd\xce\xa4";
	size_t nonceBufferLength = 8;
	unsigned char* personalizationStringBuffer = (unsigned char *)"\xbd\x93\xc6\xd5\x6b\x07\x7b\xf3\xca\x13\x0c\xc3\xef\xbf\xc7\x10";
	size_t personalizationStringBufferLength = 16;
	unsigned char* additionalInput1Buffer = (unsigned char *)"\xdf\xb1\xe7\x83\x82\xc8\xdb\xd7\xef\x1a\x20\x0b\x13\x67\x1a\xe2";
	size_t additionalInput1BufferLength = 16;
	unsigned char* entropyInputPR1Buffer = (unsigned char *)"\x34\x83\x2e\xc3\x2b\x10\x58\xc9\x8d\x72\xb0\xb6\x89\xa8\xda\xe2";
	size_t entropyInputPR1BufferLength = 16;
	unsigned char* additionalInput2Buffer = (unsigned char *)"\xca\x83\xd6\x45\x5e\x98\xcd\x09\xd6\x65\x86\xe2\x63\x92\x6d\xe6";
	size_t additionalInput2BufferLength = 16;
	unsigned char* entropyInputPR2Buffer = (unsigned char *)"\xbe\xe1\x92\xef\x26\xdd\xbb\x23\x6a\xf8\x29\xd0\xc7\xd8\x49\xb7";
	size_t entropyInputPR2BufferLength = 16;
	unsigned char* returnedBitsBuffer = (unsigned char *)"\x52\x58\xdd\xef\x4b\xda\x42\xed\x49\x9e\x57\xf1\x51\x74\xb0\x87";
	size_t returnedBitsBufferLength = 16;
	
	uint8_t resultBuffer[16];
	memset(resultBuffer, 0, 16);

    static struct ccdrbg_info info;
 	struct ccdrbg_nistctr_custom custom;
   	custom.ctr_info = ccaes_ctr_crypt_mode();
    custom.keylen = 16;
    custom.strictFIPS = 0;
    custom.use_df = 1;
	ccdrbg_factory_nistctr(&info, &custom);

	uint8_t state[info.size];
    struct ccdrbg_state* rng = (struct ccdrbg_state *)state;
    int rc;

	rc = ccdrbg_init(&info, rng, entropyInputBufferLength, entropyInputBuffer,
                         nonceBufferLength, nonceBuffer, personalizationStringBufferLength, personalizationStringBuffer);
	if (rc)
	{
		failf("ccdrbg_init");
		return CCPOST_GENERIC_FAILURE;
	}

	rc = ccdrbg_reseed(&info, rng, entropyInputPR1BufferLength, entropyInputPR1Buffer,
                                  additionalInput1BufferLength, additionalInput1Buffer);
	if (rc)
	{
		failf("ccdrbg_reseed");
		return CCPOST_GENERIC_FAILURE;
	}

	rc = ccdrbg_generate(&info, rng, 16, resultBuffer, 0, NULL);
	if (rc)
	{
		failf("ccdrbg_generate");
		return CCPOST_GENERIC_FAILURE;
	}

	rc = ccdrbg_reseed(&info, rng, 
                                  entropyInputPR2BufferLength, entropyInputPR2Buffer,  
                                  additionalInput2BufferLength, additionalInput2Buffer);
	if (rc)
	{
		failf("ccdrbg_reseed 2");
		return CCPOST_GENERIC_FAILURE;
	}

	rc = ccdrbg_generate(&info, rng, 16, resultBuffer, 0, NULL);
	if (rc)
	{
		failf("ccdrbg_generate 2");
		return CCPOST_GENERIC_FAILURE;
	}

	result = (memcmp(resultBuffer, returnedBitsBuffer, returnedBitsBufferLength)) ? CCPOST_KAT_FAILURE : 0;
	if (result)
	{
		failf("memcmp");
		return result;
	}

	return 0;
}
