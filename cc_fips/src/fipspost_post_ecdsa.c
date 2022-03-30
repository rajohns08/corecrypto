/* Copyright (c) (2017,2018,2019) Apple Inc. All rights reserved.
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
#include <corecrypto/ccec.h>
#include <corecrypto/ccrng_ecfips_test.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_ecdsa.h"

// Test ECDSA
int fipspost_post_ecdsa(uint32_t fips_mode)
{
	// Pair wise consistency test
	size_t keySize = 256; 
    int iResult = 0;

    struct ccrng_state *rng;
    struct ccrng_ecfips_test_state ectest_rng;

    ccrng_ecfips_test_init(&ectest_rng, 0, NULL);

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode))
    {
        rng = (struct ccrng_state *)&ectest_rng;
    }
    else
    {
        rng = ccrng(NULL);
    }

	ccec_const_cp_t cp = ccec_get_cp(keySize);
	ccec_full_ctx_decl_cp(cp, full_ec_key);   	
    size_t signedDataLen = ccec_sign_max_size(cp);
    uint8_t signedData[signedDataLen];
    cc_clear(signedDataLen, signedData);

    iResult = ccec_generate_key_fips(cp, rng, full_ec_key);
	ccec_full_ctx_clear_cp(cp, full_ec_key);
	if (iResult)
	{
		failf("ccec_generate_key_fips");
		return CCPOST_KAT_FAILURE;
	}

	return 0;
}
