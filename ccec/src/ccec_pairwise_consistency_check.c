/* Copyright (c) (2011,2012,2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_priv.h>
#include <corecrypto/ccec.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng.h>

#include "corecrypto/fipspost_trace.h"

bool ccec_pairwise_consistency_check(ccec_full_ctx_t full_key, struct ccrng_state *rng)
{
    FIPSPOST_TRACE_EVENT;

    size_t digest_size=CCSHA256_OUTPUT_SIZE;
	uint8_t fake_digest[digest_size];
	cc_memset(fake_digest, 0xa, digest_size);
	size_t siglen = ccec_sign_max_size(ccec_ctx_cp(full_key));
	uint8_t sig[siglen];

	int iResult = ccec_sign(full_key, digest_size, fake_digest, &siglen, sig, rng);
	if (iResult)
	{
		return false;
	}

	bool result = false;

	ccec_verify(ccec_ctx_pub(full_key), digest_size, fake_digest, siglen, sig, &result);
    cc_clear(siglen,sig); // Clear generated signature
	return result;
}
