/* Copyright (c) (2010,2011,2012,2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testbyteBuffer.h"

#if (CC_DYLIB == 0)
entryPoint(cc_dylib_tests, "cc dylib self-test verification")
#else

#if defined(_WIN32)
int cc_dylib_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(1);
    pass("");
    diag("cc_dylib_tests are not ported to Windows yet.\n");
    return 1;
}
#else

#include "fipspost.h"

#include "fipspost_post_aes_cbc.h"
#include "fipspost_post_aes_ecb.h"
#include "fipspost_post_aes_gcm.h"
#include "fipspost_post_aes_ccm.h"
#include "fipspost_post_aes_xts.h"
#include "fipspost_post_aes_cmac.h"
#include "fipspost_post_drbg_ctr.h"
#include "fipspost_post_drbg_hmac.h"
#include "fipspost_post_ecdh.h"
#include "fipspost_post_ecdsa.h"
#include "fipspost_post_ffdh.h"
#include "fipspost_post_hmac.h"
#include "fipspost_post_rsa_enc_dec.h"
#include "fipspost_post_rsa_sig.h"
#include "fipspost_post_tdes_cbc.h"
#include "fipspost_post_pbkdf.h"
#include "fipspost_post_kdf_ctr.h"

int cc_dylib_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(16);

    is(fipspost_post_aes_ecb(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for AES ECB");
    is(fipspost_post_aes_cbc(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for AES CBC");
    is(fipspost_post_aes_gcm(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for AES GCM");
    is(fipspost_post_aes_ccm(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for AES CCM");
    is(fipspost_post_aes_xts(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for AES XTS");
    is(fipspost_post_aes_cmac(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for AES CMAC");
    is(fipspost_post_tdes_cbc(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for TDES CBC");
    is(fipspost_post_hmac(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for HMAC");
    is(fipspost_post_rsa_enc_dec(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for RSA ENC/DEC");
    is(fipspost_post_rsa_sig(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for RSA SIG");
    is(fipspost_post_ecdsa(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for ECDSA");
    is(fipspost_post_ecdh(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for ECDH");
    is(fipspost_post_ffdh(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for FFDH");
    is(fipspost_post_drbg_ctr(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for CTR DRBG");
    is(fipspost_post_drbg_hmac(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for HMAC DRBG");
    is(fipspost_post_pbkdf(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for PBKDF");
    is(fipspost_post_kdf_ctr(FIPS_MODE_FLAG_VERBOSE), 0, "Run FIPS Test for CTR KDF");

    return 0;
}
#endif

#endif
