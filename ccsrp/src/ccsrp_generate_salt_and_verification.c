/* Copyright (c) (2010,2011,2012,2013,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccsrp_priv.h"

/******************************************************************************
 *  Salt and Verification Generation - used to setup an account.
 *****************************************************************************/

int ccsrp_generate_salt_and_verification(ccsrp_ctx_t srp,
                                         struct ccrng_state *rng,
                                         const char *username,
                                         size_t password_len,
                                         const void *password,
                                         size_t salt_len,
                                         void *salt,
                                         void *verifier)
{
    int status;
    if ((status = ccrng_generate(rng, salt_len, salt)) != 0)
        return status;
    return ccsrp_generate_verifier(srp, username, password_len, password, salt_len, salt, verifier);
}

int ccsrp_generate_verifier(ccsrp_ctx_t srp,
                            const char *username,
                            size_t password_len,
                            const void *password,
                            size_t salt_len,
                            const void *salt,
                            void *verifier)
{
    cc_size n = ccsrp_ctx_n(srp);
    cc_unit x[n]; // vla

    ccn_zero_multi(n, ccsrp_ctx_v(srp), x, NULL);
    ccsrp_generate_x(srp, x, username, salt_len, salt, password_len, password);
    ccsrp_generate_v(srp, x);
    ccsrp_export_ccn(srp, ccsrp_ctx_v(srp), verifier);
    ccn_zero_multi(n, ccsrp_ctx_v(srp), x, NULL);
    return 0;
}
