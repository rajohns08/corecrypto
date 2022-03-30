/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#ifndef corecrypto_ccsaetest_h
#define corecrypto_ccsaetest_h

struct ccsae_test_vector {
    const char *test_desc;
    const struct ccdigest_info *di;
    ccec_const_cp_t (*curve)(void);
    const char *password;
    const char *password_identifier;
    const char *A;
    const char *B;
    const char *rand_seq;
    const char *commit;
    const char *peer_commit;
    const char *send_confirm;
    const char *confirm;
    const char *peer_send_confirm;
    const char *peer_confirm;
    const char *kck;
    const char *pmk;
    const char *pmkid;
};

#endif /* corecrypto_ccsaetest_h */
