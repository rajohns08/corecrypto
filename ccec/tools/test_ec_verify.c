/* Copyright (c) (2010,2011,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/ccec.h>

int main(/* int argc, const char *const *argv */) {
    bool valid;
    unsigned char digest[20], sig[68];
    ccec_const_cp_t cp = ccec_cp_256();
    ccec_pub_ctx_decl_cp(cp, key); ccec_ctx_init(cp, key); 

    return ccec_verify(key, sizeof(digest), digest, sizeof(sig), sig, &valid);
}
