/* Copyright (c) (2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
#include "ccdh_internal.h"
#include <corecrypto/ccrsa_priv.h> // for MGF

/*!
 @function   ccsrp_sha_interleave_RFC2945
 @abstract   Hash Interleave per SHA_Interleave from RFC2945

 @param      srp        Digest to use, if used per RFC it will be SHA1
 @param      s         Shared Secret in array of cc_unit
 @param      dest      Byte array for output of size at least 2*di->outputsize
 */

static int ccsrp_sha_interleave_RFC2945(ccsrp_ctx_t srp, const cc_unit *s, uint8_t *dest)
{
    uint8_t buf[ccsrp_ctx_sizeof_n(srp)];   // vla
    uint8_t E[ccsrp_ctx_sizeof_n(srp) / 2]; // vla
    uint8_t F[ccsrp_ctx_sizeof_n(srp) / 2]; // vla
    uint8_t *T = buf;
    size_t digestlen = ccsrp_ctx_di(srp)->output_size;
    uint8_t G[digestlen]; // vla
    uint8_t *H = ((uint8_t *)dest) + digestlen;
    // remove all leading zero bytes from the input.
    size_t T_len = ccn_write_uint_size(ccsrp_ctx_n(srp), s);
    ccn_write_uint(ccsrp_ctx_n(srp), s, T_len, T);
    if (T_len & 1) {
        //  If the length of the resulting string is odd, also remove the first byte.
        T = &buf[1];
        T_len--;
    }
    // Extract the even-numbered bytes into a string E and the odd-numbered bytes into a string F
    for (size_t i = 0; i < T_len / 2; i++) {
        // E[i]=T[2*i];    // E = T[0] | T[2] | T[4] | ...
        // F[i]=T[2*i+1];  // F = T[1] | T[3] | T[5] | ...
        E[T_len / 2 - i - 1] = T[2 * i + 1]; // E = T[0] | T[2] | T[4] | ...
        F[T_len / 2 - i - 1] = T[2 * i];     // F = T[1] | T[3] | T[5] | ...
    }
    ccdigest(ccsrp_ctx_di(srp), T_len / 2, E, G); //  G = SHA(E)
    ccdigest(ccsrp_ctx_di(srp), T_len / 2, F, H); //  H = SHA(F)

    // Interleave the two hashes back together to form the output, i.e.
    //  result = G[0] | H[0] | G[1] | H[1] | ... | G[19] | H[19]
    for (size_t i = 0; i < digestlen; i++) {
        dest[2 * i] = G[i];
        dest[2 * i + 1] = H[i];
    }
    // With SHA1, the result will be 40 bytes (320 bits) long.
    return 0;
}

/*!
 @function   ccsrp_mgf
 @abstract   Derivation using MGF as defined in RSA PKCS1

 @param      srp        Digest to use, if used per RFC it will be SHA1
 @param      s         Shared Secret in array of cc_unit
 @param      dest      Byte array for output of size at least 2*di->outputsize
 */
static int ccsrp_mgf(ccsrp_ctx_t srp, const cc_unit *s, void *dest)
{
    size_t offset;
    uint8_t buf[ccsrp_ctx_sizeof_n(srp)]; // vla
    offset = ccsrp_export_ccn(srp, s, buf);
    /* leading zeroes are skipped */
    return ccmgf(ccsrp_ctx_di(srp),
                 2 * (ccsrp_ctx_di(srp)->output_size),
                 dest,
                 ccsrp_ctx_sizeof_n(srp) - offset,
                 buf + offset);
}

/*!
 @function   ccsrp_generate_K_from_S
 @abstract   Generate the key K from the shared secret S

 @param      srp        SRP
 @param      S          Number represented as a cc_unit array of size ccsrp_ctx_sizeof_n(srp)

 @result SRP structure is update with value S
 */
int ccsrp_generate_K_from_S(ccsrp_ctx_t srp, const cc_unit *S)
{
    int rc = CCSRP_ERROR_DEFAULT;
    if ((SRP_FLG(srp).variant & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_HASH) {
        /* K = H(S) */
        ccsrp_digest_ccn(
            srp, S, ccsrp_ctx_K(srp), (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X));
        rc = 0;
    } else if ((SRP_FLG(srp).variant & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_INTERLEAVED) {
        /* K = SHA_Interleave(S) */
        /* specification is clear, leading zeroes are skipped */
        rc = ccsrp_sha_interleave_RFC2945(srp, S, ccsrp_ctx_K(srp));
    } else if ((SRP_FLG(srp).variant & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_MGF1) {
        /* K = MGF1(S) */
        rc = ccsrp_mgf(srp, S, ccsrp_ctx_K(srp));
    } else {
        rc = CCSRP_NOT_SUPPORTED_CONFIGURATION;
    }
    if (rc == 0)
        SRP_FLG(srp).sessionkey = true;
    return rc; // No error
}
