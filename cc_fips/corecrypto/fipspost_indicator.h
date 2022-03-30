/* Copyright (c) (2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_INDICATOR_H_
#define _CORECRYPTO_FIPSPOST_INDICATOR_H_

/// Checks if a symmetric algorithm mode is allowed for the given key size.
int fips_allowed_mode(const void *mode, size_t key_byte_length);

/// Checks if a function is allowed according to FIPS. The arguments are precise the context in which the function will used if
/// required. E.G., for a SHA* hash function no parameters are needed, since the function is sufficient to define the use. On the
/// opposite a symmetric mode requires the key length in bytes and the cryptographic algorithm. num_args: the number of passed
/// arguments. It can currently be 0, 1, or 2. Depending on num_args, the following arguments can be:
/// * num_args == 1:
///    - struct ccdigest_info * for a DRBG function
///    - ccec_const_cp_t for an ECC function
///    - struct ccdigest_info * for a HMAC function
///    - ccdh_const_gp_t for a DH function
///    - ccec_const_cp_t for ECDH function
///    - key_byte_length for a KDF CTR CMAC function
///    - struct ccdigest_info * for a KDF CTR HMAC or PBKDF2 function
///    - key_bit_length for RSA related functions
int fips_allowed(const void *function, size_t num_args, ...);

#endif /* _CORECRYPTO_FIPSPOST_INDICATOR_H_ */
