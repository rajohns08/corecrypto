/* Copyright (c) (2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
*/

#ifndef _CORECRYPTO_CCAES_INTERNAL_H_
#define _CORECRYPTO_CCAES_INTERNAL_H_

#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>

#define CCAES_ROUNDKEY_SIZE 16
#define CCAES_NROUNDS_256 14

/*!
  @function ccaes_unwind_with_ecb
  @abstract "Unwind" an AES encryption key to the equivalent decryption key.

  @param aesecb An AES ECB encryption implementation
  @param key_nbytes Length in bytes of the input AES encryption key
  @param key The input AES encryption key
  @param out The output AES decryption key

  @result @p CCERR_OK iff successful, negative otherwise.
  @discussion Only AES256 (i.e. 32-byte) keys are supported.
*/
int ccaes_unwind_with_ecb(const struct ccmode_ecb *aesecb, size_t key_nbytes, const void *key, void *out);

#endif /* _CORECRYPTO_CCAES_INTERNAL_H_ */
