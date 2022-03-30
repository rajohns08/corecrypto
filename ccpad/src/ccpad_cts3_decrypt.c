/* Copyright (c) (2012,2014,2015,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccpad.h>
#include <corecrypto/cc_priv.h>
#include "ccpad_cts_helper.h"

size_t
ccpad_cts3_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *cbc_key, cccbc_iv *iv,
                   size_t len_bytes, const void *in, void *out)
{
    const size_t blocksize = cbc->block_size;
    size_t i, d;
    size_t nbytes=len_bytes;
    const uint8_t *inp = (const uint8_t *) in;
    uint8_t *outp = (uint8_t *) out;
    uint8_t z[blocksize], cN[2*blocksize];
    uint8_t *cN_1=&cN[blocksize];

    // Full blocks up to padding
    ccpad_cts_crypt(cbc, cbc_key, iv, &nbytes, &inp, &outp);

    // Tail, takes care of padding
    cc_memcpy(cN, inp, nbytes);
    if (nbytes == (blocksize*2)) {
        /* Complete Block - just decrypt and return */
        swapblocks(cN, blocksize);
        cbc->cbc(cbc_key, iv, 2, cN, outp);
        return len_bytes;
    }

    d = nbytes - blocksize;
    ecb_from_cbc(cbc, cbc_key, cN, z);

    for(i=d; i<blocksize; i++) cN_1[i] = z[i];

    /* Decrypt the n-1th block */
    cbc->cbc(cbc_key, iv, 1, cN_1, outp);

    for(i=0; i<d; i++)
        outp[i+blocksize] = cN_1[i] ^ z[i];
    return len_bytes;
}

