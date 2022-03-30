/* Copyright (c) (2011,2012,2013,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrsa_priv.h>

/*
    The r_size argument is really meant to be a size_t rather than a cc_size.  It's the size
    in bytes of the key for which this encoding is being done.  'r' on the other hand is a
    cc_unit array large enough to contain the blocksize of the key.  We need to build up the
    encoding "right justified" within r for r_size bytes.  We'll zero-pad the front and then
    at the end of this routine we'll use ccn_swap() to make it a big number.
 */

int ccrsa_oaep_encode_parameter(const struct ccdigest_info* di,
                                struct ccrng_state *rng,
                                size_t r_size, cc_unit *r,
                                size_t message_len, const uint8_t *message,
                                size_t parameter_data_len, const uint8_t *parameter_data)
{
   	const size_t encoded_len = r_size - 1;
    const size_t DB_len = encoded_len - di->output_size;
    const size_t seedMask_len = di->output_size;
    cc_unit DB[ccn_nof_size(DB_len)];//vla
    cc_unit dbMask[ccn_nof_size(DB_len)];//vla
    cc_unit seedMask[ccn_nof_size(seedMask_len)];//vla
    
    if ((encoded_len < 2 * di->output_size + 1)
        || (message_len > encoded_len - 2 * di->output_size - 1))
        return CCRSA_INVALID_INPUT;
    
    ccn_zero(ccn_nof_size(sizeof(DB)), DB);
    ccdigest(di, parameter_data_len, parameter_data, DB);
    
    uint8_t *DB_bytes = (uint8_t*)DB;
    
    DB_bytes[DB_len - 1 - message_len] = 1;
    
    cc_memcpy(DB_bytes + DB_len - message_len, message, message_len);
    
    // here we use the return buffer for generating the seed
    cc_unit *seed = r;
    if(ccrng_generate(rng, di->output_size, seed) != 0) return -1;
    ccmgf(di, DB_len, dbMask, di->output_size, seed);
    ccn_xor(ccn_nof_size(DB_len), DB, DB, dbMask);
    
    ccmgf(di, seedMask_len, seedMask, DB_len, DB);
    ccn_xor(ccn_nof_size(seedMask_len), seed, seed, seedMask);
    
    // get the block start non-destructively so we don't mess seed
    uint8_t *encoded = ccrsa_block_start(r_size, r, 0);
    // Copy the seed out before zeroing the leading zeros.
    cc_memmove(encoded+1, seed, di->output_size);
    // clear the beginning of the block if necessary
    encoded = ccrsa_block_start(r_size, r, 1);
    encoded[0] = 0;
    encoded++;
    cc_memcpy(encoded + di->output_size, DB, DB_len);
    
    ccn_clear(ccn_nof_size(DB_len), DB);
    ccn_clear(ccn_nof_size(DB_len), dbMask);
    ccn_clear(ccn_nof_size(seedMask_len), seedMask);
    
    ccn_swap(ccn_nof_size(r_size), r);
    return 0;
}
