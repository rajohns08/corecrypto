/* Copyright (c) (2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccmode_internal.h>
#include <corecrypto/ccn.h>
#include "xcunit/ccmode_test.h"
#include "crypto_test_modes.h"
#include "testbyteBuffer.h"
#include "testmore.h"

static int verbose = 0;

// to do: make sure this structure makes sense for CCM, as opposed to GCM
typedef struct ccccm_test_t {
    char *keyStr;
    char *aDataStr;
    char *init_ivStr;
    char *ptStr;
    char *ctStr;
    char *tagStr;
} ccccm_test_vector;

// Redundant tests, there are already run as part of crypto_test_modes.c
// however, this file does testing that crypto_test_modes does not support
// This file looks generic but ccm_vectors only contains test for AES
// and there is no way to specify another block cipher.
// crypto_test_modes is really generic.

// Function that is used to test ccm mode authenticated encryption with its most basic functionality
// with calls to set_iv, followed by calls to the cbcmac, and then the encryption followed by a call to finalize.

static int ccccm_discrete(const struct ccmode_ccm *mode,
                          size_t key_len, const void *key,
                          size_t nonce_len, const void *nonce,
                          size_t nbytes, const void *in, void *out,
                          size_t adata_len, const void *adata,
                          size_t tag_len, void *tag)
{
    size_t max_block_len = cc_rand(19);
    if(max_block_len == 0) {
        max_block_len = 1;
    }
    if(verbose){
        printf("\n------max_block_len=%zu\n", max_block_len);
    }
    int rc = 0;
    
    ccccm_ctx_decl(mode->size, ctx);
    ccccm_nonce_decl(mode->nonce_size, nonce_ctx);
    
    rc |= mode->init(mode, ctx, key_len, key);
    rc |= mode->set_iv(ctx, nonce_ctx, nonce_len, nonce, tag_len, adata_len, nbytes);
    
    if(adata_len > 0 && adata != NULL) {
        if (adata_len>max_block_len) {
            size_t d1 = adata_len-max_block_len;
            
            rc |= mode->cbcmac(ctx, nonce_ctx, max_block_len, adata);
            rc |= mode->cbcmac(ctx, nonce_ctx, d1, adata+max_block_len);
        } else {
            rc |= mode->cbcmac(ctx, nonce_ctx, adata_len, adata);
        }
    } else {
        if(verbose) printf("Skipping added AAD\n");
    }
    
    if(nbytes > 0) {
        rc |= mode->ccm(ctx, nonce_ctx, nbytes, in, out);
    } else {
        if(verbose) printf("Skipping data\n");
    }
    
    rc |= mode->finalize(ctx,nonce_ctx, tag);
    ccccm_ctx_clear(mode->size, ctx);
    
    return rc;
}

typedef int (*ccccm_test_func_t)(const struct ccmode_ccm *mode,
size_t key_len, const void *key,
size_t iv_len, const void *iv,
size_t nbytes, const void *in, void *out,
size_t adata_len, const void *adata,
size_t tag_len, void *tag);

static int ccm_test_a_function(const struct ccmode_ccm *em, const struct ccmode_ccm *dm,
                               size_t key_len, const void *key,
                               size_t iv_len, const void *iv,
                               size_t nbytes, const void *plaintext, void *ciphertext,
                               size_t adata_len, const void *adata,
                               size_t tag_len, void *tag,
                               ccccm_test_func_t func)
{
    uint8_t cipher_result[nbytes], plain_result[nbytes];
    uint8_t cipher_tag[tag_len], plain_tag[tag_len];
    int rc;
    
    rc = func(em, key_len, key, iv_len, iv,  nbytes, plaintext, cipher_result, adata_len, adata, tag_len, cipher_tag);
    ok_or_fail(rc == 0, "ccm encryption failed");
    memcpy(plain_tag, tag, tag_len); //set the expected tag for decryption
    rc = func(dm, key_len, key, iv_len, iv, nbytes, cipher_result, plain_result, adata_len, adata, tag_len, plain_tag );
    ok_or_fail(rc == 0, "ccm decryption failed");
    
    ok_memcmp_or_fail(plaintext, plain_result, nbytes, "Round Trip Encrypt/Decrypt works");
    ok_memcmp_or_fail(tag, cipher_tag, tag_len, "tags match on encrypt");
    ok_memcmp_or_fail(tag, plain_tag, tag_len, "tags match on decrypt");
    ok_memcmp_or_fail(ciphertext, cipher_result, nbytes, "Ciphertext matches known answer");
    
    return 1;
    
}

static int ccm_testcase(const struct ccmode_ccm *enc, const struct ccmode_ccm *dec)
{
    //Structure that contains test vectors that allow large adata by defining a repeat factor for adata
    struct iterated_adata_ccm_test_vector large_adata_vec_array[] = {
#include "../test_vectors/ccm_aes_128_long_adata_test_vectors.inc"
    };
    
    
    // Testing for different sizes of adata in ccm mode using AES128.
    unsigned int num_adata_vectors = sizeof(large_adata_vec_array) / sizeof(large_adata_vec_array[0]);
    
    for (unsigned int i = 0; i < num_adata_vectors; i++) {
        struct iterated_adata_ccm_test_vector *tmp_lvec=&(large_adata_vec_array[i]);
        
        // Generate adata by concatenating string appropriate number of times.
        size_t tmp_adata_n=tmp_lvec->aData_iterated_string_n * tmp_lvec->aData_num_of_iterations;
        char *tmp_adata = malloc(tmp_adata_n);
        
        for (size_t j = 0; j < tmp_lvec->aData_num_of_iterations; j++) {
            memcpy(&tmp_adata[j*tmp_lvec->aData_iterated_string_n], tmp_lvec->iterated_string, tmp_lvec->aData_iterated_string_n);
        }
        
        ccm_test_a_function(enc, dec,
                            tmp_lvec->key_n, tmp_lvec->key,
                            tmp_lvec->nonce_n, tmp_lvec->nonce,
                            tmp_lvec-> pdata_n, tmp_lvec->pdata,
                            tmp_lvec->enc_data,
                            tmp_adata_n, tmp_adata,
                            tmp_lvec->tag_n, tmp_lvec->tag,
                            ccccm_discrete);
        
        ccm_test_a_function(enc, dec,
                            tmp_lvec->key_n, tmp_lvec->key,
                            tmp_lvec->nonce_n, tmp_lvec->nonce,
                            tmp_lvec-> pdata_n,
                            tmp_lvec->pdata, tmp_lvec->enc_data,
                            tmp_adata_n, tmp_adata,
                            tmp_lvec->tag_n, tmp_lvec->tag,
                            ccccm_one_shot);
        
        if(verbose){
            printf("ccm_testcase %d\n", i);
        }
        
        free(tmp_adata);
    }
    
    return 1;
}

int test_ccm(const struct ccmode_ccm *encrypt_ciphermode, const struct ccmode_ccm *decrypt_ciphermode)
{
    ccm_testcase(encrypt_ciphermode, decrypt_ciphermode);
    return 1;
}


