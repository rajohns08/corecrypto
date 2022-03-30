/* Copyright (c) (2010,2011,2012,2013,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/*
 * NIST SP 800-90 CTR_DRBG (Random Number Generator)
 */

/*
 In English, this is a Deterministic Random Bit Generator,
 a.k.a. Pseudo-Random Number Generator.

 Strictly speaking, a DRBG is the output stage of a PRNG that
 needs to be seeded from an entropy source. For a full discussion
 of DRBGs, look at NIST SP 800-90. You can search for it. They
 define DRBGs based on hash functions, HMACs, ciphers in counter
 mode, and elliptic curves. This is the cipher one, using AES.
 It's been written and tested with AES-128. It should be generic
 enough to use with AES-256, but is presently untested.

 A DRBG has four routines:
 instantiate()
 generate()
 reseed()
 destroy()

 Further discussion of each routine is below. This implements the
 DRBG with a derivation function, and is intended to be used with
 prediction resistance, but that has to be done in an upper level
 with the entropy source.

 The typical usage is that instantiate() creates the DRBG and
 feeds it its initial entropy, along with a nonce, and optional
 personalization information. The generate() function generates
 random bits. The reseed() function reseeds it with more entropy.
 The destroy() function clears and deallocates the structures.

 Note that while a DRBG is a "bit" generator, this package
 generates bytes. If you need less than a byte, extract it.

 A DRBG must be reseeded every so often. You can get the number
 of calls to it remaining before a mandatory reseed from
 CCADRBGGetReseedCountdown().

 Note that this DRBG is not thread-safe. Its callers must not
 only manage entropy for it, but they must use it appropriately.

 Fortunately, CommonRNG.[ch] has a nice implementation of all that,
 and is probably what you should be using.

 */

#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_internal.h>
#include <corecrypto/cc_priv.h>
#include "ccdrbg_nistctr.h"
#include "cc_debug.h" //cc_debug.h defines printf() used in cc_macroes.h both in DEBUG and CC_KERNEL modes
#include <corecrypto/cc_macros.h>

#define DRBG_NISTCTR_DEBUG 0

// The NIST CTR_DRBG is technically only specified for AES and three-key TDEA,
// so AES is the biggest block we require.
// Reserve eight blocks to take advantage of parallel implementations of AES.
static const uint8_t zeros[CCAES_BLOCK_SIZE * CCAES_CTR_MAX_PARALLEL_NBLOCKS];

// A sort of hacky method for direct blockcipher encryption.
// Without this, we'd need descriptors for both an ECB and a CTR mode,
// and we'd need to ensure they use the same blockcipher.
static void block_encrypt(const struct ccmode_ctr *info, ccctr_ctx *ctx, const void *in, void *out)
{
    ccctr_setctr(info, ctx, in);
    ccctr_update(info, ctx, info->ecb_block_size, zeros, out);
}

/*
 * NIST SP 800-90 March 2007
 * 10.4.3 BCC Function
 */
static void bcc_update(struct ccdrbg_nistctr_state *drbg, const void *data, size_t n, void *chaining_value)
{
    size_t i;
    const uint8_t *data_bytes = data;

    // This is basically computing a CBC-MAC.
    // Maybe we can replace it with our CBC-MAC implementation someday.

    /* [4] for i = 1 to n */
    for (i = 0; i < n; ++i) {
        /* [4.1] input_block = chaining_value XOR block_i */
        cc_xor(CCADRBG_OUTLEN(drbg), chaining_value, chaining_value, data_bytes);
        data_bytes += CCADRBG_OUTLEN(drbg);

        /* [4.2] chaining_value = Block_Encrypt(Key, input_block) */
        block_encrypt(drbg->ctr_info, drbg->df_key, chaining_value, chaining_value);
    }

    /* [5] output_block = chaining_value */
    /* chaining_value already is output_block, so no copy is required */
}

static void bcc(struct ccdrbg_nistctr_state *drbg, const void *data, size_t n, void *output_block)
{
    /* [1] chaining_value = 0^outlen */
    cc_clear(CCADRBG_OUTLEN(drbg), output_block);

    bcc_update(drbg, data, n, output_block);
}

/*
 * NIST SP 800-90 March 2007
 * 10.4.2 Derivation Function Using a Block Cipher Algorithm
 */

static __inline int check_int_alignment(const void *p)
{
    /*
     * It would be great if "intptr_t" could be found in
     * some standard place.
     */
    intptr_t ip = (const char *)p - (const char *)0;

    if (ip & (intptr_t)(sizeof(int) - 1))
        return 0;

    return 1;
}

static void df_bcc_update(struct ccdrbg_nistctr_state *drbg, const char *input_string, size_t input_string_length, uint32_t *temp)
{
    size_t i, len;
    _CCADRBG_BCC *ctx = &drbg->bcc;
    size_t idx = ctx->index;
    uint8_t *S = (uint8_t *)ctx->S;

    if (idx) {
        cc_assert(idx < CCADRBG_OUTLEN(drbg));
        len = CCADRBG_OUTLEN(drbg) - idx;
        if (input_string_length < len)
            len = input_string_length;

        cc_memcpy(&S[idx], input_string, len);

        cc_assert(len <= 0xFFFFffff);
        idx += len;
        input_string += len;
        input_string_length -= len;

        if (idx < CCADRBG_OUTLEN(drbg)) {
            ctx->index = idx;
            return;
        }

        /* We have a full block in S, so let's process it */
        /* [9.2] BCC */
        bcc_update(drbg, ctx->S, 1, temp);
        idx = 0;
    }

    /* ctx->S is empty, so let's handle as many input blocks as we can */
    len = input_string_length / CCADRBG_OUTLEN(drbg);
    if (len > 0) {
#if 1
        if (check_int_alignment(input_string)) {
            /* [9.2] BCC */
            bcc_update(drbg, (const uint32_t *)input_string, len, temp);

            input_string += len * CCADRBG_OUTLEN(drbg);
            input_string_length -= len * CCADRBG_OUTLEN(drbg);
        } else
#endif
        {
            for (i = 0; i < len; ++i) {
                cc_memcpy(&S[0], input_string, CCADRBG_OUTLEN(drbg));

                /* [9.2] BCC */
                bcc_update(drbg, ctx->S, 1, temp);

                input_string += CCADRBG_OUTLEN(drbg);
                input_string_length -= CCADRBG_OUTLEN(drbg);
            }
        }
    }

    cc_assert(input_string_length < CCADRBG_OUTLEN(drbg));

    if (input_string_length) {
        cc_memcpy(&S[0], input_string, input_string_length);
        idx = input_string_length;
    }

    ctx->index = idx;
}

static void bcc_init(struct ccdrbg_nistctr_state *drbg, uint32_t L, uint32_t N, uint32_t *temp)
{
    uint32_t S[2];

    drbg->bcc.index = 0;

    /* [4] S = L || N || input_string || 0x80 */
    S[0] = CC_H2BE32(L);
    S[1] = CC_H2BE32(N);

    df_bcc_update(drbg, (const char *)S, sizeof(S), temp);
}

static void df_bcc_final(struct ccdrbg_nistctr_state *drbg, uint32_t *temp)
{
    size_t idx;
    _CCADRBG_BCC *ctx = &drbg->bcc;
    static const char endmark[] = { (char)0x80 };
    uint8_t *S = (uint8_t *)ctx->S;

    df_bcc_update(drbg, endmark, sizeof(endmark), temp);

    idx = ctx->index;
    if (idx) {
        cc_clear(CCADRBG_OUTLEN(drbg) - idx, &S[idx]);

        /* [9.2] BCC */
        bcc_update(drbg, S, 1, temp);
    }
}

static int df(struct ccdrbg_nistctr_state *drbg,
              const char *input_string[],
              uint32_t L[],
              uint32_t input_string_count,
              uint8_t *output_string,
              size_t N)
{
    size_t j, k, blocks;
    uint64_t sum_L;
    uint32_t *temp;
    uint32_t *X;
    uint32_t buffer[CCADRBG_TEMPLEN_INTS(drbg)];
    /* declare a key */
    ccctr_ctx_decl(drbg->ctr_info->size, key);

    /*
     * NIST SP 800-90 March 2007 10.4.2 states that 512 bits is
     * the maximum length for the approved block cipher algorithms.
     *
     * Also states that L(sum_L) and N are 32 bits integers.
     */
    cc_assert(drbg->ctr_info->ecb_block_size <= 512 / 8);
    uint32_t output_buffer[512 / 8 / sizeof(uint32_t)];

    if (N > sizeof(output_buffer) || N < 1) {
        ccctr_ctx_clear(drbg->ctr_info->size, key);
        return -1;
    }

    sum_L = 0;
    for (j = 0; j < input_string_count; ++j)
        sum_L += L[j];
    // sum_L is the sum of the all input data-lengths. Since maximum parameters lengths are set properly
    // in the header file, sum_L cannot be more than 32 bits. But a change to those parameters by
    // someone who is not aware of this summation here, would be a disaster.
    // Therefore, we make sum_L 64 bits and we perform the test here.
    if (sum_L > 0xFFFFffff)
        return -1;

    /* [6] temp = Null string */
    temp = buffer;

    /* [9] while len(temp) < keylen + outlen, do */
    for (j = 0; j < CCADRBG_TEMPLEN_BLOCKS(drbg); ++j) {
        /* [9.2] temp = temp || BCC(K, (IV || S)) */

        /* Since we have precomputed BCC(K, IV), we start with that... */
        cc_memcpy(&temp[0], &drbg->encryptedIV[j * CCADRBG_OUTLEN(drbg) + 0], CCADRBG_OUTLEN(drbg));

        /* typecast: ok, checks above */
        bcc_init(drbg, (uint32_t)sum_L, (uint32_t)N, temp);

        /* Compute the rest of BCC(K, (IV || S)) */
        for (k = 0; k < input_string_count; ++k)
            df_bcc_update(drbg, input_string[k], L[k], temp);

        df_bcc_final(drbg, temp);

        temp += CCADRBG_OUTLEN_INTS(drbg);
    }

    /* [6] temp = Null string */
    temp = buffer;

    /* [10] K = Leftmost keylen bits of temp */
    ccctr_init(drbg->ctr_info, key, CCADRBG_KEYLEN(drbg), &temp[0], zeros);

    /* [11] X = next outlen bits of temp */
    X = &temp[CCADRBG_KEYLEN_INTS(drbg)];

    /* [12] temp = Null string */
    temp = output_buffer;

    /* [13] While len(temp) < number_of_bits_to_return, do */
    blocks = (N / CCADRBG_OUTLEN(drbg));
    if (N & (CCADRBG_OUTLEN(drbg) - 1))
        ++blocks;
    for (j = 0; j < blocks; ++j) {
        /* [13.1] X = Block_Encrypt(K, X) */
        block_encrypt(drbg->ctr_info, key, X, temp);
        X = temp;
        temp += CCADRBG_OUTLEN_INTS(drbg);
    }

    /* [14] requested_bits = Leftmost number_of_bits_to_return of temp */
    cc_memcpy(output_string, output_buffer, N);
    ccctr_ctx_clear(drbg->ctr_info->size, key);
    cc_clear(sizeof(buffer), buffer);
    cc_clear(sizeof(output_buffer), output_buffer);

    return 0;
}

static void df_initialize(struct ccdrbg_nistctr_state *drbg)
{
    uint32_t i;
    uint8_t K[CCADRBG_KEYLEN(drbg)];
    uint32_t IV[CCADRBG_OUTLEN_INTS(drbg)];

    /* [8] K = Leftmost keylen bits of 0x00010203 ... 1D1E1F */
    for (i = 0; i < sizeof(K); ++i)
        K[i] = (uint8_t)i;

    ccctr_init(drbg->ctr_info, drbg->df_key, sizeof(K), K, zeros);

    /*
     * Precompute the partial BCC result from encrypting the IVs:
     *     encryptedIV[i] = BCC(K, IV(i))
     */

    /* [7] i = 0 */
    /* [9.1] IV = i || 0^(outlen - len(i)) */
    cc_clear(sizeof(IV), &IV[0]);

    /* [9.3] i = i + 1 */
    for (i = 0; i < CCADRBG_TEMPLEN_BLOCKS(drbg); ++i) {
        /* [9.1] IV = i || 0^(outlen - len(i)) */
        IV[0] = CC_H2BE32(i);

        /* [9.2] temp = temp || BCC(K, (IV || S))  (the IV part, at least) */
        bcc(drbg, &IV[0], 1, (uint32_t *)&drbg->encryptedIV[i * CCADRBG_OUTLEN(drbg) + 0]);
    }
}

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.2 The Update Function
 */
static int drbg_update(struct ccdrbg_nistctr_state *drbg, const uint8_t *provided_data, CC_UNUSED int isInit)
{
    uint8_t temp[CCADRBG_TEMPLEN(drbg)];
    int rc = CCDRBG_STATUS_ERROR;

    /* Clear temp buffer */
    cc_clear(sizeof(temp), temp);

    // This might leave us unaligned (i.e. with cached bytes in the key stream), but it's fine because we're about to rekey.
    ccctr_update(drbg->ctr_info, drbg->key, CCADRBG_SEEDLEN(drbg), zeros, temp);

    // check that the two halves are not the same.
    unsigned char *tempPtr = (unsigned char *)temp;
    size_t tempLen = CCADRBG_SEEDLEN(drbg);
    if (!cc_cmp_safe(tempLen / 2, tempPtr, tempPtr + (tempLen / 2))) {
        cc_clear(sizeof(temp), temp);
        return CCDRBG_STATUS_ERROR;
    }

    /* 3 temp is already of size seedlen (CCADRBG_SEEDLEN) */

    /* 4 temp = temp XOR provided_data */
    cc_xor(CCADRBG_SEEDLEN(drbg), temp, temp, provided_data);

    cc_memcpy(drbg->V, temp + CCADRBG_KEYLEN(drbg), CCADRBG_OUTLEN(drbg));

    // Increment V here to accommodate the difference between the NIST spec (pre-increment) and our CTR implementation
    // (post-increment). IMPORTANT: this MUST match the behavior of our CTR implementation, i.e. it must increment only the
    // rightmost 64 bits.
    inc_uint(drbg->V + CCADRBG_OUTLEN(drbg) - CCADRBG_CTRLEN, CCADRBG_CTRLEN);

    /* 5 Key = leftmost keylen bits of temp */
    ccctr_init(drbg->ctr_info, drbg->key, CCADRBG_KEYLEN(drbg), temp, drbg->V);

    rc = CCDRBG_STATUS_OK;

    cc_clear(sizeof(temp), temp);
    return rc;
}

// make sure drbg is initialized, before calling this function
static int
validate_inputs(struct ccdrbg_nistctr_state *drbg, size_t entropy_nbytes, size_t additionalInput_nbytes, size_t ps_nbytes)
{
    int rc = CCDRBG_STATUS_PARAM_ERROR;

    cc_require(drbg->keylen <= CCADRBG_MAX_KEYLEN, end); // keylen too long
    cc_require(drbg->ctr_info->ecb_block_size == CCAES_BLOCK_SIZE, end); // only AES is supported

    // NIST SP800 compliance checks
    if (drbg->use_df) {
        cc_require(ps_nbytes <= CCDRBG_MAX_PSINPUT_SIZE, end);                      // personalization string too long
        cc_require(entropy_nbytes <= CCDRBG_MAX_ENTROPY_SIZE, end);                 // supplied too much entropy
        cc_require(additionalInput_nbytes <= CCDRBG_MAX_ADDITIONALINPUT_SIZE, end); // additional input too long
        cc_require(entropy_nbytes >= drbg->ctr_info->ecb_block_size, end);          // supplied too litle entropy
    } else {
        size_t seedlen = CCADRBG_SEEDLEN(drbg); // outlen + keylen

        cc_require(ps_nbytes <= seedlen, end);              // personalization string too long
        cc_require(entropy_nbytes == seedlen, end);         // supplied too much or too little entropy
        cc_require(additionalInput_nbytes <= seedlen, end); // additional input too long
    }

    rc = CCDRBG_STATUS_OK;
end:
    return rc;
}

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.4.2 The Process Steps for Reseeding When a Derivation
 *            Function is Used
 */
static int
reseed(struct ccdrbg_state *rng, size_t entropy_nbytes, const void *entropy, size_t additional_nbytes, const void *additional)
{
    int err;
    uint32_t count;
    const char *input_string[2];
    uint32_t length[2];
    struct ccdrbg_nistctr_state *drbg = (struct ccdrbg_nistctr_state *)rng;
    uint8_t seed_material[CCADRBG_SEEDLEN(drbg)];

    err = validate_inputs(drbg, entropy_nbytes, additional_nbytes, 0);
    if (err != CCDRBG_STATUS_OK)
        return err;

    if (drbg->use_df) {
        /* [1] seed_material = entropy || additional */
        input_string[0] = entropy;
        /* typecast: guaranteed to fit by the above checks */
        length[0] = (uint32_t)entropy_nbytes;
        count = 1;

        if (additional && additional_nbytes) {
            input_string[count] = additional;
            /* typecast: guaranteed to fit by above checks */
            length[count] = (uint32_t)additional_nbytes;
            ++count;
        }

        /* [2] seed_material = Block_Cipher_df(seed_material, seedlen) */
        err = df(drbg, input_string, length, count, (uint8_t *)seed_material, sizeof(seed_material));
        if (err)
            return err;
    } else {
        cc_clear(sizeof(seed_material), seed_material);
        if (additional && additional_nbytes) {
            // additional_nbytes <= seedlen validated in validate_inputs
            cc_assert(additional_nbytes <= sizeof(seed_material));
            cc_memcpy(seed_material, additional, additional_nbytes);
        }
        cc_xor(CCADRBG_SEEDLEN(drbg), seed_material, seed_material, entropy);
    }

    /* [3] (Key, V) = Update(seed_material, Key, V) */
    if (drbg_update(drbg, seed_material, 0)) {
        return CCDRBG_STATUS_PARAM_ERROR;
    }

    /* [4] reseed_counter = 1 */
    drbg->reseed_counter = 1;

    return CCDRBG_STATUS_OK;
}

static void done(struct ccdrbg_state *rng)
{
    struct ccdrbg_nistctr_state *drbg = (struct ccdrbg_nistctr_state *)rng;
    size_t bs = drbg->ctr_info->ecb_block_size;
    cc_clear((((drbg->keylen + bs * 2 - 1) / bs) * bs), drbg->encryptedIV);
    cc_clear(bs, drbg->V);
    cc_clear(bs, drbg->bcc.S);
    ccctr_ctx_clear(drbg->ctr_info->size, drbg->key);
    ccctr_ctx_clear(drbg->ctr_info->size, drbg->df_key);

    cc_clear(sizeof(*drbg), drbg);

    // Possibly superfluous, but NIST wants it.
    drbg->reseed_counter = UINT32_MAX;
}

static int validate_gen_params(struct ccdrbg_nistctr_state *drbg, size_t dataOut_nbytes, size_t additional_nbytes)
{
    int rc = CCDRBG_STATUS_PARAM_ERROR;

    // Zero byte in one request is a valid use-case (21208820)
    cc_require(dataOut_nbytes <= CCDRBG_MAX_REQUEST_SIZE, end); // Requested too many bytes in one request

    size_t max = drbg->use_df ? CCDRBG_MAX_ADDITIONALINPUT_SIZE : CCADRBG_SEEDLEN(drbg);
    cc_require(additional_nbytes <= max, end); // Additional input too long

    // 1. If (reseed_counter > 2^^48), then Return (“Reseed required”, Null, V, Key, reseed_counter).
    cc_static_assert(sizeof(drbg->reseed_counter) >= 8, "Reseed counter must be uint64"); // make sure it fits 2^48
    rc = CCDRBG_STATUS_NEED_RESEED;
    cc_require(drbg->reseed_counter <= CCDRBG_RESEED_INTERVAL || !drbg->strictFIPS, end); // Reseed required

    rc = CCDRBG_STATUS_OK;
end:
    return rc;
}

static int generate(struct ccdrbg_state *rng, size_t out_nbytes, void *out, size_t additional_nbytes, const void *additional)
{
    int rc = CCDRBG_STATUS_OK;
    uint8_t *out_bytes;
    size_t nbytes;
    const char *input_string[1];
    uint32_t length[1];
    struct ccdrbg_nistctr_state *drbg = (struct ccdrbg_nistctr_state *)rng;
    uint8_t additional_buffer[CCADRBG_SEEDLEN(drbg)];
    uint8_t remainder[CCADRBG_OUTLEN(drbg)];
    size_t remainder_nbytes;

    /* [1] If reseed_counter > reseed_interval ... */
    rc = validate_gen_params(drbg, out_nbytes, (additional != NULL) ? additional_nbytes : 0);
    cc_require(rc == CCDRBG_STATUS_OK, errOut);

    /* [2] If (addional_input != Null), then */
    if (additional && additional_nbytes) {
        if (drbg->use_df) {
            input_string[0] = additional;
            /* typecast: guaranteed to fit by the checks above */
            length[0] = (uint32_t)additional_nbytes;
            /* [2.1] additional = Block_Cipher_df(additional, seedlen) */
            rc = df(drbg, input_string, length, 1, (uint8_t *)additional_buffer, sizeof(additional_buffer));
            cc_require(rc == CCDRBG_STATUS_OK, errOut);
        } else {
            cc_clear(sizeof(additional_buffer), additional_buffer);
            cc_assert(additional_nbytes == 0 ||
                      additional_nbytes == sizeof(additional_buffer)); // additional_nbytes is validated above
            cc_memcpy(additional_buffer, additional, additional_nbytes);
        }

        /* [2.2] (Key, V) = Update(additional, Key, V) */
        rc = drbg_update(drbg, additional_buffer, 0);
        cc_require(rc == CCDRBG_STATUS_OK, errOut);
    }

    /* [3]-[5] */
    out_bytes = out;
    remainder_nbytes = (16 - (out_nbytes % 16)) % 16;
    while (out_nbytes > 0) {
        nbytes = CC_MIN(sizeof(zeros), out_nbytes);
        ccctr_update(drbg->ctr_info, drbg->key, nbytes, zeros, out_bytes);
        out_nbytes -= nbytes;
        out_bytes += nbytes;
    }

    // Need to discard the remainder of the block, if any.
    ccctr_update(drbg->ctr_info, drbg->key, remainder_nbytes, zeros, remainder);
    cc_clear(remainder_nbytes, remainder);

    /* [6] (Key, V) = Update(additional, Key, V) */
    rc = drbg_update(drbg, additional && additional_nbytes ? additional_buffer : zeros, 0);
    cc_require(rc == CCDRBG_STATUS_OK, errOut);

    /* [7] reseed_counter = reseed_counter + 1 */
    drbg->reseed_counter += 1;

errOut:
    cc_clear(sizeof(additional_buffer), additional_buffer);
    return rc;
}

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.3.2 The Process Steps for Instantiation When a Derivation
 *            Function is Used
 */

// length of input personalization string ps might be zero
// nonce is not validated, caller needs to make sure nonce is right as per NIST 800-90A section 8.6.7

static int nistctr_init(const struct ccdrbg_nistctr_custom *custom,
                        struct ccdrbg_nistctr_state *drbg,
                        char *keys,
                        const void *entropy,
                        size_t entropy_nbytes,
                        const void *nonce,
                        size_t nonce_nbytes,
                        const void *ps,
                        size_t ps_nbytes)
{
    int err;
    uint32_t count;
    char *buf;

    drbg->ctr_info = custom->ctr_info;
    drbg->keylen = custom->keylen;
    buf = keys;

    size_t bs = drbg->ctr_info->ecb_block_size;
    drbg->encryptedIV = (uint8_t *)buf;
    buf += ((drbg->keylen + bs * 2 - 1) / bs) * bs;
    drbg->V = (uint8_t *)buf;
    buf += bs; // CCADRBG_OUTLEN(drbg);
    drbg->bcc.S = (uint8_t *)buf;
    buf += bs; // CCADRBG_OUTLEN(drbg);
    drbg->key = (ccctr_ctx *)buf;
    buf += drbg->ctr_info->size;
    drbg->df_key = (ccctr_ctx *)buf; // buf+=drbg->ecb->size;

    // First initialize the struct
    drbg->strictFIPS = custom->strictFIPS;
    drbg->use_df = custom->use_df;

    // Reseed counter is set in [6] below.
    // V is set in [4] and [5]

    // Initialize the derivation function
    //

    // nonce is not checked, caller needs to make sure nonce is right as per NIST 800-90A section 8.6.7
    int rc = validate_inputs(drbg, entropy_nbytes, 0, ps_nbytes);
    if (rc != CCDRBG_STATUS_OK) {
        done((struct ccdrbg_state *)drbg);
        return rc;
    }

    uint8_t K[CCADRBG_KEYLEN(drbg)];
    uint8_t seed_material[CCADRBG_SEEDLEN(drbg)];

    if (drbg->use_df) {
        uint32_t length[3];
        const char *input_string[3];

        df_initialize(drbg);

        /* [1] seed_material = entropy || nonce || ps */

        input_string[0] = entropy;
        /* typecast: guaranteed to fit by above checks */
        length[0] = (uint32_t)entropy_nbytes;

        input_string[1] = nonce;
        /* typecast: guaranteed to fit by above checks */
        length[1] = (uint32_t)nonce_nbytes;

        count = 2;
        if (ps && ps_nbytes) {
            input_string[count] = ps;
            /* typecast: guaranteed to fit by above checks */
            length[count] = (uint32_t)ps_nbytes;
            ++count;
        }
        /* [2] seed_material = Block_Cipher_df(seed_material, seedlen) */
        err = df(drbg, input_string, length, count, (uint8_t *)seed_material, sizeof(seed_material));
        if (err) {
            cc_clear(sizeof(seed_material), seed_material);
            done((struct ccdrbg_state *)drbg);
            return err;
        }

    } else {
        cc_clear(sizeof(seed_material), seed_material);
        if (ps && ps_nbytes) {
            // ps_nbytes <= seedlen validated in validate_inputs
            cc_assert(ps_nbytes <= sizeof(seed_material));
            cc_memcpy(seed_material, ps, ps_nbytes);
        }
        cc_xor(CCADRBG_SEEDLEN(drbg), seed_material, seed_material, entropy);
    }

    /* [3] Key = 0^keylen */
    cc_clear(sizeof(K), K);

    /* [4] V = 0^outlen */
    cc_clear(CCADRBG_OUTLEN(drbg), drbg->V);
    // to accommodate pre-increment v. post-increment
    drbg->V[CCADRBG_OUTLEN(drbg) - 1] = 1;

    ccctr_init(drbg->ctr_info, drbg->key, sizeof(K), K, drbg->V);

    /* [5] (Key, V) = Update(seed_material, Key, V) */
    if (drbg_update(drbg, seed_material, 1)) {
        cc_clear(sizeof(seed_material), seed_material);
        done((struct ccdrbg_state *)drbg);
        return CCDRBG_STATUS_PARAM_ERROR;
    }
    cc_clear(sizeof(seed_material), seed_material);

    /* [6] reseed_counter = 1 */
    drbg->reseed_counter = 1;

    return CCDRBG_STATUS_OK;
}

static int init(const struct ccdrbg_info *info,
                struct ccdrbg_state *drbg,
                size_t entropy_nbytes,
                const void *entropy,
                size_t nonce_nbytes,
                const void *nonce,
                size_t ps_nbytes,
                const void *ps)
{
    struct ccdrbg_nistctr_state *prng = (struct ccdrbg_nistctr_state *)drbg;
    const struct ccdrbg_nistctr_custom *custom = info->custom;

    char *keys = (char *)(prng + 1);

    return nistctr_init(custom, prng, keys, entropy, entropy_nbytes, nonce, nonce_nbytes, ps, ps_nbytes);
}

/* This initialize an info object with the right options */
void ccdrbg_factory_nistctr(struct ccdrbg_info *info, const struct ccdrbg_nistctr_custom *custom)
{
    info->size = sizeof(struct ccdrbg_nistctr_state) + CCDRBG_NISTCTR_SIZE(custom->ctr_info, custom->keylen);
    info->init = init;
    info->generate = generate;
    info->reseed = reseed;
    info->done = done;
    info->custom = custom;
};
