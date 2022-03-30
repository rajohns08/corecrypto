/* Copyright (c) (2012,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"
#include "crypto_test_digest.h"
#include "cc_memory.h"

static int verbose = 0;

#if (CCDIGEST == 0)
entryPoint(ccdigest,"ccdigest test")
#else
#include <corecrypto/ccasn1.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccdigest_priv.h>
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccripemd.h>

/* Currently, ccdigest and friends won't work when length == 0 and the
 * data pointer is NULL.
 */

#define DIGEST_DATA_POINTER_NULL_TOLERANT 0

typedef struct test_vector_t {
    uint8_t *input;
    size_t len;
    uint8_t *md2_answer;
    uint8_t *md4_answer;
    uint8_t *md5_answer;
    uint8_t *sha1_answer;
    uint8_t *sha224_answer;
    uint8_t *sha256_answer;
    uint8_t *sha384_answer;
    uint8_t *sha512_answer;
    uint8_t *rmd160_answer;
    uint8_t *sha512_256_answer;
} test_vector;

static int test_answer(const struct ccdigest_info *di, test_vector *vector, void*answer) {
    uint8_t *correct_answer = NULL;
    if(ccdigest_oid_equal(di, CC_DIGEST_OID_MD2)) correct_answer = vector->md2_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD4)) correct_answer = vector->md4_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_MD5)) correct_answer = vector->md5_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA1)) correct_answer = vector->sha1_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA224)) correct_answer = vector->sha224_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA256)) correct_answer = vector->sha256_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA384)) correct_answer = vector->sha384_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA512)) correct_answer = vector->sha512_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_RMD160)) correct_answer = vector->rmd160_answer;
    else if(ccdigest_oid_equal(di,  CC_DIGEST_OID_SHA512_256)) correct_answer = vector->sha512_256_answer;
    if(correct_answer == NULL) {
        return 1;
    }
    byteBuffer answer_bb = bytesToBytes(answer, di->output_size);
    byteBuffer correct_answer_bb = hexStringToBytes((char *) correct_answer);
    ok(bytesAreEqual(correct_answer_bb, answer_bb), "compare memory of answer");
    if(bytesAreEqual(correct_answer_bb, answer_bb) == 0) {
        printByteBuffer(correct_answer_bb, "Correct Answer");
        printByteBuffer(answer_bb, "Provided Answer");
    }
    free(correct_answer_bb);
    free(answer_bb);
    return 1;
}

static int guard_ok(uint8_t *p, int chr, size_t len) {
    for(size_t i=0; i<len; i++) if(p[i] != chr) return 0;
    return 1;
}

static int test_discrete(const struct ccdigest_info *di, test_vector *vector) {
    uint8_t answer[128];
    size_t total = vector->len;
    size_t chunk = vector->len/2;
    uint8_t *p = vector->input;
    uint8_t ctxfrontguard[4096];
    ccdigest_di_decl(di, ctx);
    uint8_t ctxrearguard[4096];
    memset(ctxfrontguard, 0xee, 4096);
    memset(ctxrearguard, 0xee, 4096);
    // break it up into pieces.
    ccdigest_init(di, ctx);
    ok(guard_ok(ctxfrontguard, 0xee, 4096), "context is safe");
    ok(guard_ok(ctxrearguard, 0xee, 4096), "context is safe");
    do {
        ccdigest_update(di, ctx, chunk, p);
        total -= chunk;
        p += chunk;
        chunk /= 2;
        if(chunk == 0) chunk = total;
    } while(total);
    ok(guard_ok(ctxfrontguard, 0xee, 4096), "context is safe");
    ok(guard_ok(ctxrearguard, 0xee, 4096), "context is safe");

    ccdigest_final(di, ctx, answer);

    ok(guard_ok(ctxfrontguard, 0xee, 4096), "context is safe");
    ok(guard_ok(ctxrearguard, 0xee, 4096), "context is safe");
    ok(test_answer(di, vector, answer), "check answer");
    return 1;
}

static int test_oneshot(const struct ccdigest_info *di, test_vector *vector) {
    uint8_t answer[128];
    ccdigest(di, vector->len, vector->input, answer);
    ok(test_answer(di, vector, answer), "check answer");
    return 1;
}

static int test_digest_many_blocks(const struct ccdigest_info *di) {
    static const size_t buffer_size = 16383;
    static uint8_t buffer[buffer_size];
    static test_vector vector[] = {
        { buffer, buffer_size,
            (uint8_t *) "460825c272c70b141a24364117e1242e", //MD2
            (uint8_t *) "45eb5470a0e700ef2f47e408652792dc", //MD4
            (uint8_t *) "ef17d771a405e1effd7fb6a1f9950018", //MD5
            (uint8_t *) "217edfa45f521c1232e4cc2cacac29bf8a9d1e66", //SHA1
            (uint8_t *) "bfcef78f215b9682767c4ba7404379ef87012c4b7346631ccb965c2d", //SHA224
            (uint8_t *) "fab82f1352405c22ca2953ff80a508e5567c51e1a9aeb57cf9a56447e40ba066", //SHA256
            (uint8_t *) "220dfd6babc12b08f6f456133d52aa2975dfb50689de810ab0fa8cd9a7650218dc6afaf24f77f6b969f9ea7141f9aeb7", //SHA384
            (uint8_t *) "a238834f3693080d7cce3c44c7600e8a09311ba8e6059002bc67d4158430148abd2d8255afdf3b2f944fa5e1025dd6c4646f5dd9f6858ee1222a67430a24d491", //SHA512
            (uint8_t *) "d6cca8771842686d759d5778702c24bcc4d355e0", //RMD160
            (uint8_t *) "05a1178de8564d8c6a814bf1c3a4df3d0dde4aa4d491e77aae3958d2f93b6bd4", //SHA512/256
        },
    };
    int vector_size = sizeof (vector) / sizeof (test_vector);
    for(size_t n=0; n<buffer_size; n++) buffer[n] = n&0xff;
    if(verbose) diag("Digest Large Test");
    for(int i=0; i<vector_size; i++) {
        ok(test_oneshot(di, &vector[i]), "test one-shot with data less than blocksize");
        ok(test_discrete(di, &vector[i]), "test discrete with data less than blocksize");
    }
    return 1;
}

static int test_digest_eq_blocksize(const struct ccdigest_info *di) {
    static test_vector vector[] = {
        { (uint8_t *) "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", 128,
            (uint8_t *) "33a584d542532ca385fb9da278844fe1", //MD2
            (uint8_t *) "f7a45071e2b72f5ecbdec4e30342883a", //MD4
            (uint8_t *) "b63f67ab30bf8e5fcada5bd0ce610bf3", //MD5
            (uint8_t *) "82e0a30115ca91906859075062e59f25d3c42949", //SHA1
            (uint8_t *) "60ea0c511d336cbf383e67e139c5e4672e73536cc7cce168b90bbcf9", //SHA224
            (uint8_t *) "16f3e2071629d02b0ba9e4a43643f6976514ebd8b4b8f0f9ebf3bd7cde6463d8", //SHA256
            (uint8_t *) "7b61f365fe573d3691bef585f5c5862210223bfb08d9994762b6c54308a4f9934d8c35b3823255116c1e63f821bd794d", //SHA384
            (uint8_t *) "92fd0a1e6218274d4ab9824bf2be236ef8bdc5bd5fead472e04850f01aabcdfa8ecccc8d690fd86ae2295886ff26b4602e8f8651d12434a3cef0b4aff8ca13b4", //SHA512
            (uint8_t *) "4c06c1234bcf7345d1fda40ae79618ad35eca158", //RMD160
            (uint8_t *) "511edf1e6d14258ba4214f6e912a1c58946e98682e812fbcf10419341db378c2", //SHA512/256
        },
    };
    int vector_size = sizeof (vector) / sizeof (test_vector);
    if(verbose) diag("Digest EQ Test");
    for(int i=0; i<vector_size; i++) {
        ok(test_oneshot(di, &vector[i]), "test one-shot with data less than blocksize");
        ok(test_discrete(di, &vector[i]), "test discrete with data less than blocksize");
    }
    return 1;
}

static int test_digest_lt_blocksize(const struct ccdigest_info *di) {
    static test_vector vector[] = {
        { (uint8_t *) "Test vector from febooti.com", 28,
        (uint8_t *) "db128d6e0d20a1192a6bd1fade401150", //MD2
        (uint8_t *) "6578f2664bc56e0b5b3f85ed26ecc67b", //MD4
        (uint8_t *) "500ab6613c6db7fbd30c62f5ff573d0f", //MD5
        (uint8_t *) "a7631795f6d59cd6d14ebd0058a6394a4b93d868", //SHA1
        (uint8_t *) "3628b402254caa96827e3c79c0a559e4558da8ee2b65f1496578137d", //SHA224
        (uint8_t *) "077b18fe29036ada4890bdec192186e10678597a67880290521df70df4bac9ab", //SHA256
        (uint8_t *) "388bb2d487de48740f45fcb44152b0b665428c49def1aaf7c7f09a40c10aff1cd7c3fe3325193c4dd35d4eaa032f49b0", //SHA384
        (uint8_t *) "09fb898bc97319a243a63f6971747f8e102481fb8d5346c55cb44855adc2e0e98f304e552b0db1d4eeba8a5c8779f6a3010f0e1a2beb5b9547a13b6edca11e8a", //SHA512
        (uint8_t *) "4e1ff644ca9f6e86167ccb30ff27e0d84ceb2a61", //RMD160
        (uint8_t *) "beef461565a39d813810b5330b2987190dd6e24ec69e1a03d6f9705d01c1ad61", // SHA512/256
        },
    };
    int vector_size = sizeof (vector) / sizeof (test_vector);
    if(verbose) diag("Digest LT Test");

    for(int i=0; i<vector_size; i++) {
        ok(test_oneshot(di, &vector[i]), "test one-shot with data less than blocksize");
        ok(test_discrete(di, &vector[i]), "test discrete with data less than blocksize");
    }
    return 1;
}

static int test_digest_of_zero(const struct ccdigest_info *di) {
#if DIGEST_DATA_POINTER_NULL_TOLERANT
    static test_vector vectorNULL = { NULL, 0,
        (uint8_t *) "8350e5a3e24c153df2275c9f80692773", //MD2
        (uint8_t *) "31d6cfe0d16ae931b73c59d7e0c089c0", //MD4
        (uint8_t *) "d41d8cd98f00b204e9800998ecf8427e", //MD5
        (uint8_t *) "da39a3ee5e6b4b0d3255bfef95601890afd80709", //SHA1
        (uint8_t *) "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", //SHA224
        (uint8_t *) "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", //SHA256
        (uint8_t *) "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", //SHA384
        (uint8_t *) "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", //SHA512
        (uint8_t *) "9c1185a5c5e9fc54612808977ee8f548b2258d31", //RMD160
         (uint8_t *) "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", // SHA512/256
    };
#endif /* DIGEST_DATA_POINTER_NULL_TOLERANT */
    static test_vector vectorPOINTER = { (uint8_t *) "XXXX", 0,
        (uint8_t *) "8350e5a3e24c153df2275c9f80692773", //MD2
        (uint8_t *) "31d6cfe0d16ae931b73c59d7e0c089c0", //MD4
        (uint8_t *) "d41d8cd98f00b204e9800998ecf8427e", //MD5
        (uint8_t *) "da39a3ee5e6b4b0d3255bfef95601890afd80709", //SHA1
        (uint8_t *) "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", //SHA224
        (uint8_t *) "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", //SHA256
        (uint8_t *) "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", //SHA384
        (uint8_t *) "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", //SHA512
        (uint8_t *) "9c1185a5c5e9fc54612808977ee8f548b2258d31", //RMD160
        (uint8_t *) "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", // SHA512/256
    };
#if DIGEST_DATA_POINTER_NULL_TOLERANT
    if(verbose) diag("NULL-Oneshot");
    ok_or_fail(test_oneshot(di, &vectorNULL), "test one-shot with NULL pointer");
    ok_or_fail(test_discrete(di, &vectorNULL), "test discrete with NULL pointer");
#endif /* DIGEST_DATA_POINTER_NULL_TOLERANT */
    if(verbose) diag("Pointer-Oneshot");
    ok(test_oneshot(di, &vectorPOINTER), "test one-shot with live pointer");
    ok(test_discrete(di, &vectorPOINTER), "test discrete with live pointer");
    return 1;
}

static int test_corrupt_context(const struct ccdigest_info *di)
{
    uint8_t digest[di->output_size];
    uint8_t chunk[128] = { 0 };
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);

    // Corrupt the context.
    ccdigest_num(di, ctx) = 0xffffffff;
    ccdigest_update(di, ctx, sizeof(chunk), chunk);

    // Corrupt the context.
    ccdigest_num(di, ctx) = 0xffffffff;
    ccdigest_final(di, ctx, digest);

    // Sanity check the resulting digest.
    static test_vector vector = {
        NULL, 0, NULL, NULL,
        (uint8_t *) "f09f35a5637839458e462e6350ecbce4", //MD5
        (uint8_t *) "0ae4f711ef5d6e9d26c611fd2c8c8ac45ecbf9e7", //SHA1
        (uint8_t *) "2fbd823ebcd9909d265827e4bce793a4fc572e3f39c7c3dd67749f3e", //SHA224
        (uint8_t *) "38723a2e5e8a17aa7950dc008209944e898f69a7bd10a23c839d341e935fd5ca", //SHA256
        (uint8_t *) "f809b88323411f24a6f152e5e9d9d1b5466b77e0f3c7550f8b242c31b6e7b99bcb45bdecb6124bc23283db3b9fc4f5b3", //SHA384
        (uint8_t *) "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a552d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11", //SHA512
        NULL,
        (uint8_t *) "fe3d375e149b888e08e2521007764b422d2cd6f7b0606881b7fe1b1370d5fa88", //SHA512/256
    };

    ok(test_answer(di, &vector, digest), "Invalid digest");

    return 1;
}

// CHUNK_SIZE will be either (1 << 31) or (1 << 32), depending on size of size_t.
//
// * In the former case, (1 << 31) * 8 == (1 << 34), which would let
//   ccdigest_nbits() overflow if we don't perform 64-bit multiplication.
//
// * In the latter case, we ensure that the custom division routine works on
//   64-bit systems too.
#define CHUNK_SIZE (sizeof(size_t) << 29)
#define NUM_CHUNKS 8

// Check that nblocks was computed correctly.
static void custom1_compress(CC_UNUSED ccdigest_state_t state, size_t nblocks, CC_UNUSED const void *in)
{
    is(nblocks, CHUNK_SIZE / CCSHA1_BLOCK_SIZE, "nblocks is correct");
}

// Check that nblocks was computed correctly.
static void custom2_compress(CC_UNUSED ccdigest_state_t state, size_t nblocks, CC_UNUSED const void *in)
{
    is(nblocks, CHUNK_SIZE / CCSHA512_BLOCK_SIZE, "nblocks is correct");
}

// Check that .nbits contains the expected value.
static void custom_final(CC_UNUSED const struct ccdigest_info *di, ccdigest_ctx_t ctx, CC_UNUSED unsigned char *digest)
{
    is(ccdigest_nbits(di, ctx), (uint64_t)CHUNK_SIZE * NUM_CHUNKS * 8, "nbits is correct");
}

// An empty state.
const uint8_t custom_initial_state[CCSHA512_STATE_SIZE] = { 0 };

// A custom digest with a 512-bit block size.
const struct ccdigest_info custom1_di = {
    .output_size = CCSHA1_OUTPUT_SIZE,
    .state_size = CCSHA1_STATE_SIZE,
    .block_size = CCSHA1_BLOCK_SIZE,
    .oid_size = ccoid_sha1_len,
    .oid = CC_DIGEST_OID_SHA1,
    .initial_state = custom_initial_state,
    .compress = custom1_compress,
    .final = custom_final,
};

// A custom digest with a 1024-bit block size.
const struct ccdigest_info custom2_di = {
    .output_size = CCSHA512_OUTPUT_SIZE,
    .state_size = CCSHA512_STATE_SIZE,
    .block_size = CCSHA512_BLOCK_SIZE,
    .oid_size = ccoid_sha512_len,
    .oid = CC_DIGEST_OID_SHA512,
    .initial_state = custom_initial_state,
    .compress = custom2_compress,
    .final = custom_final,
};

static int test_huge_input(const struct ccdigest_info *di)
{
    ccdigest_di_decl(di, dc);
    ccdigest_init(di, dc);

    for (uint64_t l = 0; l < NUM_CHUNKS; l++) {
        ccdigest_update(di, dc, CHUNK_SIZE, NULL);
    }

    ccdigest_final(di, dc, NULL);
    return 1;
}

static int test_finalize(const struct ccdigest_info *di)
{
    uint8_t digest1[di->output_size];
    uint8_t digest2[di->output_size];
    uint8_t chunk1[128] = { 0 };
    uint8_t chunk2[256] = { 0 };

    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);

    ccdigest_update(di, ctx, sizeof(chunk1), chunk1);
    ccdigest_final(di, ctx, digest1);
    ccdigest_final(di, ctx, digest2);

    ok_memcmp(digest1, digest2, sizeof(digest1), "digests match");

    ccdigest_update(di, ctx, sizeof(chunk1), chunk1);
    ccdigest_final(di, ctx, digest1);

    ccdigest(di, sizeof(chunk2), chunk2, digest2);

    ok_memcmp(digest1, digest2, sizeof(digest1), "digests match");

    return 1;
}

static int test_digest(const struct ccdigest_info *di) {
    ok(test_digest_of_zero(di), "test_digest_of_zero");
    ok(test_digest_lt_blocksize(di), "test_digest_lt_blocksize");
    ok(test_digest_eq_blocksize(di), "test_digest_eq_blocksize");
    ok(test_digest_many_blocks(di), "test_digest_many_blocks");
    ok(test_corrupt_context(di), "test_corrupt_context");
    ok(test_finalize(di), "test_finalize");
    return 1;
}

int ccdigest_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    if(verbose) diag("Starting digest tests");
    int ntests = 956;
    ntests += 20; // test_huge_input
    ntests += 45; // test_finalize
    plan_tests(ntests);

    ok(test_huge_input(&custom1_di), "test_huge_input #1");
    ok(test_huge_input(&custom2_di), "test_huge_input #2");
    
    // Pure C version
    ok(test_digest(&ccmd2_ltc_di), "ccmd2_di");
    ok(test_digest(&ccmd4_ltc_di), "ccmd4_ltc_di");
    ok(test_digest(&ccmd5_ltc_di), "ccmd5_ltc_di");
    ok(test_digest(&ccsha1_ltc_di), "ccsha1_ltc_di");
    ok(test_digest(&ccsha1_eay_di), "ccsha1_eay_di");
    ok(test_digest(&ccsha224_ltc_di), "ccsha224_ltc_di");
    ok(test_digest(&ccsha256_ltc_di), "ccsha256_ltc_di");
    ok(test_digest(&ccsha384_ltc_di), "ccsha384_ltc_di");
    ok(test_digest(&ccsha512_ltc_di), "ccsha512_ltc_di");
    ok(test_digest(&ccrmd160_ltc_di), "ccrmd160_ltc_di");
    ok(test_digest(&ccsha512_256_ltc_di), "ccsha512_256_ltc_di");
    
    // Default (optimized)
    ok(test_digest(ccsha1_di()),   "Default ccsha1_di");
    ok(test_digest(ccsha224_di()), "Default ccsha224_di");
    ok(test_digest(ccsha256_di()), "Default ccsha256_di");
    ok(test_digest(ccsha384_di()), "Default ccsha384_di");
    ok(test_digest(ccsha512_di()), "Default ccsha512_di");
    ok(test_digest(ccsha512_256_di()), "Default ccsha512_256_di");

    //this is a standalone KAT test for sha256. It is used when clients have only sha256 available.
    ok(sha256_kat()==0, "sha256, standalone KAT");

    return 0;
}
#endif
