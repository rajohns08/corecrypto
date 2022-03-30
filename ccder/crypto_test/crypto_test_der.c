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

#ifndef CCDER_MULTIBYTE_TAGS
#define CCDER_MULTIBYTE_TAGS 1
#endif // CCDER_MULTIBYTE_TAGS

#include "testmore.h"
#include "testbyteBuffer.h"
#include "crypto_test_der.h"
#include <corecrypto/ccder.h>

#if (CCDER == 0)
entryPoint(ccder_tests, "ccder")
#else

//============================= ccder_sizeof ===================================

static void testSizeOf()
{
    is(ccder_sizeof(CCDER_EOL, 0), (size_t)2, "EOL");
    is(ccder_sizeof(CCDER_BOOLEAN, 0), (size_t)2, "BOOLEAN");
    is(ccder_sizeof(CCDER_INTEGER, 0), (size_t)2, "INTEGER");
    is(ccder_sizeof(CCDER_BIT_STRING, 0), (size_t)2, "BIT_STRING");
    is(ccder_sizeof(CCDER_OCTET_STRING, 0), (size_t)2, "OCTET_STRING");
    is(ccder_sizeof(CCDER_NULL, 0), (size_t)2, "NULL");
    is(ccder_sizeof(CCDER_OBJECT_IDENTIFIER, 0), (size_t)2, "OBJECT_IDENTIFIER");
    is(ccder_sizeof(CCDER_REAL, 0), (size_t)2, "REAL");
    is(ccder_sizeof(CCDER_ENUMERATED, 0), (size_t)2, "ENUMERATED");
    is(ccder_sizeof(CCDER_EMBEDDED_PDV, 0), (size_t)2, "EMBEDDED_PDV");
    is(ccder_sizeof(CCDER_UTF8_STRING, 0), (size_t)2, "UTF8_STRING");
    is(ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE, 0), (size_t)2, "CONSTRUCTED_SEQUENCE");
    is(ccder_sizeof(CCDER_CONSTRUCTED_SET, 0), (size_t)2, "CONSTRUCTED_SET");
    is(ccder_sizeof(CCDER_NUMERIC_STRING, 0), (size_t)2, "NUMERIC_STRING");
    is(ccder_sizeof(CCDER_PRINTABLE_STRING, 0), (size_t)2, "PRINTABLE_STRING");
    is(ccder_sizeof(CCDER_T61_STRING, 0), (size_t)2, "T61_STRING");
    is(ccder_sizeof(CCDER_VIDEOTEX_STRING, 0), (size_t)2, "VIDEOTEX_STRING");
    is(ccder_sizeof(CCDER_IA5_STRING, 0), (size_t)2, "IA5_STRING");
    is(ccder_sizeof(CCDER_UTC_TIME, 0), (size_t)2, "UTC_TIME");
    is(ccder_sizeof(CCDER_GENERALIZED_TIME, 0), (size_t)2, "GENERALIZED_TIME");
    is(ccder_sizeof(CCDER_GRAPHIC_STRING, 0), (size_t)2, "GRAPHIC_STRING");
    is(ccder_sizeof(CCDER_VISIBLE_STRING, 0), (size_t)2, "VISIBLE_STRING");
    is(ccder_sizeof(CCDER_GENERAL_STRING, 0), (size_t)2, "GENERAL_STRING");
    is(ccder_sizeof(CCDER_UNIVERSAL_STRING, 0), (size_t)2, "UNIVERSAL_STRING");
    is(ccder_sizeof(CCDER_BMP_STRING, 0), (size_t)2, "BMP_STRING");
    is(ccder_sizeof(CCDER_HIGH_TAG_NUMBER, 0), (size_t)3, "HIGH_TAG_NUMBER");
    is(ccder_sizeof(0x1f, 0), (size_t)3, "[31]");
    is(ccder_sizeof(0x20, 0), (size_t)3, "[32]");
    is(ccder_sizeof(0x7f, 0), (size_t)3, "[127]");
    is(ccder_sizeof(0x80, 0), (size_t)4, "[128]");
    is(ccder_sizeof(0x3fff, 0), (size_t)4, "[4095]");
    is(ccder_sizeof(0x4000, 0), (size_t)5, "[4096]");
    is(ccder_sizeof(0x1fffff, 0), (size_t)5, "[2097151]");
    is(ccder_sizeof(0x200000, 0), (size_t)6, "[2097152]");

    is(ccder_sizeof(CCDER_OCTET_STRING, 1), (size_t)3, "OCTET_STRING(1)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 127), (size_t)129, "OCTET_STRING(127)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 128), (size_t)131, "OCTET_STRING(128)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 128), (size_t)131, "OCTET_STRING(129)");
}

//============================= ccder_sizeof_uint64 ============================

static void testSizeOfUInt64()
{
    is(ccder_sizeof_uint64(0), (size_t)3, "uint64(0)");
    is(ccder_sizeof_uint64(1), (size_t)3, "uint64(1)");
    is(ccder_sizeof_uint64(0x7f), (size_t)3, "uint64(0x7f)");
    is(ccder_sizeof_uint64(0x80), (size_t)4, "uint64(0x80)");
    is(ccder_sizeof_uint64(0x100), (size_t)4, "uint64(0x100)");
    is(ccder_sizeof_uint64(0x7fff), (size_t)4, "uint64(0x7fff)");
    is(ccder_sizeof_uint64(0x8000), (size_t)5, "uint64(0x8000)");
    is(ccder_sizeof_uint64(0x7fffff), (size_t)5, "uint64(0x7fffff)");
    is(ccder_sizeof_uint64(0x800000), (size_t)6, "uint64(0x800000)");
    is(ccder_sizeof_uint64(0x7fffffff), (size_t)6, "uint64(0x7fffffff)");
    is(ccder_sizeof_uint64(0x80000000), (size_t)7, "uint64(0x80000000)");
    is(ccder_sizeof_uint64(0x7fffffffff), (size_t)7, "uint64(0x7fffffffff)");
    is(ccder_sizeof_uint64(0x8000000000), (size_t)8, "uint64(0x8000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffff), (size_t)8, "uint64(0x7fffffffffff)");
    is(ccder_sizeof_uint64(0x800000000000), (size_t)9, "uint64(0x800000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffffff), (size_t)9, "uint64(0x7fffffffffffff)");
    is(ccder_sizeof_uint64(0x80000000000000), (size_t)10, "uint64(0x80000000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffffffff), (size_t)10, "uint64(0x7fffffffffffffff)");
}

//================================ ccder_encode_tag ============================

static void testEncodeTag(void)
{
    // These define the length bounds for tags
    unsigned long limits[] = {0x7f, 0x3fff, 0x1fffff, 0xfffffff, 0x10000000};
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        ccder_tag tag = limits[i] & CCDER_TAGNUM_MASK;

        size_t length = i + 1; // this length is too short
        uint8_t *invalid_der = malloc(length);
        if (invalid_der) {
            uint8_t *der_start = invalid_der;
            uint8_t *der_end = invalid_der + length;
            uint8_t *new_der_end = ccder_encode_tag(tag, der_start, der_end);
            is(new_der_end, NULL, "ccder_encode_tag");
            free(invalid_der);
        }

        length = i + 2;
        uint8_t *valid_der = malloc(length);
        if (valid_der) {
            uint8_t *der_start = valid_der;
            uint8_t *der_end = valid_der + length;
            uint8_t *new_der_end = ccder_encode_tag(tag, der_start, der_end);
            isnt(new_der_end, NULL, "ccder_encode_tag");

            // We decode the first octet length, and then n, depending on what tag length we're decoding
            is(new_der_end, der_end - (i + 2), "ccder_encode_tag expected %p, got %p", der_end - (i + 2), new_der_end);
            free(valid_der);
        }
    }
}

//================================ ccder_encode_len ============================

static int testEncodeLen(void)
{
    uint8_t tmp[5];

    // 1 byte
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result1[5]={0};
    is(ccder_encode_len(0,(const uint8_t*)&tmp[0],&tmp[1]),&tmp[0],"ccder_encode_len return value for 1byte length");
    ok_memcmp_or_fail(tmp, expected_result1,sizeof(tmp),"ccder_encode_len output for 1byte length");

    // 2 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result2[5]={0x81,0x80};
    is(ccder_encode_len(0x80,(const uint8_t*)&tmp[0],&tmp[2]),&tmp[0],"ccder_encode_len return value for 2byte length");
    ok_memcmp_or_fail(tmp, expected_result2,sizeof(tmp),"ccder_encode_len output for 2byte length");

    // 3 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result3[5]={0x82,0xFF,0xFE};
    is(ccder_encode_len(0xFFFE,(const uint8_t*)&tmp[0],&tmp[3]),&tmp[0],"ccder_encode_len return value for 3byte length");
    ok_memcmp_or_fail(tmp, expected_result3,sizeof(tmp),"ccder_encode_len output for 3byte length");

    // 4 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result4[5]={0x83,0xFF,0xFE,0xFD};
    is(ccder_encode_len(0xFFFEFD,(const uint8_t*)&tmp[0],&tmp[4]),&tmp[0],"ccder_encode_len return value for 4byte length");
    ok_memcmp_or_fail(tmp, expected_result4,sizeof(tmp),"ccder_encode_len output for 4byte length");

    // 5 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result5[5]={0x84,0xFF,0xFE,0xFD,0xFC};
    is(ccder_encode_len(0xFFFEFDFC,(const uint8_t*)&tmp[0],&tmp[5]),&tmp[0],"ccder_encode_len return value for 5byte length");
    ok_memcmp_or_fail(tmp, expected_result5,sizeof(tmp),"ccder_encode_len output for 5byte length");

    if (sizeof(size_t)>4) {
        // 5 bytes
        is(ccder_encode_len((size_t)1<<33,&tmp[0],NULL),NULL, "length bigger than UINT32_MAX not supported"); // Expect error
    } else {
        pass("On 32bit platforms, the length can't exceed UINT32_MAX");
    }
    return 0;
}

//====================== ccder_decode_len ===================================

static void testDecodeLen(void)
{
    uint8_t one_der[] = {0x81}; // one additional octet, but missing
    uint8_t *der_start = one_der;
    uint8_t *der_end = one_der + sizeof(one_der);
    size_t len = 0;
    const uint8_t *new_der = ccder_decode_len(&len, der_start, der_end);
    is(new_der, NULL, "ccder_decode_len");

    uint8_t two_der[] = {0x82, 0x01}; // two additional octets, but missing
    der_start = two_der;
    der_end = two_der + sizeof(two_der);
    new_der = ccder_decode_len(&len, der_start, der_end);
    is(new_der, NULL, "ccder_decode_len");

    uint8_t three_der[] = {0x83, 0x01, 0x02}; // three additional octets, but missing
    der_start = three_der;
    der_end = three_der + sizeof(three_der);
    new_der = ccder_decode_len(&len, der_start, der_end);
    is(new_der, NULL, "ccder_decode_len");

    size_t length = 0x112233;
    uint8_t *valid_three_der = malloc(length + 4);
    if (valid_three_der) {
        valid_three_der[0] = 0x83;
        valid_three_der[1] = (uint8_t)(length >> 16);
        valid_three_der[2] = (uint8_t)(length >> 8);
        valid_three_der[3] = (uint8_t)(length >> 0);
        der_start = valid_three_der;
        der_end = valid_three_der + length + 4;
        new_der = ccder_decode_len(&len, der_start, der_end);
        isnt(new_der, NULL, "ccder_decode_len");
        is(new_der, valid_three_der + 4, "ccder_decode_len");

        free(valid_three_der);
    }

    // Note: we do not parse lengths with four or more octets
}

//================================ ccder_encode_body ============================

static void testEncodeBody()
{
    uint8_t der[] = {0x00};
    size_t length = sizeof(der) + 1; // invalid size
    uint8_t *body = NULL;
    uint8_t *new_der = ccder_encode_body(length, body, der, der + sizeof(der));
    is(new_der, NULL, "ccder_encode_body");
}

static void testEncodeBodyNoCopy()
{
    uint8_t der[] = {0x00};
    size_t length = sizeof(der) + 1; // invalid size
    uint8_t *new_der = ccder_encode_body_nocopy(length, der, der + sizeof(der));
    is(new_der, NULL, "ccder_encode_body");
}

//====================== ccder_decode_uint_n ===================================

typedef struct der_decode_uint_n_struct {
    char  *der_str_buf;
    cc_size n;
    int err;
} der_decode_uint_n_t;

der_decode_uint_n_t test_der_decode_uint_n[]={
    {"0200",0,1}, // Must have one byte content
    {"020100",0,0},
    {"020101",1,0},
    {"02020080",1,0},
    {"028109008000000000000001",ccn_nof_size(8),0},
    {"0281110080000000000000000000000000000001",ccn_nof_size(16),0},
    {"02020040",0,1},                   // Too many padding zeroes
    {"0203000080",1,1},                 // Too many padding zeroes
    {"02810A00000000000000000001",1,1}, // Too many padding zeroes
    {"0281088000000000000001",0,1},     // Negative
    };

static void testDecodeUInt_n()
{
    for (size_t i=0;i<sizeof(test_der_decode_uint_n)/sizeof(test_der_decode_uint_n[0]);i++) {
        cc_size n=0;
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint_n[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        if (!test_der_decode_uint_n[i].err) {
            is(ccder_decode_uint_n(&n,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint_n return value");
            is(n,test_der_decode_uint_n[i].n, "ccder_decode_uint_n expected output");
        } else {
            is(ccder_decode_uint_n(&n,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint_n return value");
        }
        free(der_buf);
    }
}

//====================== ccder_decode_uint64 ===================================

typedef struct der_decode_uint64_struct {
    char  *der_str_buf;
    uint64_t v;
    int err;
} der_decode_uint64_t;

der_decode_uint64_t test_der_decode_uint64[]={
    {"0200",0,1}, // Must have one byte content
    {"020100",0,0},
    {"020101",1,0},
    {"02020080",0x80,0},
    {"02084070605040302010",0x4070605040302010,0},
    {"0209008070605040302010",0x8070605040302010,0},
    {"0209018070605040302010",0x8070605040302010,1}, // Too big to be uint64_t
    {"02020040",1,1},                      // Too many padding zeroes
    {"0203000080",1,1},                    // Too many padding zeroes
    {"0281088000000000000001",0,1},        // Negative
    {"02810A00000000000000000001",1,1},    // Too many padding zeroes
    {"0281110001000000000000000000000000000001",0,1}, // Too big to be uint64_t
};

static void testDecodeUInt64()
{
    for (size_t i=0;i<sizeof(test_der_decode_uint64)/sizeof(test_der_decode_uint64[0]);i++) {
        uint64_t computed_v=0;
        uint64_t expected_v=0;
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint64[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        if (!test_der_decode_uint64[i].err) {
            expected_v=test_der_decode_uint64[i].v;
            is(ccder_decode_uint64(&computed_v,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint64 return value");
            is(computed_v,expected_v, "ccder_decode_uint64 expected output");
        }
        else {
            is(ccder_decode_uint64(&computed_v,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint64 return value");
        }
        free(der_buf);
    }
}

static void testDecodeEmptyBitstring()
{
    uint8_t malformed_der_buffer[] = { CCDER_BIT_STRING, 0x00 };
    size_t malformed_der_buffer_len = sizeof(malformed_der_buffer);

    uint8_t *der_ptr = malformed_der_buffer;
    size_t der_ptr_len = malformed_der_buffer_len;
    uint8_t string[10];
    size_t string_len = 0;
    const uint8_t *new_der_ptr = ccder_decode_bitstring((const uint8_t **)&string, &string_len,
                                                        (const uint8_t *)der_ptr, (const uint8_t *)(der_ptr + der_ptr_len));
    isnt(new_der_ptr, NULL, "ccder_decode_bitstring");
    is(string_len, (size_t)0, "ccder_decode_bitstring returned non-empty bit string for empty bitstring container");
}

static void testDecodeNullBitstring()
{
    uint8_t *der_ptr = NULL;
    size_t der_ptr_len = 0;
    uint8_t string[10];
    size_t string_len = 0;
    const uint8_t *new_der_ptr = ccder_decode_bitstring((const uint8_t **)&string, &string_len,
                                                        (const uint8_t *)der_ptr, (const uint8_t *)(der_ptr + der_ptr_len));
    is(new_der_ptr, NULL, "ccder_decode_bitstring");
}

static void testDecodeBitstring() {
    testDecodeEmptyBitstring();
    testDecodeNullBitstring();
}

static void testDecodeOID() {
    uint8_t malformed_der_buffer[] = { CCDER_OBJECT_IDENTIFIER, 0x00 };
    size_t malformed_der_buffer_len = sizeof(malformed_der_buffer);

    uint8_t *der_ptr = malformed_der_buffer;
    size_t der_ptr_len = malformed_der_buffer_len;
    uint8_t string[10];
    size_t string_len = 0;
    const uint8_t *new_der_ptr = ccder_decode_oid((const uint8_t **)&string, (const uint8_t *)der_ptr,
                                                  (const uint8_t *)(der_ptr + der_ptr_len));

    isnt(new_der_ptr, NULL, "ccder_decode_oid");
    is(string_len, (size_t)0, "ccder_decode_oid returned non-empty OID for empty OID container");

    // Invalidate the tag length -- 0x84 is an invalid tag length
    malformed_der_buffer[1] = 0x84;
    new_der_ptr = ccder_decode_oid((const uint8_t **)&string, (const uint8_t *)der_ptr,
                                   (const uint8_t *)(der_ptr + der_ptr_len));

    is(new_der_ptr, NULL, "ccder_decode_oid");
}

//====================== ccder_decode_uint ===================================

typedef struct der_decode_uint_struct {
    char  *der_str_buf;
    cc_unit v[CCN192_N];
    int err;
} der_decode_uint_t;

der_decode_uint_t test_der_decode_uint[]={
    {"0200",                        {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Must have one byte content
    {"020100",                      {CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00)},0},
    {"02020080",                    {CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,80)},0},
    {"02020040",                    {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"0203000001",                  {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"02810A00000000000000000001",  {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"0281088000000000000001",      {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Negative
    {"02811901000000000000000000000000000000000000000000000000",
                                    {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too big
};

static void testDecodeUInt()
{
    for (size_t i=0;i<sizeof(test_der_decode_uint)/sizeof(test_der_decode_uint[0]);i++) {
        cc_unit computed_v[CCN192_N];
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        memset(computed_v,0xAA,sizeof(computed_v)); // Fill with a different value to start with.
        
        if (!test_der_decode_uint[i].err) {
            cc_unit *expected_v=test_der_decode_uint[i].v;
            is(ccder_decode_uint(CCN192_N,computed_v,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint return value");
            ok_memcmp(computed_v,expected_v,sizeof(test_der_decode_uint[i].v), "ccder_decode_uint expected output");
        }
        else {
            is(ccder_decode_uint(CCN192_N, computed_v,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint64 return value");
        }
        free(der_buf);
    }
}

const uint8_t derbuf1[] = { 0x30, 0x01, 0xAA };
const uint8_t derbuf2[] = { 0x30, 0x01, 0xAA, 0xBB }; // Too much data, but still valid
const uint8_t derbuf3[] = { 0x30, 0x03, 0xAA }; // No enough data for len
const uint8_t derbuf4[] = { 0x30, 0x84, 0xAA }; // Invalid length

typedef struct der_decode_tl_struct {
    const uint8_t  *der;
    size_t der_len;
    size_t next_der_offset; // 0 is test is invalid
    size_t end_der_offset;  // 0 is test is invalid
    const char *description;
} der_decode_tl_t;

der_decode_tl_t test_der_decode_tl[] = {
    {&derbuf1[0],0,0,0,"Wrong der_end"},
    {&derbuf1[0],1,0,0,"Wrong der_end"},
    {&derbuf1[0],2,0,0,"Wrong der_end"},
    {&derbuf1[0],sizeof(derbuf1),2,3,"valid test, exactly enough data"},
    {&derbuf2[0],sizeof(derbuf2),2,3,"valid test, too much data"},
    {&derbuf3[0],sizeof(derbuf3),0,0,"No enough data for length"},
    {&derbuf4[0],sizeof(derbuf4),0,0,"Invalid length"},

};

static void testDecode_tl()
{
    for (size_t i = 0; i < sizeof(test_der_decode_tl) / sizeof(test_der_decode_tl[0]); i++) {
        const der_decode_tl_t test = test_der_decode_tl[i];
        const uint8_t *der_end = test.der+test.der_len;
        const uint8_t *der_body_end = NULL;
        const uint8_t *expected_return = NULL; // for errors
        const uint8_t *expected_body_end = test.der; // for errors
        if (test.next_der_offset) {
            expected_return = test.der + test.next_der_offset;
            expected_body_end = test.der + test.end_der_offset;
        }

        is(ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE, &der_body_end,
                                       test.der,der_end), expected_return,
                                       "%zu: %s", i, test.description);
        is(der_body_end, expected_body_end, "%zu: %s", i, test.description);
    }
}

static void testDecodeTag()
{
    // The second byte of this multi-byte tag does not have the top-three bits reserved.
    uint8_t malformed_der_buffer[sizeof(ccder_tag)];
    for (size_t i = 0; i < sizeof(ccder_tag); i++) {
        malformed_der_buffer[i] = 0xFF;
    }
    size_t malformed_der_buffer_len = sizeof(malformed_der_buffer);

    uint8_t *der_ptr = malformed_der_buffer;
    size_t der_ptr_len = malformed_der_buffer_len;
    ccder_tag tag;
    const uint8_t *body = ccder_decode_tag(&tag, der_ptr, der_ptr + der_ptr_len);

    is(body, NULL, "ccder_decode_tag");

    for (size_t i = 0; i < sizeof(ccder_tag); i++) {
        malformed_der_buffer[i] = 0x00;
    }
    malformed_der_buffer[0] = 0xFF;
    body = ccder_decode_tag(&tag, der_ptr, der_ptr + der_ptr_len);

    isnt(body, NULL, "ccder_decode_tag");
}

static void testSizeofTag()
{
    unsigned long limits[] = {0x1e, 0x7f, 0x3fff, 0x1fffff, 0xfffffff, 0x10000000};
    for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
        ccder_tag tag = limits[i] & CCDER_TAGNUM_MASK;
        size_t size = ccder_sizeof_tag(tag);
        is(size, i + 1, "ccder_sizeof_tag expected %zu, got %zu", i + 1, size);
    }
}

ccder_sig_test_vector sig_test_vectors[] = {
#include "ccder_signature_strict_vectors.inc"
    {.signature = NULL}
};

static void test_ccder_decode_seqii_strict() {
    for (int i = 0; sig_test_vectors[i].signature != NULL; i++) {
        const ccder_sig_test_vector tv = sig_test_vectors[i];
        
        cc_size n = ccn_nof(tv.nbits);
        byteBuffer sig = hexStringToBytes(tv.signature);
        const uint8_t *sig_end = sig->bytes + sig->len;
        cc_unit r[n], s[n];
        
        const uint8_t *result = ccder_decode_seqii_strict(n, r, s, sig->bytes, sig_end);
        is(result != NULL, tv.valid, "Strict signature decoding error on test vector %d, %s", i, tv.signature);
        
        if (tv.valid && result) {
            cc_unit rp[n], sp[n];
            byteBuffer tv_r = hexStringToBytes(tv.r);
            byteBuffer tv_s = hexStringToBytes(tv.s);
            
            ccn_read_uint(n, rp, tv_r->len, tv_r->bytes);
            ccn_read_uint(n, sp, tv_s->len, tv_s->bytes);
            free(tv_r);
            free(tv_s);
            
            ok_ccn_cmp(n, r, rp, "Incorrect r value on test vector %d", i);
            ok_ccn_cmp(n, s, sp, "Incorrect s value on test vector %d", i);
        } else {
            is(1, 1, "Dummy test1");
            is(1, 1, "Dummy test2");
        }
        
        free(sig);
    }
    return;
}

//=============================== MAIN ccder ===================================

int ccder_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int ntests = 159;
    ntests += 386 * 3; // test_ccder_decode_seqii_strict (# test_vectors x # tests)
    plan_tests(ntests);

    testDecode_tl();
    testDecodeTag();
    testSizeOfUInt64();
    testSizeOf();
    testEncodeLen();
    testDecodeLen();
    testDecodeUInt();
    testDecodeUInt_n();
    testDecodeUInt64();
    testDecodeBitstring();
    testDecodeOID();
    testEncodeBody();
    testEncodeBodyNoCopy();
    testSizeofTag();
    testEncodeTag();
    test_ccder_decode_seqii_strict();

    return 0;
}

#endif // entryPoint(ccder,"ccder")
