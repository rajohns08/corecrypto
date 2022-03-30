/* Copyright (c) (2014,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#import <XCTest/XCTest.h>
#import <corecrypto/ccrng_test.h>
#import <corecrypto/ccrng_system.h>


NSString *cc_hex_string(size_t len, const unsigned char *s);
NSString *cc_composeString(NSString *format, ...);

#define XCAssertMemEquals(len, a1, a2, description, ...) \
({ \
    @try { \
        const void *_a1value = (a1); \
        const void *_a2value = (a2); \
        size_t _lenvalue = (len); \
        if (memcmp(_a1value, _a2value, _lenvalue) != 0) {\
            NSString *_expression = cc_composeString(description, ##__VA_ARGS__); \
            NSString *_a1encoded = cc_hex_string(_lenvalue, _a1value); \
            NSString *_a2encoded = cc_hex_string(_lenvalue, _a2value); \
            XCTFail(@"%@\n%@\n should be \n%@",_expression, _a1encoded, _a2encoded);\
        }\
    }\
    @catch (NSException *exception) {\
        XCTFail(@"An exception caught");\
    }\
})

#define XCAssertCharsEquals(len, a1, a2, description, ...) \
({ \
    @try { \
        const void *_a1value = (a1); \
        const void *_a2value = (a2); \
        size_t _lenvalue = (len); \
        if (memcmp(_a1value, _a2value, _lenvalue) != 0) { \
            NSString *_expression = cc_composeString(description, ##__VA_ARGS__); \
            NSString *_a1encoded = cc_hex_string(_lenvalue, _a1value); \
            NSString *_a2encoded = cc_hex_string(_lenvalue, _a2value); \
            XCTFail(@"%@\n%@\n should be \n%@",_expression, _a1encoded, _a2encoded);\
        } \
    } \
    @catch (NSException *exception) {\
        XCTFail(@"An exception caught");\
    }\
})


// When choosing the input seed, it must have the format "\x00\x01\x02\x03"...
#define XCTestRNG(rngname,input_seed) \
    struct ccrng_test_state _test_rng; \
    struct ccrng_state* rngname=(struct ccrng_state*)&_test_rng; \
    size_t  seedlen=sizeof(input_seed)-1; \
    uint8_t random_seed[16]; \
    uint8_t *seed=(uint8_t *)input_seed; \
    if (input_seed==NULL || seedlen<=0) \
    {\
        seed=random_seed; \
        seedlen=sizeof(random_seed); \
        struct ccrng_system_state system_rng; \
        XCTAssert(ccrng_system_init(&system_rng)==0); \
        XCTAssert(ccrng_generate((struct ccrng_state *)&system_rng, seedlen, random_seed)==0); \
        ccrng_system_done(&system_rng); \
    } else {\
        printf("Forced "); \
        seed=(uint8_t *)input_seed; \
    } \
    XCTAssert(ccrng_test_init(&_test_rng, seedlen,seed,"")==0); \
    NSString *_seed_encoded = cc_hex_string(seedlen, seed); \
    printf("XCTestRNG seed: %s {", [_seed_encoded UTF8String]); \
    for (size_t i=0;i<seedlen;i++) printf("\\x%02x",seed[i]); \
    printf("}\n"); \


#define XCTestRNG_Done(rng) \
    ccrng_test_done((struct ccrng_test_state*)rng); \
    rng=NULL;
