/* Copyright (c) (2014,2015,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#import "cc_unit.h"
#import <corecrypto/ccn.h>

NSString *ccn_string(cc_size count, const cc_unit *s);

#define XCAssertCCNEquals(count, a1, a2, description, ...) \
({ \
    @try { \
        const cc_unit *_a1value = (a1); \
        const cc_unit *_a2value = (a2); \
        cc_size _countvalue = (count); \
        if (ccn_cmp(_countvalue, _a1value, _a2value) != 0) { \
            NSString *_expression = cc_composeString(description, ##__VA_ARGS__); \
            NSString *_a1encoded = ccn_string(_countvalue, _a1value); \
            NSString *_a2encoded = ccn_string(_countvalue, _a2value); \
            XCTFail(@"%@\n%@\n should be \n%@",_expression, _a1encoded, _a2encoded);\
        } \
    } \
    @catch (NSException *exception) {\
        XCTFail(@"An exception caught");\
    }\
})
