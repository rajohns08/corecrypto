/* Copyright (c) (2010,2011,2012,2014,2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#import "ccn_unit.h"
#include "cc_debug.h"

NSString *ccn_string(cc_size count, const cc_unit *s) {
    NSMutableString *r = [[NSMutableString alloc] initWithCapacity: 3 + count * 8];
    for (cc_size ix = count; ix--;) {
        [r appendFormat: @"%" CCPRIx_UNIT, s[ix]];
    }
    [r autorelease];
    return r;
}
