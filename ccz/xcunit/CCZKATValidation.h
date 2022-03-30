/* Copyright (c) (2011,2012,2014,2015,2019) Apple Inc. All rights reserved.
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
#import <corecrypto/ccz.h>

@interface CCZKATValidation : XCTestCase
{
    ccz *a, *b, *c, *d, *r;
    unsigned expected_reallocs;

    struct ccz a_c;
    struct ccz b_c;
    struct ccz c_c;
    struct ccz lsra_c;
    struct ccz lsra8_c;
    struct ccz lsra64_c;
    struct ccz lsra65_c;
    struct ccz lsla_c;
    struct ccz lsla64_c;
    struct ccz lsla65_c;
    struct ccz sumab_c;
    struct ccz diffba_c;
    struct ccz prodab_c;
    struct ccz squarea_c;
}

- (void) setUp;
- (void) tearDown;

@end
