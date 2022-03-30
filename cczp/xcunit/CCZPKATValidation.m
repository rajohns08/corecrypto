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

#import "CCZPKATValidation.h"

#import <corecrypto/cczp.h>
#import "ccn_unit.h"
#include <corecrypto/ccn_debug.h>

@implementation CCZPKATValidation

// clang-format off
static const uint8_t abytes[192/8] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20,0x21,0x22,0x23,0x24 };
static cc_unit a192[ccn_nof(192)] = {
    CCN192_C(01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24)};
static cc_unit a192_recip[1 + ccn_nof(192)] = {
    CCN200_C(00,03,f8,03,ff,ff,ff,ff,ff,ff,e8,47,b8,18,00,00,00,00,00,8d,ab,a5,78,a8,00)};
// clang-format on

- (void)test_size
{
    STAssertEquals(
        cczp_size(8), sizeof(struct cczp) + sizeof(cc_unit) + 2 * 8, @"8 byte prime cczp size ok");
}

- (void)test_nof_n
{
    STAssertEquals(
        cczp_nof_n(16), ccn_nof_size(sizeof(struct cczp)) + 1 + 2 * 16, @"16 unit prime cczp n ok");
}

- (void)test_decl_n
{
    struct zp42 {
        cczp_decl_n(42, myzp);
    };
    STAssertEquals(sizeof(struct zp42),
                   ((cczp_size(ccn_sizeof_n(42)) + 15) & ~15),
                   @"cczp_decl_n(42) is the right size.");
}

- (void)test_N
{
    cczp_decl_n(1, zp);
    CCZP_N(zp) = 21;
    STAssertEquals(CCZP_N(zp), (size_t)21, @"CCZP_N(zp) is 21.");
}

- (void)test_MOD_PRIME
{
    cczp_decl_n(1, zp);
    CCZP_MOD_PRIME(zp) = cczp_mod;
    STAssertEquals(CCZP_MOD_PRIME(zp), &cczp_mod, @"CCZP_MOD_PRIME(zp)");
}

- (void)test_PRIME
{
    cczp_decl_n(4, zp);
    CCZP_N(zp) = 4;
    cc_unit *prime = CCZP_PRIME(zp);
    STAssertEquals((uint8_t *)prime, ((uint8_t *)zp) + sizeof(struct cczp), @"CCZP_PRIME(zp)");
}

- (void)test_RECIP
{
    cczp_decl_n(4, zp);
    CCZP_N(zp) = 4;
    cc_unit *recip = CCZP_RECIP(zp);
    STAssertEquals((uint8_t *)recip,
                   ((uint8_t *)zp) + sizeof(struct cczp) + ccn_sizeof_n(4),
                   @"CCZP_RECIP(zp)");
}

- (void)test_n
{
    cczp_decl_n(1, zp);
    CCZP_N(zp) = 25;
    STAssertEquals(cczp_n(zp), (size_t)25, @"cczp_n(zp) is 25.");
}

- (void)test_mod_prime
{
    cczp_decl_n(1, zp);
    CCZP_MOD_PRIME(zp) = cczp_mod;
    STAssertEquals(cczp_mod_prime(zp), &cczp_mod, @"cczp_mod_prime(zp)");
}

- (void)test_prime
{
    cczp_decl_n(4, zp);
    CCZP_N(zp) = 4;
    const cc_unit *prime = cczp_prime(zp);
    STAssertEquals((uint8_t *)prime, ((uint8_t *)zp) + sizeof(struct cczp), @"cczp_mod_prime(zp)");
}

- (void)test_recip
{
    cczp_decl_n(4, zp);
    CCZP_N(zp) = 4;
    const cc_unit *recip = cczp_recip(zp);
    STAssertEquals((uint8_t *)recip,
                   ((uint8_t *)zp) + sizeof(struct cczp) + ccn_sizeof_n(4),
                   @"cczp_recip(zp)");
}

- (void)test_init
{
    cczp_decl_n(ccn_nof(192), zp);
    CCZP_N(zp) = ccn_nof(192);
    ccn_set(ccn_nof(192), CCZP_PRIME(zp), a192);
    cczp_init(zp);

    STAssertEquals(cczp_mod_prime(zp), &cczp_mod, @"cczp_init(zp) initialized mod_prime");
    STAssertCCNEquals(
        1 + ccn_nof(192), cczp_recip(zp), a192_recip, @"cczp_init(zp)initialized recip");
}

- (void)test_mod
{
}

- (void)test_modn
{
}

- (void)test_mul
{
}

- (void)test_sqr
{
}

- (void)test_power
{
}

- (void)test_powern
{
}

- (void)test_add
{
}

- (void)test_sub
{
}

- (void)test_div2
{
}

- (void)test_div
{
}

- (void)test_mod_inv
{
}

- (void)test_mod_inv_slow
{
}

- (void)test_mod_inv_slown
{
}

static void cczp_set_prime(cczp_t zp, cc_size n, const cc_unit *prime)
{
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), prime);
    // cczp_init(zp);
}

static void cczp_set_prime1(cczp_t zp, uint64_t v)
{
    const size_t n = ccn_nof_size(sizeof(v));
    cc_unit td[n] = { ccn64_v(v) };
    cczp_set_prime(zp, n, td);
}

- (void)test_rabin_miller
{
    const cc_size n = ccn_nof(192);
    cczp_decl_n(n, zp);
    cczp_set_prime(zp, n, a192);
    STAssertFalse(cczp_rabin_miller(zp, 8), @"a192 is not prime");

    cczp_set_prime1(zp, 17);
    STAssertTrue(cczp_rabin_miller(zp, 8), @"17 is prime");
    cczp_set_prime1(zp, 0x665);
    STAssertTrue(cczp_rabin_miller(zp, 8), @"0x665 is prime");
    cczp_set_prime1(zp, 0x679);
    STAssertTrue(cczp_rabin_miller(zp, 8), @"0x679 is prime");
}

- (void)test_random_prime
{
}

@end
