/* Copyright (c) (2011,2012,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#include "ccperf.h"
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccmd2.h>
#include <corecrypto/ccmd4.h>
#include <corecrypto/ccmd5.h>

#define CCDIGEST_TEST(_di) { .name=#_di, .di=&_di }

static struct ccdigest_info ccsha1_di_default;
static struct ccdigest_info ccsha224_di_default;
static struct ccdigest_info ccsha256_di_default;
static struct ccdigest_info ccsha384_di_default;
static struct ccdigest_info ccsha512_di_default;
static struct ccdigest_info ccsha512_256_di_default;


static struct ccdigest_perf_test {
    const char *name;
    const struct ccdigest_info *di;
} ccdigest_perf_tests[] = {
    CCDIGEST_TEST(ccsha1_eay_di),
    CCDIGEST_TEST(ccsha1_ltc_di),
    CCDIGEST_TEST(ccsha1_di_default),
    CCDIGEST_TEST(ccsha224_ltc_di),
    CCDIGEST_TEST(ccsha224_di_default),
    CCDIGEST_TEST(ccsha256_ltc_di),
    CCDIGEST_TEST(ccsha256_di_default),
    CCDIGEST_TEST(ccsha384_ltc_di),
    CCDIGEST_TEST(ccsha384_di_default),
    CCDIGEST_TEST(ccsha512_ltc_di),
    CCDIGEST_TEST(ccsha512_di_default),
    CCDIGEST_TEST(ccsha512_256_ltc_di),
    CCDIGEST_TEST(ccsha512_256_di_default),
    CCDIGEST_TEST(ccmd2_ltc_di),
    CCDIGEST_TEST(ccmd4_ltc_di),
    CCDIGEST_TEST(ccmd5_ltc_di),
};

static double perf_ccdigest(size_t loops, size_t *psize, const void *arg)
{
    const struct ccdigest_perf_test *test=arg;
    unsigned char h[test->di->output_size];
    unsigned char data[*psize];

    perf_start();
    do {
        ccdigest(test->di, *psize, data, h);
    } while (--loops != 0);
    return perf_seconds();
}

static struct ccperf_family family;

static const size_t sizes[]={16,256,32*1024};

struct ccperf_family *ccperf_family_ccdigest(int argc, char *argv[])
{
    memcpy(&ccsha1_di_default,ccsha1_di(),sizeof(ccsha1_di_default));
    memcpy(&ccsha224_di_default,ccsha224_di(),sizeof(ccsha224_di_default));
    memcpy(&ccsha256_di_default,ccsha256_di(),sizeof(ccsha256_di_default));
    memcpy(&ccsha384_di_default,ccsha384_di(),sizeof(ccsha384_di_default));
    memcpy(&ccsha512_di_default,ccsha512_di(),sizeof(ccsha512_di_default));
    memcpy(&ccsha512_256_di_default,ccsha512_256_di(),sizeof(ccsha512_256_di_default));
    F_GET_ALL(family, ccdigest);
    F_SIZES_FROM_ARRAY(family, sizes);
    family.size_kind=ccperf_size_bytes;
    return &family;
}
