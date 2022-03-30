/* Copyright (c) (2010,2011,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccdigest.h>
#include "cctest.h"
#include "ccdigest_test.h"

int ccdigest_test(const struct ccdigest_info *di, size_t len,
                  const void *data, const void *digest)
{
    unsigned char temp[di->output_size];

    ccdigest(di, len, data, temp);
    return memcmp(temp, digest, di->output_size);
}

/* process data by chunk */
int ccdigest_test_chunk(const struct ccdigest_info *di, size_t len,
                        const void *data, const void *digest, size_t chunk)
{
    ccdigest_di_decl(di, dc);
    unsigned char temp[di->output_size];

    ccdigest_init(di, dc);
    while(len>chunk) {
        ccdigest_update(di, dc, chunk, data);
        data+=chunk;
        len-=chunk;
    }
    ccdigest_update(di, dc, len, data);
    ccdigest_final(di, dc, temp);

    return memcmp(temp, digest, di->output_size);
}

int ccdigest_test_vector(const struct ccdigest_info *di, const struct ccdigest_vector *v)
{
    return ccdigest_test(di, v->len,(const unsigned char *)v->message, v->digest);
}

int ccdigest_test_chunk_vector(const struct ccdigest_info *di, const struct ccdigest_vector *v, size_t chunk)
{
    return ccdigest_test_chunk(di, v->len, (const unsigned char *)v->message, v->digest, chunk);
}
