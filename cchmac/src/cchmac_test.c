/* Copyright (c) (2011,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cchmac.h>
#include "cchmac_internal.h"
#include <corecrypto/cc_priv.h>

int cchmac_test(const struct cchmac_test_input *input)
{
    unsigned char mac[input->di->output_size];

    cchmac(input->di, input->key_len, input->key,
           input->data_len, input->data, mac);

    return memcmp(mac, input->expected_mac, input->mac_len);
}

int cchmac_test_chunks(const struct cchmac_test_input *input, size_t chunk_size)
{
    unsigned char mac[input->di->output_size];
    size_t len=input->data_len;
    const unsigned char *data=input->data;
    const struct ccdigest_info *di=input->di;
    cchmac_di_decl(di, hc);

    cchmac_init(di, hc, input->key_len, input->key);

    while(len>chunk_size) {
        cchmac_update(di, hc, chunk_size, data);
        data+=chunk_size;
        len-=chunk_size;
    }

    cchmac_update(di, hc, len, data);
    cchmac_final(di, hc, mac);

    return memcmp(mac, input->expected_mac, input->mac_len);
}
