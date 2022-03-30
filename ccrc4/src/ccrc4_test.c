/* Copyright (c) (2011,2015,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccrc4.h>
#include "ccrc4_internal.h"

/* rc4 test, encrypt then decrypt in place */
int ccrc4_test(const struct ccrc4_info *rc4, const struct ccrc4_vector *v)
{
    ccrc4_ctx_decl(rc4->size, skey);
    unsigned char temp[v->datalen];
    int rc;

    rc4->init(skey, v->keylen, v->key);
    rc4->crypt(skey, v->datalen, v->ct, temp);
    rc=memcmp(temp, v->pt, v->datalen);

    rc4->init(skey, v->keylen, v->key);
    rc4->crypt(skey, v->datalen, temp, temp);
    rc|=memcmp(temp, v->ct, v->datalen);

    return rc;
}
