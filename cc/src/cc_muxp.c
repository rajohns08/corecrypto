/* Copyright (c) (2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_priv.h>
/*
Per C99 ISO/IEC 9899:1999 §6.5.8 and 6.5.9 Relational operator:
Each of the operators < , > , <= , >=, ==, !=  yield 1 if the specified relation is true and 0 if it is false. ... The result type is integer.
Also applies to other revisions of the C standard such as C11.
*/
// returns z= s ? a : b in constant time, when a and be are pointers. s must be either 0 or 1.
void *cc_muxp(int s, const void *a, const void *b)
{
    cc_assert(s==1 || s==0);
    uintptr_t ia = (uintptr_t) a;
    uintptr_t ib = (uintptr_t) b;
    uintptr_t cond =~((uintptr_t)s-(uintptr_t)1);//s?~zero:zero; see above
    uintptr_t rc = (cond&ia)|(~cond&ib);
    return (void *)rc;
}
