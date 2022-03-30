/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc.h>
#include "corecrypto/fipspost_trace.h"

#if ( CC_HAS_MEMSET_S == 1 ) && (defined( __STDC_WANT_LIB_EXT1__ ) && ( __STDC_WANT_LIB_EXT1__ == 1 ) )
void cc_clear(size_t len, void *dst)
{
    FIPSPOST_TRACE_EVENT;
    memset_s(dst,len,0,len);
}
#elif defined(_WIN32) && !defined(__clang__) //Clang with Microsoft CodeGen, doesn't support SecureZeroMemory
#include <windows.h>
static void cc_clear(size_t len, void *dst)
{
    SecureZeroMemory(dst, len);
}
#else
void cc_clear(size_t len, void *dst)
{
    FIPSPOST_TRACE_EVENT;
    volatile char *vptr = (volatile char *)dst;
    while (len--)
        *vptr++ = '\0';
}
#endif
