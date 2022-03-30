/* Copyright (c) (2012,2015,2016,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_config.h>

#if CCAES_INTEL_ASM

static void vng_aesni_encrypt_blocks(const char *key, const char *in, char *out, int Nr, int nblocks)
{

#if CC_KERNEL
    char    xmm_buffer[6*16] CC_ALIGNED(16);
    __asm__ volatile(
        "movaps %%xmm0, 0(%[buf])\n\t"
        "movaps %%xmm1, 16(%[buf])\n\t"
        "movaps %%xmm2, 32(%[buf])\n\t"
        "movaps %%xmm3, 48(%[buf])\n\t"
        "movaps %%xmm4, 64(%[buf])\n\t"
        "movaps %%xmm5, 80(%[buf])\n\t"
        :
        : [buf] "r" (xmm_buffer)
        : 
        );
#endif

        if (Nr == 160) {

            __asm__ volatile(

			"sub    $4, %[Nb]\n\t"
			"jl		1f\n\t"

            "movups (%[key]), %%xmm4\n\t"
            "movups 16(%[key]), %%xmm5\n\t"

            "0:\n\t"

            "movups (%[pt]), %%xmm0\n\t"
            "movups 16(%[pt]), %%xmm1\n\t"
            "movups 32(%[pt]), %%xmm2\n\t"
            "movups 48(%[pt]), %%xmm3\n\t"

            "pxor   %%xmm4, %%xmm0\n\t"
            "pxor   %%xmm4, %%xmm1\n\t"
            "pxor   %%xmm4, %%xmm2\n\t"
            "pxor   %%xmm4, %%xmm3\n\t"
            "movups 32(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 48(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 64(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 80(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 96(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 112(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 128(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 144(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 160(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 16(%[key]), %%xmm5\n\t"

            "aesenclast %%xmm4, %%xmm0\n\t"
            "aesenclast %%xmm4, %%xmm1\n\t"
            "aesenclast %%xmm4, %%xmm2\n\t"
            "aesenclast %%xmm4, %%xmm3\n\t"
            "movups 0(%[key]), %%xmm4\n\t"

            "movups %%xmm0, (%[ct])\n\t"
            "movups %%xmm1, 16(%[ct])\n\t"
            "movups %%xmm2, 32(%[ct])\n\t"
            "movups %%xmm3, 48(%[ct])\n\t"

            "add    $64, %[ct]\n\t"
            "add    $64, %[pt]\n\t"
            "sub    $4, %[Nb]\n\t"
            "jg     0b\n\t"

            "1:\n\t"

            "add    $4, %[Nb]\n\t"
			"jle	1f\n\t"

            "0:\n\t"

            "movups (%[pt]), %%xmm0\n\t"
            "movups (%[key]), %%xmm1\n\t"
            "pxor   %%xmm1, %%xmm0\n\t"
            "movups 16(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 32(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 48(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 64(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 80(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 96(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 112(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 128(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 144(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 160(%[key]), %%xmm1\n\t"
            "aesenclast %%xmm1, %%xmm0\n\t"
            "movups %%xmm0, (%[ct])\n\t"

            "add    $16, %[ct]\n\t"
            "add    $16, %[pt]\n\t"
            "sub    $1, %[Nb]\n\t"
            "jg     0b\n\t"

            "1:\n\t"


            :
            : [ct] "r" (out), [pt] "r" (in), [key] "r" (key), [Nb] "r" (nblocks)
            : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"
            );

        } else if (Nr == 192) {

            __asm__ volatile(

			"sub    $4, %[Nb]\n\t"
			"jl		1f\n\t"

            "movups (%[key]), %%xmm4\n\t"
            "movups 16(%[key]), %%xmm5\n\t"

            "0:\n\t"

            "movups (%[pt]), %%xmm0\n\t"
            "movups 16(%[pt]), %%xmm1\n\t"
            "movups 32(%[pt]), %%xmm2\n\t"
            "movups 48(%[pt]), %%xmm3\n\t"

            "pxor   %%xmm4, %%xmm0\n\t"
            "pxor   %%xmm4, %%xmm1\n\t"
            "pxor   %%xmm4, %%xmm2\n\t"
            "pxor   %%xmm4, %%xmm3\n\t"
            "movups 32(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 48(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 64(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 80(%[key]), %%xmm5\n\t"


            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 96(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 112(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 128(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 144(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 160(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 176(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 192(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 16(%[key]), %%xmm5\n\t"

            "aesenclast %%xmm4, %%xmm0\n\t"
            "aesenclast %%xmm4, %%xmm1\n\t"
            "aesenclast %%xmm4, %%xmm2\n\t"
            "aesenclast %%xmm4, %%xmm3\n\t"
            "movups 0(%[key]), %%xmm4\n\t"

            "movups %%xmm0, (%[ct])\n\t"
            "movups %%xmm1, 16(%[ct])\n\t"
            "movups %%xmm2, 32(%[ct])\n\t"
            "movups %%xmm3, 48(%[ct])\n\t"

            "add    $64, %[ct]\n\t"
            "add    $64, %[pt]\n\t"
            "sub    $4, %[Nb]\n\t"
            "jg     0b\n\t"

            "1:\n\t"

            "add    $4, %[Nb]\n\t"
			"jle	1f\n\t"

            "0:\n\t"

            "movups (%[pt]), %%xmm0\n\t"
            "movups (%[key]), %%xmm1\n\t"
            "pxor   %%xmm1, %%xmm0\n\t"
            "movups 16(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 32(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 48(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 64(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 80(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 96(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 112(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 128(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 144(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 160(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 176(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 192(%[key]), %%xmm1\n\t"
            "aesenclast %%xmm1, %%xmm0\n\t"
            "movups %%xmm0, (%[ct])\n\t"

            "add    $16, %[ct]\n\t"
            "add    $16, %[pt]\n\t"
            "sub    $1, %[Nb]\n\t"
            "jg     0b\n\t"

            "1:\n\t"


            :
            : [ct] "r" (out), [pt] "r" (in), [key] "r" (key), [Nb] "r" (nblocks)
            : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"
            );

        } else {

            __asm__ volatile(

			"sub    $4, %[Nb]\n\t"
			"jl		1f\n\t"

            "movups (%[key]), %%xmm4\n\t"
            "movups 16(%[key]), %%xmm5\n\t"

            "0:\n\t"

            "movups (%[pt]), %%xmm0\n\t"
            "movups 16(%[pt]), %%xmm1\n\t"
            "movups 32(%[pt]), %%xmm2\n\t"
            "movups 48(%[pt]), %%xmm3\n\t"

            "pxor   %%xmm4, %%xmm0\n\t"
            "pxor   %%xmm4, %%xmm1\n\t"
            "pxor   %%xmm4, %%xmm2\n\t"
            "pxor   %%xmm4, %%xmm3\n\t"
            "movups 32(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 48(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 64(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 80(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 96(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 112(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 128(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 144(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 160(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 176(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 192(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 208(%[key]), %%xmm5\n\t"

            "aesenc %%xmm4, %%xmm0\n\t"
            "aesenc %%xmm4, %%xmm1\n\t"
            "aesenc %%xmm4, %%xmm2\n\t"
            "aesenc %%xmm4, %%xmm3\n\t"
            "movups 224(%[key]), %%xmm4\n\t"

            "aesenc %%xmm5, %%xmm0\n\t"
            "aesenc %%xmm5, %%xmm1\n\t"
            "aesenc %%xmm5, %%xmm2\n\t"
            "aesenc %%xmm5, %%xmm3\n\t"
            "movups 16(%[key]), %%xmm5\n\t"

            "aesenclast %%xmm4, %%xmm0\n\t"
            "aesenclast %%xmm4, %%xmm1\n\t"
            "aesenclast %%xmm4, %%xmm2\n\t"
            "aesenclast %%xmm4, %%xmm3\n\t"
            "movups 0(%[key]), %%xmm4\n\t"

            "movups %%xmm0, (%[ct])\n\t"
            "movups %%xmm1, 16(%[ct])\n\t"
            "movups %%xmm2, 32(%[ct])\n\t"
            "movups %%xmm3, 48(%[ct])\n\t"

            "add    $64, %[ct]\n\t"
            "add    $64, %[pt]\n\t"
            "sub    $4, %[Nb]\n\t"
            "jg     0b\n\t"

            "1:\n\t"

            "add    $4, %[Nb]\n\t"
			"jle	1f\n\t"

            "0:\n\t"

            "movups (%[pt]), %%xmm0\n\t"
            "movups (%[key]), %%xmm1\n\t"
            "pxor   %%xmm1, %%xmm0\n\t"
            "movups 16(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 32(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 48(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 64(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 80(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 96(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 112(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 128(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 144(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 160(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 176(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 192(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 208(%[key]), %%xmm1\n\t"
            "aesenc %%xmm1, %%xmm0\n\t"
            "movups 224(%[key]), %%xmm1\n\t"
            "aesenclast %%xmm1, %%xmm0\n\t"
            "movups %%xmm0, (%[ct])\n\t"

            "add    $16, %[ct]\n\t"
            "add    $16, %[pt]\n\t"
            "sub    $1, %[Nb]\n\t"
            "jg     0b\n\t"

            "1:\n\t"

            :
            : [ct] "r" (out), [pt] "r" (in), [key] "r" (key), [Nb] "r" (nblocks)
            : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"
            );


        }

#if CC_KERNEL
    __asm__ volatile(
        "movaps 0(%[buf]), %%xmm0\n\t"
        "movaps 16(%[buf]), %%xmm1\n\t"
        "movaps 32(%[buf]), %%xmm2\n\t"
        "movaps 48(%[buf]), %%xmm3\n\t"
        "movaps 64(%[buf]), %%xmm4\n\t"
        "movaps 80(%[buf]), %%xmm5\n\t"
        :
        : [buf] "r" (xmm_buffer)
        : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"
        );
#endif

}

#include "vng_aesPriv.h"
#define ECB_CTX_SIZE sizeof(vng_aes_encrypt_ctx) 		/* The size of the context */


/* ==========================================================================
	VNG Optimized AES implementation.  This implementation is optimized but
	does not use the AESNI instructions
   ========================================================================== */

/* Initialize a context with the key */
static int init_wrapper_opt(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key,
                            size_t rawkey_len, const void *rawkey)
{
	return vng_aes_encrypt_opt_key((const unsigned char *)rawkey, (int) rawkey_len, (vng_aes_encrypt_ctx*) key);
}

/* cbc encrypt or decrypt nblocks from in to out. */
static int ecb_wrapper_opt(const ccecb_ctx *key, size_t nblocks, const void *in,
                           void *out)
{
	while (nblocks--) 
	{
		vng_aes_encrypt_opt((const unsigned char*)in, (unsigned char *) out, (const vng_aes_encrypt_ctx*) key);
		in += CCAES_BLOCK_SIZE;
		out += CCAES_BLOCK_SIZE;
	}
    
    return 0;
}

const struct ccmode_ecb ccaes_intel_ecb_encrypt_opt_mode = {
    .size = ECB_CTX_SIZE,
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_opt,
    .ecb = ecb_wrapper_opt,
};

/* ==========================================================================
	VNG AESNI implementation.  This implementation uses the AESNI 
	instructions
   ========================================================================== */

/* Initialize a context with the key */
static int init_wrapper_aesni(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *key,
                              size_t rawkey_len, const void *rawkey)
{
	return vng_aes_encrypt_aesni_key((const unsigned char *)rawkey, (int) rawkey_len, (vng_aes_encrypt_ctx*) key);
}

static int ecb_wrapper_aesni(const ccecb_ctx *key, size_t nblocks, const void *in,
                             void *out)
{
	const vng_aes_encrypt_ctx *ctx = (const vng_aes_encrypt_ctx *) key;

	vng_aesni_encrypt_blocks((const char *) ctx->ks, (const char *) in, (char *) out, (int) ctx->rn, (int) nblocks);

	return 0;
}

const struct ccmode_ecb ccaes_intel_ecb_encrypt_aesni_mode = {
    .size = ECB_CTX_SIZE,
    .block_size = CCAES_BLOCK_SIZE,
    .init = init_wrapper_aesni,
    .ecb = ecb_wrapper_aesni,
};

#endif /* CCAES_INTEL_ASM */

