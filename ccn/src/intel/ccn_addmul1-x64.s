# Copyright (c) (2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>

#if defined(__x86_64__) && CCN_MUL1_ASM

.text

#define n %rcx
#define r %rsi
#define s %r8
#define v %rdx
#define a %r9
#define b %rdi
#define c %r10

.align 4
.globl _ccn_addmul1_asm
_ccn_addmul1_asm: /* cc_unit ccn_addmul1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v); */
    pushq %rbp
    movq %rsp, %rbp

    // Free %rdx.
    movq %rdx, s

    // Move v into %rdx, free %rcx.
    movq %rcx, %rdx

    // Move n into %rcx.
    movq %rdi, %rcx

    // r += n * 8
    leaq (r,%rdi,8), r
    // s += n * 8
    leaq (s,%rdi,8), s

    negq n

    // carry = 0, clear flags.
    xorq c, c

    // Save CF/OF.
    lahf

    // n & 1 == 0?
    bt $0, n
    jnc L_do2

L_do1:
    // Restore CF/OF.
    sahf

    // s[i] * v
    mulxq (s,n,8), a, c

    adcxq (r,n,8), a
    movq a, (r,n,8)

    leaq 1(n), n

    // Save CF/OF.
    lahf

L_do2:
    // n & 2 == 0?
    bt $1, n
    jnc L_skip2

    // Restore either the initial flags CF=OF=0 or the carry from L_do1.
    sahf

    // s[i] * v
    mulxq (s,n,8), a, b

    adcxq c, a
    adoxq (r,n,8), a
    movq a, (r,n,8)

    // s[i+1] * v
    mulxq 8(s,n,8), a, c

    adcxq b, a
    adoxq 8(r,n,8), a
    movq a, 8(r,n,8)

    leaq 2(n), n
    jmp L_loop4

L_skip2:
    // Restore either the initial flags CF=OF=0 or the carry from L_do1.
    sahf

L_loop4:
    jrcxz L_done

    // s[i] * v
    mulxq (s,n,8), a, b

    adcxq c, a
    adoxq (r,n,8), a
    movq a, (r,n,8)

    // s[i+1] * v
    mulxq 8(s,n,8), a, c

    adcxq b, a
    adoxq 8(r,n,8), a
    movq a, 8(r,n,8)

    // s[i+2] * v
    mulxq 16(s,n,8), a, b

    adcxq c, a
    adoxq 16(r,n,8), a
    movq a, 16(r,n,8)

    // s[i+3] * v
    mulxq 24(s,n,8), a, c

    adcxq b, a
    adoxq 24(r,n,8), a
    movq a, 24(r,n,8)

    leaq 4(n), n
    jmp L_loop4

L_done:
    movq $0, %rax
    adcxq %rax, c
    adoxq c, %rax

    popq %rbp
    ret

#endif
