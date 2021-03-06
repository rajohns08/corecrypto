# Copyright (c) (2011,2014,2015,2016,2018,2019) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to 
# people who accept that license. IMPORTANT:  Any license rights granted to you by 
# Apple Inc. (if any) are limited to internal use within your organization only on 
# devices and computers you own or control, for the sole purpose of verifying the 
# security characteristics and correct functioning of the Apple Software.  You may 
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.
#include <corecrypto/cc_config.h>



//  This file implements schoolbook multiplication implemented for 32- and
//  64-bit Intel.  The same algorithm is used for both architectures.
//  Pseudo-code in C:
//
//    cc_dunit mulAdd2(cc_unit a, cc_unit b, cc_unit c, cc_unit d) { return (cc_dunit)a*b + c + d; }
//    cc_unit hi(cc_dunit a) { return a >> CCN_UNIT_BITS; }
//    cc_unit lo(cc_dunit a) { return a; }
//
//    void ccn_mul(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
//      cc_unit c = 0;
//      for (cc_size j=0; j<n; ++j) {
//        cc_dunit p = mulAdd2(s[j], t[0], 0, c);
//        r[j] = lo(p);
//        c = hi(p);
//      }
//      r[n] = c;
//      for (cc_size i=1; i<n; ++i) {
//        c = 0;
//        for (cc_size j=0; j<n; ++j) {
//          cc_dunit p = mulAdd2(s[j], t[i], r[i+j], c);
//          r[i+j] = lo(p);
//          c = hi(p);
//        }
//        r[i+n] = c;
//      }
//    }

#if CCN_MUL_ASM
#if defined __x86_64__

#define n  %rdi
#define r  %rsi
#define s  %r8
#define t  %rcx
#define ti %r9
#define p  %rax
#define q  %rdx
#define c  %rbx
#define j  %r10
#define i  %r11

.p2align 4
.globl _ccn_mul
_ccn_mul:
//  Schoolbook multiplication implemented for x86_64.
    push    %rbp
    mov     %rsp,   %rbp
    push    %rbx
//  ccn_mul(n, r, s, t) - Computes r = s*t, where s and t are pointers to
//  n-word (64n-bit) unsigned numbers, and r is a pointer to the 2n-word (128n-
//  bit) unsigned result buffer.
//
//  If n is zero, there is nothing to be done.
    test    n,      n
    jz      L_exit
//  Initial setup before we begin the multiplication; first, move the pointer s
//  into the correct register (we need to free up RDX for use with the MUL
//  instruction), and advance r, s, and t to point at the nth element of the
//  corresponding buffers (so that we can use negative indexing that counts
//  up to zero, avoiding an extra compare in our loops).
    lea (%rdx,n,8), s
    lea    (t,n,8), t
    lea    (r,n,8), r
//  First multiplication loop; we compute the (n+1)-word product s[0...n]*t[0]
//  and store it to the low-order n+1 words of r.  Before the loop starts, we
//  need to set up a counter (initialized to -n for our negative-indexing
//  scheme), zero out a c register (since there is no c-in to the low
//  partial product), and load t[0] (since it is a loop invariant).
    neg     n
    mov     n,      i
    mov     n,      j
    xor     c,      c
    mov    (t,i,8), ti
//  In the loop itself, we load a word from t, compute the full product with
//  s, add the high part of the previous multiplication, and store the result
//  to r.
L_sj_t0_product:
    mov    (s,j,8), p
    mul     ti
    add     c,      p
    adc     $0,     q
    mov     p,     (r,j,8)
    mov     q,      c
    add     $1,     j
    jnz     L_sj_t0_product
//  Store the remaining high word of the product we just computed; decrement
//  the outer-loop counter and exit if we have run out of words in t.
L_loop_over_i:
    mov     c,     (r)
    add    $1,      i
    jz      L_exit
//  More work remains to be done; load the next word of t, and add its product
//  with s to the accumulated buffer.  This code is essentially identical
//  to the s*t0 product above, except that we need to add the corresponding
//  already-computed word from the result buffer to each partial product.
    lea   8(r),     r
    mov     n,      j
    xor     c,      c
    mov    (t,i,8), ti
L_sj_ti_product:
//  Main work loop: compute the partial product p:q = s[j]*t[i] + r[i+j] + c.
//  The low part of the result (p) is stored back to r[i+j].  The high part
//  of the result (q) becomes c for the next iteration.
    mov    (s,j,8), p
    mul     ti
    add     c,      p
    adc     $0,     q
    add    (r,j,8), p
    adc     $0,     q
    mov     p,     (r,j,8)
    mov     q,      c
    add     $1,     j
    jnz     L_sj_ti_product
    jmp     L_loop_over_i
L_exit:
    pop     %rbx
    pop     %rbp
    ret

#elif defined __i386__

#define n 32(%esp)
#define r %esi
#define s %ebx
#define t 44(%esp)
#define c %ecx
#define p %eax
#define q %edx
#define j %edi
#define i 4(%esp)
#define ti (%esp)

.p2align 4
.globl _ccn_mul
_ccn_mul:
//  Schoolbook multiplication implemented for i386.
//  Setup frame, save volatile registers, load parameters.
    push    %ebp
    mov     %esp,   %ebp
    push    %ebx
    push    %esi
    push    %edi
    sub     $12,    %esp
    mov     n,      j
    mov  36(%esp),  r
    mov  40(%esp),  s
//  Nothing to do if size is zero.
    test    j,      j
    jz      L_exit
//  Place the low-order word of t on the stack where it will have a known
//  address, since we can't spare another register to track it in the loops.
//  Advance r and s pointers to &r[n] and &s[n] so that we can use negative
//  indexing when we loop through these numbers, then negate j, and clear
//  carry.
    mov     t,      c
    mov    (c),     c
    mov     c,      ti      // store t[0] to stack where we can find it.
    lea    (r,j,4), r
    lea    (s,j,4), s
    mov     j,      i
    neg     j
    mov     j,      n       // save negated n so we can reload it.
    xor     c,      c
L_sj_t0_product:
//  Initial work loop: compute the partial product p:q = s[j]*t[0] + c.
//  The low part of the result (p) is stored to r[j].  The high part
//  of the result (q) becomes c for the next iteration.
    mov    (s,j,4), p
    mull    ti
    add     c,      p
    adc     $0,     q
    mov     p,     (r,j,4)
    mov     q,      c
    add     $1,     j
    jnz     L_sj_t0_product
L_loop_over_i:
//  Store the remaining high word of the product we just computed; decrement
//  the outer-loop counter and exit if we have run out of words in s.
    mov     c,     (r)
    subl    $1,     i
    jz      L_exit
//  More work remains to be done; load the next word of t, and add its product
//  with s to the accumulated buffer.  This code is essentially identical
//  to the s*t0 product above, except that we need to add the corresponding
//  already-computed word from the result buffer to each partial product.
    lea   4(r),     r
    mov     t,      c
    add     $4,     c       // &t[i]
    mov     c,      t
    mov    (c),     c
    mov     c,      ti      // store t[0] to stack where we can find it.
    mov     n,      j
    xor     c,      c
L_sj_ti_product:
//  Main work loop: compute the partial product p:q = s[j]*t[i] + r[i+j] + c.
//  The low part of the result (p) is stored back to r[i+j].  The high part
//  of the result (q) becomes c for the next iteration.
    mov    (s,j,4), p
    mull    ti
    add     c,      p
    adc     $0,     q
    add    (r,j,4), p
    adc     $0,     q
    mov     p,     (r,j,4)
    mov     q,      c
    add     $1,     j
    jnz     L_sj_ti_product
    jmp     L_loop_over_i
L_exit:
    add     $12,    %esp
    pop     %edi
    pop     %esi
    pop     %ebx
    pop     %ebp
    ret

#endif /* architecture */
#endif /* CCN_MUL_ASM */

