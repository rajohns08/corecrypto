# Copyright (c) (2014-2016,2019,2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

#include <corecrypto/cc_config.h>


#if defined(__arm64__)

#include "ccarm_pac_bti_macros.h"

    .align  6
L_ONE:
    .quad 1,0
L_TWO:
    .quad 2,0
.Lbswap_mask:
    .byte 15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0

#define PT x0
#define CT x1
#define len x2
#define pctr x3
#define KS x4
#define NR w6

#define t0    v1
#define t1    v2
#define t2    v3
#define KEY     v20
#define qKEY    q20
#define FINALKEY    v21
#define qFINALKEY   q21
#define t4    v6
#define qt4   q6
#define ctr0    v22
#define ctr1    v23
#define ctr2    v24
#define ctr3    v25
#define ctr4    v26
#define ctr5    v27
#define ctr6    v28
#define ctr7    v29
#define qctr0   q22
#define qctr1   q23
#define qctr2   q24
#define qctr3   q25
#define qctr4   q26
#define qctr5   q27
#define qctr6   q28
#define qctr7   q29
#define ctr     v30
#define qctr    q30

#define ONE     v16
#define TWO     v17
#define Lbswap  v18
#define Zero    v31

/* -----------------------------------------------------------------------------------

                         AES-CTR crypt macro definitions

    -------------------------------------------------------------------------------- */

    /*
        general round aes_encrypt
        $1 should be the i-th expanded key
    */
    .macro  aesenc
    aese.16b    $0, $1  
    aesmc.16b   $0, $0
    .endm

    /*
        last 2 rounds aes_encrypt
    */
    .macro  aeslast
    aese.16b    $0, KEY
    eor.16b     $0, $0, FINALKEY
    .endm

    /* 
        swap the high/low quad registers in $1 and write to $0
    */
    .macro  transpose
    ext.16b $0, $1, $1, #8  
    .endm

    /*
        byte swap $1 and write to $0
    */
    .macro  byteswap
    tbl.16b $0, {$1}, Lbswap
    .endm

    /*
        i-th round aes_encrypt(ctr0:ctr7);
        exit with reading the next expanded key in KEY
    */
    .macro ROUND i
    aesenc  ctr0, KEY
    aesenc  ctr1, KEY
    aesenc  ctr2, KEY
    aesenc  ctr3, KEY
    aesenc  ctr4, KEY
    aesenc  ctr5, KEY
    aesenc  ctr6, KEY
    aesenc  ctr7, KEY
    ldr     qKEY, [KS, #(\i*16)]
    .endm

    /*
        v7 = aes_encrypt(ctr); ctr++;
    */
    .macro  single_block_encrypt
    mov     x7, KS
    byteswap  v7, ctr
    ld1.4s  {v4,v5,v6}, [x7], #48
    add.2d  ctr, ONE, ctr
    aesenc  v7, v4
    aesenc  v7, v5
    aesenc  v7, v6
    ld1.4s  {v4,v5,v6}, [x7], #48
    aesenc  v7, v4
    aesenc  v7, v5
    aesenc  v7, v6
    ld1.4s  {v4,v5,v6}, [x7], #48
    aesenc  v7, v4
    aesenc  v7, v5
    aesenc  v7, v6
    ld1.4s  {KEY,FINALKEY}, [x7], #32
    cmp      NR, #160
    b.le      1f
    aesenc  v7, KEY
    aesenc  v7, FINALKEY
    ld1.4s  {KEY,FINALKEY}, [x7], #32
    cmp      NR, #192
    b.le     1f
    aesenc  v7, KEY
    aesenc  v7, FINALKEY
    ld1.4s  {KEY,FINALKEY}, [x7], #32
1:  aese.16b  v7, KEY
    eor.16b v7, v7, FINALKEY
    .endm


    .globl _aes_ctr_crypt
    .align 4
_aes_ctr_crypt:
    BRANCH_TARGET_CALL

    /* set up often used constants in registers */
    adrp        x7, L_ONE@page
    add         x7, x7, L_ONE@pageoff
#if CC_KERNEL
    sub     sp, sp, #24*16
    mov     x8, sp
    st1.4s  {v0,v1,v2,v3}, [x8], #4*16
    st1.4s  {v4,v5,v6,v7}, [x8], #4*16
    st1.4s  {v16,v17,v18,v19}, [x8], #4*16
    st1.4s  {v20,v21,v22,v23}, [x8], #4*16
    st1.4s  {v24,v25,v26,v27}, [x8], #4*16
    st1.4s  {v28,v29,v30,v31}, [x8], #4*16
#endif
    ld1.4s      {ONE,TWO,Lbswap}, [x7]
    eor.16b     Zero,Zero,Zero  
  
    /* initiate ctr/T/NR in registers */ 
    ldr      qctr, [pctr]
    ldr      NR, [KS, #240]
 
    /* 
        byte swap ctr to add constants 0:7 to derive ctr0:ctr7, which needs to be byte swap back for aes_encrypt 
        
    */ 
    byteswap  ctr, ctr

    subs        len, len, #128
    b.lt        Decrypt_Main_Loop_End
    b           Decrypt_Main_Loop
      
    .align 6
Decrypt_Main_Loop:


    byteswap    ctr0, ctr
    add.2d      ctr1, ONE, ctr      // ctr1 = ctr + 1
    add.2d      ctr2, TWO, ctr
    add.2d      ctr3, TWO, ctr1
    byteswap    ctr1, ctr1          // byte swap ctr1 for aes_encrypt
    add.2d      ctr4, TWO, ctr2
    byteswap    ctr2, ctr2
    add.2d      ctr5, TWO, ctr3
    byteswap    ctr3, ctr3
    add.2d      ctr6, TWO, ctr4
    byteswap    ctr4, ctr4
    add.2d      ctr7, TWO, ctr5
    byteswap    ctr5, ctr5
    add.2d      ctr, TWO, ctr6
    ldr     qKEY, [KS]
    byteswap    ctr6, ctr6
    byteswap    ctr7, ctr7
      

    ROUND 1
    ROUND 2
    ROUND 3
    ROUND 4
    ROUND 5
    ROUND 6
    ROUND 7
    ROUND 8
    ROUND 9

    ldr qFINALKEY, [KS, #160]
    cmp  NR, #160
    b.le  1f

    ROUND 10
    ROUND 11

    ldr qFINALKEY, [KS, #192]
    cmp  NR, #192
    b.le  1f

    ROUND 12
    ROUND 13

    ldr qFINALKEY, [KS, #224]

1:

    /* 
        aeslast needs KEY/FINALKEY to finish final 2 rounds
        Vcipher++ = Vplain++ XOR ctr0:ctr7;
    */
     
    ld1.4s  {v4,v5,v6,v7}, [PT], #64
    aeslast ctr0
    aeslast ctr1
    aeslast ctr2
    aeslast ctr3
    eor.16b  ctr0, v4, ctr0
    eor.16b  ctr1, v5, ctr1
    eor.16b  ctr2, v6, ctr2
    eor.16b  ctr3, v7, ctr3
    ld1.4s  {v4,v5,v6,v7}, [PT], #64
    aeslast ctr4
    aeslast ctr5
    aeslast ctr6
    aeslast ctr7
    st1.4s  {ctr0, ctr1, ctr2, ctr3}, [CT], #64 
    eor.16b  ctr4, v4, ctr4
    eor.16b  ctr5, v5, ctr5
    eor.16b  ctr6, v6, ctr6
    eor.16b  ctr7, v7, ctr7
    st1.4s  {ctr4, ctr5, ctr6, ctr7}, [CT], #64 

    subs    len, len, #128
    b.ge    Decrypt_Main_Loop

Decrypt_Main_Loop_End:

    /* dealing with single block */

    adds    len, len, #(128-16)
    b.lt    L_Decrypt_done
  
L_Decrypt_block_Loop:
    /*
        v7 = aes_encrypt(ctr); ctr++;
    */
    single_block_encrypt

    /*
        *decipher++ = *cipher++ XOR v7;
    */
    ld1.4s  {v4},[PT],#16 
    eor.16b    v7, v4, v7
    st1.4s  {v7},[CT],#16

    subs   len, len, #16
    b.ge   L_Decrypt_block_Loop


L_Decrypt_done:

    byteswap    ctr, ctr
    str         qctr, [pctr]
#if CC_KERNEL
    ld1.4s  {v0,v1,v2,v3}, [sp], #4*16
    ld1.4s  {v4,v5,v6,v7}, [sp], #4*16
    ld1.4s  {v16,v17,v18,v19}, [sp], #4*16
    ld1.4s  {v20,v21,v22,v23}, [sp], #4*16
    ld1.4s  {v24,v25,v26,v27}, [sp], #4*16
    ld1.4s  {v28,v29,v30,v31}, [sp], #4*16
#endif
    ret         lr

#endif  // __arm64__

