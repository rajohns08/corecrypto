;# Copyright (c) (2016,2019) Apple Inc. All rights reserved.
;#
;# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
;# is contained in the License.txt file distributed with corecrypto) and only to 
;# people who accept that license. IMPORTANT:  Any license rights granted to you by 
;# Apple Inc. (if any) are limited to internal use within your organization only on 
;# devices and computers you own or control, for the sole purpose of verifying the 
;# security characteristics and correct functioning of the Apple Software.  You may 
;# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

    PRESERVE8
    THUMB
    AREA     Example,CODE,READONLY
    ;void ccsha256_v6m_compress(uint32_t *state, uint32_t nblocks, const uint32_t *in)
    EXPORT _ccsha256_v6m_compress
	EXPORT ccsha256_v6m_compress

ccsha256_v6m_compress
    ;.section	__TEXT,__text,regular,pure_instructions
	;.syntax unified
	;.globl	_ccsha256_v6m_compress
	ALIGN 2
	;.code	16      ;ccsha256_v6m_compress
	;.thumb_func	_ccsha256_v6m_compress
_ccsha256_v6m_compress

A  RN r0
B  RN r1
C  RN r2
D  RN r3
E  RN r4
F  RN r5
G  RN r6
H  RN r7
HH RN r8
DD RN r9
TT RN r10
Sha256Table RN r11
Idx RN r12

CCSHA256_BLOCK_SIZE  EQU (64) ;in bytes

;vars
W_LEN      EQU (4*80)
STACK_SIZE EQU W_LEN+ (8)*4

W          EQU 0 ; lenght is 64*4 bytes
STATE      EQU 4+W_LEN
NBLOCKS    EQU 8+W_LEN
INPUT_DATA      EQU 12+W_LEN
SHA256TBL  EQU 16+W_LEN

    ;preserve r4-r12
    push	{r4, r5, r6, r7, lr}
	
    mov r3, r8
	push {r3}
    mov r3, r9
	push {r3}
	mov r3, r10
	push {r3}
	mov r3, r11
	push {r3}
    mov r3, r12
	push {r3}
	  
	sub	sp, #STACK_SIZE
    cmp	r1, #0
	bne	Start
	b	Return

Start
    str r0, [sp, #STATE]
    str r1, [sp, #NBLOCKS]
    str r2, [sp, #INPUT_DATA]

    bl Set_Sha256_Table_Address

NBlocks_Loop

;-- schedule W[0] tp W[15] -------------------------------------------------
    MACRO
    Set_W_0_15  $input_data, $ofs
    ldr	r0, [$input_data, #(4*$ofs)]
	rev	r0, r0
	str	r0, [sp, #(W + 4*$ofs)]
    MEND

    ldr r1, [sp, #INPUT_DATA]
    Set_W_0_15 r1, 15  ; pipeline this chk bjn
    Set_W_0_15 r1, 14
    Set_W_0_15 r1, 13
    Set_W_0_15 r1, 12
    Set_W_0_15 r1, 11
    Set_W_0_15 r1, 10
    Set_W_0_15 r1, 9
    Set_W_0_15 r1, 8
    Set_W_0_15 r1, 7
    Set_W_0_15 r1, 6
    Set_W_0_15 r1, 5
    Set_W_0_15 r1, 4
    Set_W_0_15 r1, 3
    Set_W_0_15 r1, 2
    Set_W_0_15 r1, 1
    Set_W_0_15 r1, 0 ;r0 is W[0] here

;-- schedule W[16] tp W[63] -------------------------------------------------
;r = Gamma0(x)  x>>>18 ^ x >>3 ^ x>>>7
    MACRO
    Gamma   $rv, $x, $n1, $n2, $n3
    mov	    r7, $x
    movs	$rv, $n1
    rors	r7, $rv
    lsrs	r6, $x, $n2
    eors	r6, r7

    movs	r7, $n3
    mov	    $rv, $x
    rors	$rv, r7
    eors	$rv, r6
    MEND

;W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    movs	r1, #0
    ;r0 is W[0] here
    add	    r2, sp, #W
Set_W_16_63
	adds	r3, r2, r1

    ldr	    r4, [r3, #36] ;W[i-7]
	adds	r0, r4

    ldr	    r4, [r3, #56] ;W[i-2]
    Gamma   r5, r4, #19, #10, #17
    adds    r0, r5

	ldr	    r4, [r3, #4] ;W[i-15]
    Gamma   r5, r4, #18, #3, #7 ;Gammma0
    adds    r0, r5

	str   	r0, [r3, #64] ;W[i]
    mov  	r0, r4

	adds	r1, #4
	cmp  	r1, #(64-16)*4
	bne  	Set_W_16_63

;---------------------------------------------------------------------

;-- Maj(x,y,z)  ((x|y)&z) | (x& y)
		MACRO
		Maj		$tmp, $rv, $x, $y, $z
        mov     $rv, $x
        orrs    $rv, $y
		ands    $rv, $z
		
		mov     $tmp, $x
		ands    $tmp, $y
		orrs    $rv, $tmp
		MEND

;-- Sigma(x)  x>>>n1 ^ x>>>n2 ^ x>>>n3
		MACRO
		Sigma   $tmp, $rv, $x, $n1,$n2,$n3
		mov     TT, $x  ;save $x
		
        movs	$tmp, $n1
        mov     $rv, TT
        rors	$rv, $tmp

        movs	$tmp, $n2
        rors	$x, $tmp

		eors    $rv, $x
		
        movs	$tmp, $n3
        mov	    $x, TT
        rors	$x, $tmp

		eors    $rv, $x

        mov     $x, TT
  	
		MEND

;-- Ch(x,y,z)  z^(x&(y^z))
		MACRO
		Ch      $rv, $x, $y, $z
		mov     $rv, $z
		eors    $rv, $y
		ands    $rv, $x
		eors    $rv, $z
        MEND

        MACRO
        Add_Ki_Wi $tmp, $rv, $io, $ii
        mov  $tmp, $ii

        mov  $rv, Sha256Table
        ldr  $rv, [$rv, $tmp]
        add  $io, $rv

        add	 $rv, sp, #W
        ldr  $rv, [$rv, $tmp]
        add  $io, $rv
        MEND

        MACRO
        Load_Ki $tmp, $rv, $ii
		mov  $tmp, $ii
        mov  $rv, Sha256Table
        ldr  $rv, [$rv, $tmp]
        MEND

        MACRO
        Load_Wi $tmp, $rv, $ii
		mov  $tmp, $ii
        add	 $rv, sp, #W
        ldr  $rv, [$rv, $tmp]
        MEND

;---------------------------------------------------------------------
;h =  h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
;d += h; 
;h  = h + Sigma0(a) + Maj(a, b, c);

        MACRO
		Round $A, $B, $C, $tmp, $E, $F, $G, $rv, $ii

        mov HH, $rv  ;out
        mov DD, $tmp  ;tmp

        Sigma   $tmp, $rv, $E, #11, #6, #25
        add HH, $rv

        Ch      $rv, $E, $F, $G
        add HH, $rv

        Add_Ki_Wi $tmp, $rv, HH, $ii

        add DD, HH

        Sigma   $tmp, $rv, $A, #13, #2, #22
        add HH, $rv

        Maj $tmp, $rv, $A, $B, $C
        add HH, $rv

        movs $tmp, #4
        add $ii, $tmp

        mov $rv, HH
        mov $tmp, DD
        MEND

        MACRO
        Update_State $tmp, $V ,$in, $ofs
        ldr $tmp, [$V, $ofs]
        add $tmp, $in
        str $tmp, [$V, $ofs]
        MEND

;---------------------------------------------------------------------
       movs r0, #0
	   mov Idx, r0
	   
	   ldr H, [sp, #STATE]
       ldr A, [H, #0]
       ldr B, [H, #4]
       ldr C, [H, #8]
       ldr D, [H, #12]
       ldr E, [H, #16]
       ldr F, [H, #20]
       ldr G, [H, #24]
       ldr H, [H, #28]

;---------------------------------------------------------------------
Round_Loop
       Round  A, B, C, D, E, F, G, H, Idx
       Round  H, A, B, C, D, E, F, G, Idx
       Round  G, H, A, B, C, D, E, F, Idx
       Round  F, G, H, A, B, C, D, E, Idx
       Round  E, F, G, H, A, B, C, D, Idx
       Round  D, E, F, G, H, A, B, C, Idx
       Round  C, D, E, F, G, H, A, B, Idx
       Round  B, C, D, E, F, G, H, A, Idx

       mov TT, r0
       mov r0, Idx
	   cmp r0, #255
       mov r0, TT
	   bge Out_Of_Loop
       b Round_Loop
;---
Out_Of_Loop
       mov HH, H
       mov DD, D
       ldr H, [sp, #STATE]
       Update_State D, H, A, #0
       Update_State D, H, B, #4
       Update_State D, H, C, #8
       Update_State D, H, DD, #12
       Update_State D, H, E, #16
       Update_State D, H, F, #20
       Update_State D, H, G, #24
       Update_State D, H, HH, #28

       ldr r0, [sp, #INPUT_DATA]
       movs r1,#CCSHA256_BLOCK_SIZE
       adds r0,r1
       str r0, [sp, #INPUT_DATA]

       ldr r0, [sp, #NBLOCKS]
       subs r0, #1
       str r0, [sp, #NBLOCKS] ; this can be saved
       beq  Return
       b   NBlocks_Loop

Return
	add	sp, #STACK_SIZE
    ;restore r4-r8, r9, r10, r11, r12
    pop {r3} ;mov r12, r3
	pop {r2} ;mov r11, r3
	pop {r1} ;mov r10, r3
    pop {r0} ;mov r9, r3
    mov r12, r3
    pop {r3}
    mov r11, r2
    mov r10, r1
    mov r9,  r0
	mov r8, r3
   
	pop	{r4, r5, r6, r7, pc}

;---------------------------------------------------------------------
Set_Sha256_Table_Address
       adr	r0, Sha256Table_Indicator
	   ldr  r0, [r0]
Sha256Table_Save
	   add	r0, pc
	   str	r0, [sp, #SHA256TBL]
	   mov Sha256Table, r0
       mov pc, lr
;---------------------------------------------------------------------
	ALIGN	4
Sha256Table_Indicator
	DCD _ccsha256_K-(Sha256Table_Save+4)

_ccsha256_K
	DCD	1116352408              ; 0x428a2f98
	DCD	1899447441              ; 0x71374491
	DCD	3049323471              ; 0xb5c0fbcf
	DCD	3921009573              ; 0xe9b5dba5
	DCD	961987163               ; 0x3956c25b
	DCD	1508970993              ; 0x59f111f1
	DCD	2453635748              ; 0x923f82a4
	DCD	2870763221              ; 0xab1c5ed5
	DCD	3624381080              ; 0xd807aa98
	DCD	310598401               ; 0x12835b01
	DCD	607225278               ; 0x243185be
	DCD	1426881987              ; 0x550c7dc3
	DCD	1925078388              ; 0x72be5d74
	DCD	2162078206              ; 0x80deb1fe
	DCD	2614888103              ; 0x9bdc06a7
	DCD	3248222580              ; 0xc19bf174
	DCD	3835390401              ; 0xe49b69c1
	DCD	4022224774              ; 0xefbe4786
	DCD	264347078               ; 0xfc19dc6
	DCD	604807628               ; 0x240ca1cc
	DCD	770255983               ; 0x2de92c6f
	DCD	1249150122              ; 0x4a7484aa
	DCD	1555081692              ; 0x5cb0a9dc
	DCD	1996064986              ; 0x76f988da
	DCD	2554220882              ; 0x983e5152
	DCD	2821834349              ; 0xa831c66d
	DCD	2952996808              ; 0xb00327c8
	DCD	3210313671              ; 0xbf597fc7
	DCD	3336571891              ; 0xc6e00bf3
	DCD	3584528711              ; 0xd5a79147
	DCD	113926993               ; 0x6ca6351
	DCD	338241895               ; 0x14292967
	DCD	666307205               ; 0x27b70a85
	DCD	773529912               ; 0x2e1b2138
	DCD	1294757372              ; 0x4d2c6dfc
	DCD	1396182291              ; 0x53380d13
	DCD	1695183700              ; 0x650a7354
	DCD	1986661051              ; 0x766a0abb
	DCD	2177026350              ; 0x81c2c92e
	DCD	2456956037              ; 0x92722c85
	DCD	2730485921              ; 0xa2bfe8a1
	DCD	2820302411              ; 0xa81a664b
	DCD	3259730800              ; 0xc24b8b70
	DCD	3345764771              ; 0xc76c51a3
	DCD	3516065817              ; 0xd192e819
	DCD	3600352804              ; 0xd6990624
	DCD	4094571909              ; 0xf40e3585
	DCD	275423344               ; 0x106aa070
	DCD	430227734               ; 0x19a4c116
	DCD	506948616               ; 0x1e376c08
	DCD	659060556               ; 0x2748774c
	DCD	883997877               ; 0x34b0bcb5
	DCD	958139571               ; 0x391c0cb3
	DCD	1322822218              ; 0x4ed8aa4a
	DCD	1537002063              ; 0x5b9cca4f
	DCD	1747873779              ; 0x682e6ff3
	DCD	1955562222              ; 0x748f82ee
	DCD	2024104815              ; 0x78a5636f
	DCD	2227730452              ; 0x84c87814
	DCD	2361852424              ; 0x8cc70208
	DCD	2428436474              ; 0x90befffa
	DCD	2756734187              ; 0xa4506ceb
	DCD	3204031479              ; 0xbef9a3f7
	DCD	3329325298              ; 0xc67178f2


;.subsections_via_symbols

    END


