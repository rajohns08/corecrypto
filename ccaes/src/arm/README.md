/* Copyright (c) (2011,2015,2016) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

This directory is introduced to add arm-based assembly code optimized implementation of FIPS-197 AES functions.

	- aes_encrypt_key
	- aes_decrypt_key
	- aes_encrypt_cbc
	- aes_decrypt_cbc

It replaces the old C code implementation in bsd/crypto/aes/gen.

This directory contains

	README.md	: this file.
	Makefile	: a copy of Makefile from other project directory (../gen/)

	aesdata.s	: tables used for other assembly code
	aeskey.s	: used to define aes_encrypt_key/aes_decrypt_key

	aes_cbc.s	: a common code template for aes_encrypt_cbc and aes_decrypt_cbc
	aesencbc.s	: a wrapper of aes_cbc.s to define aes_encrypt_cbc
	aesdecbc.s	: a wrapper of aes_cbc.s to define aes_decrypt_cbc

	EncryptDecrypt.s : this is not used yet in the xnu project. This is a code template to define
                       the atomic function aes_encrypt/aes_decrypt, that might be useful in early
                       development of other modes (such as XTS) functions.
                       define Select = 0 to define aes_encrypt
                       define Select = 1 to define aes_decrypt

This implementation (for arm) was derived based on the i386/x86_64 implementation (../i386/).
Because the 2nd operand in arm data processing instructions comes as the output of the barrel shifter, almost
all tables in the i386 port (in which 3/4 are actually rotated versions of the main 1/4 table) can be reduced 
to the main quarter of the table.

The CBC mode verification and profiling tools (using the assembly code here) can be built from 

$ cd ../test/ 
$ makeoptarm.sh         # this will build armv6+armv7 aesoptarm
$ makegenarm.sh			# this will build armv6+armv7 aesgenarm


