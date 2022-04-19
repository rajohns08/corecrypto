/* Copyright (c) (2010,2012,2014-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

The corecrypto (cc) project
===========================

The main goal is to provide low level fast math routines and crypto APIs which
can be used in various environments (Kernel, bootloader, userspace, etc.).  It
is an explicit goal to minimize dependancies between modules and functions so
that clients of this library only end up with the routines they need and
nothing more.

Corecrypto compiles under all Apple OSs, Windows, Android and Linux.

**NOTE:** This repo is a fork of the `corecrypto` source code provided at https://developer.apple.com/security. No modifications to the `corecrypto` source code have been made - only build/project files.

Building a universal (fat) binary iOS devices + simulators
------
1. cd into root repo directory

1. `xcodebuild -target corecrypto -configuration Debug -arch x86_64 -sdk iphonesimulator SYMROOT="/Users/rajohns/Downloads/corecrypto_build"`

1. `xcodebuild -target corecrypto -configuration Release -arch arm64 -sdk iphoneos SYMROOT="/Users/rajohns/Downloads/corecrypto_build"`

1. cd into `/Users/rajohns/Downloads/corecrypto_build`

1. `lipo -create Debug-iphonesimulator/libcorecrypto_static.a Release-iphoneos/libcorecrypto_static.a -output libcorecrypto_static.a`



Corecrypto Modules
------------------

Current corecrypto consists of the following submodules:

* `cc`:			  Headers and code common to all of the modules
* `ccasn1`:		  ASN.1 typeid constants and ccoid definition.
* `ccder`:		  DER encoding decoding support
* `ccn`:		  Math on vectors of n cc_units
* `cczp`:		  Modular arithmetic mod integer p, on vectors of n cc_units
* `ccz`:          Variable sized signed integer math routines
* `ccdrbg`:       Deterministic Random Byte Generators
* `ccrng`:        Random Bytes Generators
* `ccdh`:         Diffie-Hellman routines.
* `ccec25519`:    Elliptic curve signature and Diffie-Hellman routines using the Edward's 25519 curve
* `ccrsa`:        RSA routines.
* `ccec`:         Eliptic Curve Curves, ec specific math and APIs
* `ccdigest`:     Digest abstraction layer.
* `cchmac`:       HMAC using any ccdigest.
* `ccpbkdf2`:     PBKDF2 using any ccdigest.
* `ccmd2`:        MD2 digest implementations.
* `ccmd4`:        MD4 digest implementations.
* `ccmd5`:        MD5 digest implementations.
* `ccripemd`:     RIPE-MD digest implementations.
* `ccsha1`:       SHA-1 digest implementations.
* `ccsha2`:       SHA-2 digest implementations.
* `ccmode`:       Symmetric cipher chaining mode interfaces.
* `ccpad`:        Symmetric cipher padding code.
* `ccaes`:        AES symmetric cipher implementations.
* `ccblowfish`:   Blowfish symmetric cipher implementations.
* `cccast`:       Cast symmetric cipher implementations.
* `ccdes`:        DES and 3DES symmetric cipher implementations.
* `ccrc2`:        RC2 symmetric cipher implementations.
* `ccrc4`:        RC4 symmetric cipher implementations.
* `ccperf`:       Performance testing harness.
* `cctest`:       Common utilities for creating self tests and XCunit tests.
* `ccprime`:      Functions for generating large prime numbers. Mostly used in RSA key generation.
* `ccspake`:      SPAKE2+ password-based key exchange implementation.

### Module Subdirectories

Each module has the following subdirectories:

* `corecrypto`:     headers for this module
* `src`:            sources for this module
* `doc`:            documentation, references, etc.
* `xcunit`:         XCTest based unit tests for this module.
* `crypto_tests`:   sources for executable tests for this module
* `test_vectors`:   test vectors for this module
* `tools`:          sources for random helper tools.

The following subdirections don't follow the module layout yet:

* `corecrypto_kext`:   Supporting files for kernel extension build and fips support.
* `corecrypto_dylib`:  Supporting files for userspace shared lib build and fips support.
