/* Copyright (c) (2018-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef crypto_test_primality_runner_h
#define crypto_test_primality_runner_h

#include "ccdict.h"

/*!
 * @function crypto_test_primality_runner
 * @abstract Run a primality test vector with the test vector data.
 * @param vector A `ccdict_t` containing all the relevant test vector data.
 * @return True if the test passed, and false otherwise.
 */
CC_NONNULL((1))
bool
crypto_test_primality_runner(ccdict_t vector);

#endif /* crypto_test_primality_runner_h */

