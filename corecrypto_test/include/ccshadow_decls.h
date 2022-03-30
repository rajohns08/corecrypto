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

#ifndef CCSHADOW_DECL
#error Define CCSHADOW_DECL before including this file
#endif

#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <mach/mach_time.h>
#include "cc_config.h"

CCSHADOW_DECL(open,
              int,
              (const char *path, int oflag, mode_t mode),
              (path, oflag, mode));

CCSHADOW_DECL(read,
              ssize_t,
              (int fildes, void *buf, size_t nbyte),
              (fildes, buf, nbyte));

CCSHADOW_DECL(write,
              ssize_t,
              (int fildes, const void *buf, size_t nbyte),
              (fildes, buf, nbyte));

CCSHADOW_DECL(close,
              int,
              (int fildes),
              (fildes));

CCSHADOW_DECL(fchmod,
              int,
              (int fildes, mode_t mode),
              (fildes, mode));

CCSHADOW_DECL(fchown,
              int,
              (int fildes, uid_t owner, gid_t group),
              (fildes, owner, group));

CCSHADOW_DECL(getentropy,
              int,
              (void *buf, size_t buflen),
              (buf, buflen));

CCSHADOW_VOID_DECL(cc_abort,
                   (const char *msg),
                   (msg));

CCSHADOW_DECL(cc_rdrand,
              bool,
              (uint64_t *rand),
              (rand));



#define CCSHADOW_NONCE_DECL(funcname) CCSHADOW_DECL(funcname, uint64_t, (void), ());

#if CC_USE_L4
CCSHADOW_NONCE_DECL(ert_time_now)
#elif CC_KERNEL
CCSHADOW_NONCE_DECL(mach_absolute_time)
#elif CC_DARWIN
CCSHADOW_NONCE_DECL(mach_absolute_time)
#elif defined(_WIN32)
CCSHADOW_NONCE_DECL(cc_absolute_time)
#elif CC_LINUX
#if CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
CCSHADOW_NONCE_DECL(mach_absolute_time)
#else
CCSHADOW_NONCE_DECL(cc_absolute_time)
#endif
#endif
