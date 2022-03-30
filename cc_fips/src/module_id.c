/* Copyright (c) (2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <string.h>
#include <stdio.h>

#include <corecrypto/cc_config.h>

#include "module_id.h"

//
//  Provide string version of the FIPS 140-x Validated corecrypto Module
//
extern const char *cc_module_id(enum cc_module_id_format outformat)
{
    static char moduleID[256] = { 0 };
    const size_t length = sizeof(moduleID);

#define moduleBaseName "Apple corecrypto Module" // Module Base Name
#define moduleVersion "11.1"                     // 2020 OS Releases

#if CC_USE_L4                           /* Apple Silicon SEP */
#define moduleTarget "Secure Key Store" // Target Environment
#define moduleType "Hardware"           // Hardware SEP:SKS
#elif CC_KERNEL
#define moduleTarget "Kernel" // Target Environment
#define moduleType "Software" // Hardware / Software
#else
#define moduleTarget "User"   // Target Environment
#define moduleType "Software" // Hardware / Software
#endif

#if defined(__x86_64__)        // macOS/Intel
#define moduleProc "Intel"     // Intel-based Macs
#else                          // Apple Silicon based OSes
#define moduleProc "Apple ARM" // All SoC-based Platforms
#endif                         // Apple Silicon based OSes

    switch (outformat) {
    case cc_module_id_Full: {
        // <moduleBaseName> v<moduleVersion> [<moduleProc>, <moduleTarget>, <moduleType>]
        // Apple corecrypto Module v11.1 [Apple Silicon, Secure Key Store, Hardware]
        /// snprintf can be a macro, and thus requires the ()
        (snprintf)(moduleID, length, "%s v%s [%s, %s, %s]", moduleBaseName, moduleVersion, moduleProc, moduleTarget, moduleType);
    } break;
    case cc_module_id_Version:
        (snprintf)(moduleID, length, "%s", moduleVersion);
        break;
    case cc_module_id_Target:
        (snprintf)(moduleID, length, "%s", moduleTarget);
        break;
    case cc_module_id_Proc:
        (snprintf)(moduleID, length, "%s", moduleProc);
        break;
    case cc_module_id_Name:
        (snprintf)(moduleID, length, "%s", moduleBaseName);
        break;
    case cc_module_id_Type:
        (snprintf)(moduleID, length, "%s", moduleType);
        break;
    }

    return moduleID;
}
