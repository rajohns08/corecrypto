/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include "cc.h"
#include "cc_memory.h"
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>
#include "ccdh_internal.h"
#include "cc_error.h"

// Lists of groups that are included with different build target libraries, so we can conditionally compile
// small lists of groups to the correct for the appropriate targets
#define CCDH_CORE_GROUP_LIST \
    ccdh_gp_rfc5114_MODP_1024_160(), \
    ccdh_gp_rfc5114_MODP_2048_224(), \
    ccdh_gp_rfc5114_MODP_2048_256(), \
    ccdh_gp_rfc3526group05(), \
    ccdh_gp_rfc3526group14(), \
    ccdh_gp_rfc3526group15(), \
    ccdh_gp_rfc3526group16(), \
    ccdh_gp_rfc3526group17(), \
    ccdh_gp_rfc3526group18()

#define CCDH_RTKIOS_GROUP_LIST CCDH_CORE_GROUP_LIST
#define CCDH_RTKITROM_GROUP_LIST CCDH_CORE_GROUP_LIST
#define CCDH_IBOOT_GROUP_LIST CCDH_CORE_GROUP_LIST

#define CCDH_EFI_GROUP_LIST \
    CCDH_CORE_GROUP_LIST, \
    ccsrp_gp_rfc5054_1024(), \
    ccsrp_gp_rfc5054_2048(), \
    ccsrp_gp_rfc5054_3072(), \
    ccsrp_gp_rfc5054_4096(), \
    ccsrp_gp_rfc5054_8192()

#define CCDH_L4_GROUP_LIST \
    ccdh_gp_apple768(), \
    ccdh_gp_rfc2409group02()

// Functions to compare a given cc_n number to a prime in a known group
static uint8_t compare_prime(cc_size np, cc_unit *p, ccdh_const_gp_t group)
{
    cc_size num_length = ccn_n(np, p); // Length without leading 0's.
    return (uint8_t)ccn_cmpn(num_length, p, CCDH_GP_N(group), CCDH_GP_PRIME(group));
}

// Functions to compare a given cc_n number to a generator in a known group
static uint8_t compare_generator(cc_size np, const cc_unit *p, ccdh_const_gp_t group)
{
    cc_size num_length = ccn_n(np, p); // Length without leading 0's.
    cc_size g_length = ccn_n(CCDH_GP_N(group), CCDH_GP_G(group));
    return (uint8_t)ccn_cmpn(num_length, p, g_length, CCDH_GP_G(group));
}

// Largest Prime of Groups we're checking
#define MAX_PRIME_BITS 8192

// Function looks up prime and generator to see if they correspond to any pre-specified groups.
static int ccdh_memory_workspace_lookup_gp(size_t g_nbytes, uint8_t *g, size_t p_nbytes, uint8_t *p, ccdh_const_gp_t *result)
{
    *result = NULL;    //Make sure we return a NULL if we quit on errors in workspace macros.
    const cc_size max_blob_n = ccn_sizeof(MAX_PRIME_BITS);
    CC_DECL_WORKSPACE_OR_FAIL(ws, max_blob_n*2);
    
    // Inputs come in as Big Endian blobs and we need to convert them to little endian. The following buffers hold
    // these values.
    CC_DECL_BP_WS(ws, bp);
    cc_unit *tmp_p=CC_ALLOC_WS(ws, max_blob_n);
    cc_unit *tmp_g=CC_ALLOC_WS(ws, max_blob_n);
    
    // Canonicalize input to little endian, and strip leading zeros.
    if (ccn_read_uint(max_blob_n, tmp_p, p_nbytes, p) == -1) {
        *result=NULL;
        CC_FREE_BP_WS(ws, bp); // Free memory workspace
        CC_CLEAR_AND_FREE_WORKSPACE(ws);
        return CCERR_OK;
    }
    if (ccn_read_uint(max_blob_n, tmp_g, g_nbytes, g) == -1) {
        *result = NULL;
        CC_FREE_BP_WS(ws, bp); // Free memory workspace
        CC_CLEAR_AND_FREE_WORKSPACE(ws);
        return CCERR_OK;
    }
    
    // Check inputs against all known groups with ccn formated inputs.
    *result = ccdh_ccn_lookup_gp (max_blob_n, tmp_p, max_blob_n, tmp_g);

    CC_FREE_BP_WS(ws, bp); // Free memory workspace
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return CCERR_OK;
}

// Equivalent to ccdh_lookup_gp, but inputs are provided in cc_unit format.
// Inputs are a prime and generator, and output is a known ccdh group if prime and generator correspond to known list
// Function is used in preventing users from accidentally allowing small subgroups on well known groups.
ccdh_const_gp_t ccdh_ccn_lookup_gp(cc_size pn, cc_unit *p, cc_size gn, cc_unit *g)
{
    // Array of known groups that we are going to check the incoming prime and generator against.
    // The order in this array attempts to optimize the linear lookup in practice, by starting with common groups
    // We only include groups that are appropriate for corresponding library build targets.

    ccdh_const_gp_t known_groups[] = {
#if CC_USE_L4
        CCDH_L4_GROUP_LIST,
#elif CC_RTKIT
        CCDH_RTKIOS_GROUP_LIST,
#elif CC_RTKITROM
        CCDH_RTKITROM_GROUP_LIST,
#elif CC_IBOOT
        CCDH_IBOOT_GROUP_LIST,
#elif CC_EFI
        CCDH_EFI_GROUP_LIST,
#else
        CCDH_L4_GROUP_LIST,
        CCDH_EFI_GROUP_LIST,
        CCDH_CORE_GROUP_LIST,
#endif
    };
    
    // Compute the number of groups in the array
    int num_known_groups = sizeof(known_groups) / sizeof(known_groups[0]);

    // Check inputs against all known groups;
    ccdh_const_gp_t known_group;
    for (int i = 0; i < num_known_groups; i++) {
        known_group = known_groups[i];
        
        if (compare_prime(pn, p, known_group) != 0) {
            continue;
        }
        if (compare_generator(gn, g, known_group) != 0) {
            continue;
        }
        return known_group;
    }
    
    // Failing through the list implies the group is not known.
    known_group = NULL;
    return known_group;
}

// This is a wrapper function to hide the memory management complexity enforced by
// by using core crypto's memory workspaces.
ccdh_const_gp_t ccdh_lookup_gp(size_t p_nbytes, uint8_t *p, size_t g_nbytes, uint8_t *g)
{
    ccdh_const_gp_t result;
    if (CCERR_OK != ccdh_memory_workspace_lookup_gp(p_nbytes, p, g_nbytes, g, &result)) {
        return NULL;
    }
    return result;
}
