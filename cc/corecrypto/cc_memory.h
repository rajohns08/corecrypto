/* Copyright (c) (2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "cc_config.h"

#ifndef corecrypto_cc_memory_h
#define corecrypto_cc_memory_h

#if CORECRYPTO_DEBUG && !defined(_WIN32) && !defined(_WIN64)
#define CC_ALLOC_DEBUG 1
#endif

struct ws_dbg {
    const void *p;
    const char *file;
    int line;
    const char *func;
};

#if defined(CC_ALLOC_DEBUG)
extern struct ws_dbg g_ws_dbg;
#endif

#include <corecrypto/cc_config.h>
#include <corecrypto/cc_error.h>
#include "cc_debug.h"
#include <corecrypto/cc_priv.h>

CC_INLINE void cc_alloc_debug(CC_UNUSED const void *p, CC_UNUSED const char *file, CC_UNUSED int line, CC_UNUSED const char *func)
{
#if defined(CC_ALLOC_DEBUG)
    // Contract for some client is to have a single malloc at a time
    cc_assert(g_ws_dbg.p == NULL);
    g_ws_dbg = (struct ws_dbg){ p, file, line, func };
#endif
}

CC_INLINE void cc_free_debug(CC_UNUSED const void *p)
{
#if defined(CC_ALLOC_DEBUG)
    // Contract for some client is to have a single malloc at a time
    cc_assert(g_ws_dbg.p == p); // Free the address we allocated
    g_ws_dbg = (struct ws_dbg){};
#endif
}

// =============================================================================
//   Declare workspace with memory in STACK
//  This is the least preferred option since most corecrypto client have
//  small stack. It is still useful when needing small allocations and errors
//  can't be easily propagated
// =============================================================================

// Declare a variable in stack and use its address
// Only uses this when we don't have a way to propagate error
#define CC_DECL_WORKSPACE_STACK(ws, n)                 \
    cc_unit ws##_buf[(n)];                             \
    cc_ws ws##_ctx = { &ws##_buf[0], &ws##_buf[(n)] }; \
    cc_ws_t ws = &ws##_ctx;                            \
    cc_alloc_debug(ws->start, __FILE__, __LINE__, __func__);

// Reset pointers to avoid future reference
#define CC_FREE_WORKSPACE_STACK(ws)  \
    cc_free_debug(ws->start);        \
    ws->start = NULL;                \
    ws->end = NULL;

#define CC_CLEAR_AND_FREE_WORKSPACE_STACK(ws)             \
    cc_try_abort_if(ws->start > ws->end, "free ws");      \
    ccn_clear((cc_size)(ws->end - ws->start), ws->start); \
    CC_FREE_WORKSPACE_STACK(ws);

// =============================================================================
//   Declare workspace in the region correspding to HEAP or STACK
// depending on the setting of CC_USE_HEAP_FOR_WORKSPACE
// This should be the preference for large memory allocations but it requires
// to propagate error in case of allocation failure
// =============================================================================
#if CC_USE_HEAP_FOR_WORKSPACE

// Malloc/free functions to be used
#if CC_KERNEL
#include <IOKit/IOLib.h>
#include <vm/pmap.h>
CC_INLINE void *cc_malloc_clear(size_t s)
{
    void *p = NULL;
    if (pmap_in_ppl()) {
        if (s > PAGE_SIZE) {
            panic("PPL cc_malloc_clear trying to allocate %zu > PAGE_SIZE", s);
        }

        p = pmap_claim_reserved_ppl_page();
    } else {
        p = IOMalloc(s);
    }
    if (p != NULL) {
        memset(p, 0, s);
    }
    return p;
}
CC_INLINE void cc_free(void *p, size_t size)
{
    if (pmap_in_ppl()) {
        if (size > PAGE_SIZE) {
            panic("PPL cc_malloc_clear trying to free %zu > PAGE_SIZE", size);
        }

        pmap_free_reserved_ppl_page(p);

        return;
    }

    IOFree(p, size);
}
#else // !CC_KERNEL
#include <stdlib.h>
CC_INLINE void *cc_malloc_clear(size_t s)
{
    void *p = malloc(s);
    if (p != NULL) {
        memset(p, 0, s);
    }
    return p;
}
CC_INLINE void cc_free(void *p, size_t size CC_UNUSED)
{
    free(p);
}

#endif // !CC_KERNEL

#define CC_DECL_WORKSPACE_OR_FAIL(ws, n)               \
    cc_unit *ws##_buf = (cc_unit *) cc_malloc_clear(ccn_sizeof_n((n)));  \
    cc_ws ws##_ctx = { &ws##_buf[0], &ws##_buf[(n)] }; \
    cc_ws_t ws = &ws##_ctx;                            \
    if (NULL == ws->start)                             \
        return CCERR_MEMORY_ALLOC_FAIL;                \
    cc_alloc_debug(ws->start, __FILE__, __LINE__, __func__);

// Free and reset pointers to avoid future references
#define CC_FREE_WORKSPACE(ws)                                                 \
    cc_free_debug(ws->start);                                                 \
    cc_try_abort_if(ws->start > ws->end, "free ws");                          \
    cc_free(ws->start, (size_t)(ws->end - ws->start) * sizeof(ws->start[0])); \
    ws->start = NULL;                                                         \
    ws->end = NULL;

#else // !CC_USE_HEAP_FOR_WORKSPACE

// Declare a variable in stack and use its address
// Could use alloca but alloca is not so portable, and not secure.
#define CC_DECL_WORKSPACE_OR_FAIL CC_DECL_WORKSPACE_STACK

// Reset pointers to avoid future reference
#define CC_FREE_WORKSPACE CC_FREE_WORKSPACE_STACK

#endif // !CC_USE_HEAP_FOR_WORKSPACE

// =============================================================================
//   Common
// =============================================================================

#define CC_CLEAR_AND_FREE_WORKSPACE(ws)                       \
        cc_try_abort_if(ws->start > ws->end, "clear ws");     \
        ccn_clear((cc_size)(ws->end - ws->start), ws->start); \
        CC_FREE_WORKSPACE(ws);

// To allocate array of n cc_unit in the WS
#define CC_DECL_BP_WS(ws, bp) cc_unit *bp = ws->start;
#define CC_FREE_BP_WS(ws, bp) ws->start = bp;
#define CC_ALLOC_WS(ws, n) \
    ws->start;             \
    ws->start += n;        \
    cc_try_abort_if(ws->start > ws->end, "alloc ws");

#if CC_KERNEL
#include <libkern/section_keywords.h>
#define CC_READ_ONLY_LATE(_t) SECURITY_READ_ONLY_LATE(_t)
#else
#define CC_READ_ONLY_LATE(_t) _t
#endif

#endif // corecrypto_cc_memory_h
