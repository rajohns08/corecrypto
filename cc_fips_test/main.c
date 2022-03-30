/* Copyright (c) (2012,2014-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>

#include <corecrypto/fipspost.h>
#include "fipspost_get_hmac.h"
#include "fipspost_trace.h"
#include "fipspost_trace_priv.h"
#include "module_id.h"

static void usage(const char *argv[]);
static struct mach_header *fipspost_dylib_get_header(void);

static void usage(const char *argv[])
{
    fprintf(stderr,
            "Usage: %s [-vfFN] [-m mode] [-t trace.out]\n\n"
            "Execute the FIPS POST tests under a variety of conditions.\n"
            "\t-v,--verbose    \tIncrease logging.\n"
            "\t-f,--force      \tFull test set.\n"
            "\t-F,--fail       \tForce tests to fail, but continue testing.\n"
            "\t-N,--nointegrity\tBypass the integrity checks.\n"
            "\t-m,--mode mode  \tSpecify a discrete numerical fips_mode to test.\n"
            "\t-t,--trace file \tLog tracing output, if available, to the filename.\n"
            "\t                \tReturn an error if tracing is disabled.\n"
            "%s\n"
            , argv[0], cc_module_id(cc_module_id_Full));
    exit(-1);
}

static struct mach_header *fipspost_dylib_get_header(void)
{
    // Get information about the dylib
    Dl_info dylib_info;
    memset(&dylib_info, 0, sizeof(dylib_info));
    if (!dladdr(fipspost_post, &dylib_info)) {
        fprintf(stderr, "dladdr failed\n");
        return NULL;
    }

    return (struct mach_header *)dylib_info.dli_fbase;
}

static int fipspost_trace_writer(void *ctx, const uint8_t *buf, size_t len)
{
    FILE *f = (FILE *)ctx;
    size_t ret = fwrite(buf, 1, len, f);
    if (ret != len) {
        return -1;
    }
    return 0;
}

struct fips_config {
    bool initialized;
    uint32_t fips_mode;
    const char *trace_fname;
};

static void initconfig(struct fips_config *config, int argc, const char **argv)
{
    /* initialize first from command-line arguments */
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose")) {
            config->fips_mode |= FIPS_MODE_FLAG_VERBOSE;
        } else if (!strcmp(arg, "-f") || !strcmp(arg, "--force")) {
            config->fips_mode |= FIPS_MODE_FLAG_FULL;
        } else if (!strcmp(arg, "-F") || !strcmp(arg, "--fail")) {
            config->fips_mode |= FIPS_MODE_FLAG_FORCEFAIL;
        } else if (!strcmp(arg, "-N") || !strcmp(arg, "--nointegrity")) {
            config->fips_mode |= FIPS_MODE_FLAG_NOINTEG;
        } else if (!strcmp(arg, "-m") || !strcmp(arg, "--mode")) {
            config->fips_mode = (uint32_t)strtoll(argv[++i], NULL, 10);
        } else if (!strcmp(arg, "-t") || !strcmp(arg, "--trace")) {
            config->trace_fname = argv[++i];
        } else {
            usage(argv);
        }

        config->initialized = 1;
    }

    /* in the absence of command-line arguments, initialize from boot-args */
    if (!config->initialized) {
        char boot_args_buffer[1024] = {};
        size_t boot_args_buffer_size = sizeof(boot_args_buffer);

        int err = sysctlbyname("kern.bootargs", boot_args_buffer, &boot_args_buffer_size, NULL, 0);
        if (err == 0) {
            char* fips_str = strcasestr(boot_args_buffer, "fips_mode");
            if (NULL != fips_str) {
                fprintf(stderr, "A fips_mode boot arg was set: %s\n", fips_str);
                fflush(stderr);
                int n = sscanf(fips_str, "fips_mode=%d",  &config->fips_mode);
                if (n == 1) {
                    config->initialized = 1;
                }
            }
        }
    }

    /*
      in the absence of boot-args, default to FIPS_MODE_FLAG_FULL
      which means to run the FIPS POST and if an error happens log it
      but do not fail and allow the system to boot
    */
    if (!config->initialized) {
        config->fips_mode = FIPS_MODE_FLAG_FULL;
    }

    /* this flag cannot be set directly */
    /* its value is implied by the presence or absence of a filename */
    if (config->trace_fname) {
        config->fips_mode |= FIPS_MODE_FLAG_TRACE;
    } else {
        config->fips_mode &= ~(uint32_t)FIPS_MODE_FLAG_TRACE;
    }
}

static int fipspost(struct fips_config *config)
{
    uint32_t fips_mode = config->fips_mode;
    int fipspost_result = CCPOST_GENERIC_FAILURE;
    FILE *fipstrace_out = NULL;
    fipspost_trace_vtable_t fipstrace_vtab = fipspost_trace_vtable;

    if (fips_mode == 0) {
        fprintf(stderr, "Bypassing FIPS mode for user space!\n");
        fflush(stderr);
        return CCERR_OK;
    }

    // Run the POST tests
    if (FIPS_MODE_IS_VERBOSE(fips_mode)) {
        fprintf(stderr, "About to call the FIPS_POST function in the corecrypto.dylib\n");
        fflush(stderr);
    }

    if (FIPS_MODE_IS_TRACE(fips_mode)) {
        if (fipstrace_vtab == NULL) {
            fprintf(stderr, "Tracing: disabled, not available.\n");
            fprintf(stderr, "Tracing required by test parameters; exiting.\n");
            exit(-1);
        }

        if (config->trace_fname) {
            fprintf(stderr, "Tracing: enabled\n");
            fipstrace_out = fopen(config->trace_fname, "w");
            (*fipstrace_vtab->fipspost_trace_start)(fips_mode, fipspost_trace_writer, fipstrace_out);
        }
    } else {
        fprintf(stderr, "Tracing: disabled%s\n", fipstrace_vtab == NULL ? "" : ", but available.");
    }

    fipspost_result = fipspost_post(fips_mode, fipspost_dylib_get_header());

    if (FIPS_MODE_IS_VERBOSE(fips_mode))
    {
        fprintf(stderr, "Returned from calling the FIPS_POST function in the corecrypto.dylib: result = %s\n", (fipspost_result==0) ? "true" : "false");
        fflush(stderr);
    }

    if ((fipspost_result != 0) && FIPS_MODE_IS_FULL(fips_mode))
    {
        fprintf(stderr, "FIPS_POST failed!\n");
        fflush(stderr);
    }

    if (fipstrace_out) {
        int ret = (fipstrace_vtab->fipspost_trace_end)((uint32_t)fipspost_result);
        fprintf(stderr, "Tracing returned: %d\n", ret);
        fclose(fipstrace_out);
    }

    return fipspost_result;
}

// The current Assumption is that FIPS will be on all of the time.
// If that assumption changes this code must change
int main(int argc, const char **argv)
{
    int fipspost_result;
    struct fips_config config = {};

    initconfig(&config, argc, argv);
    fipspost_result = fipspost(&config);

    return fipspost_result;
}
