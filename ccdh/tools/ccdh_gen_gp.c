/* Copyright (c) (2011,2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

/* This tool can be used to generate group parameters as static ccdh_gp_t.
   This is using corecrypto itself
   CAVEAT: this tool can only generate the parameters for the native cc_unit size
 */

#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

#include <corecrypto/ccdh.h>
#include "cc_debug.h"

#include "appleDhGroups.h"
#include "rfc2409DhGroups.h"
#include "rfc3526DhGroups.h"
#include "rfc5114DhGroups.h"
#include "rfc5054SrpGroups.h"

/* template for header file :*/
static char *h_template =
"ccdh_const_gp_t %s(void);\n";

/* template for source file :*/
static char *c_template =
"/*\n"
" *  corecrypto\n"
" *\n"
" *  Autogenerated file - Use scheme ccdh_gen_gp\n"
" *\n"
" *  Copyright (c) 2011-2015 Apple Inc. All rights reserved.\n"
" *\n"
" */\n\n"
"/* Autogenerated file - Use scheme ccdh_gen_gp to regenerate */\n"
"#include \"ccdh_internal.h\"\n"
"#include <corecrypto/%s_gp.h>\n"
"\n"
"static ccdh_gp_decl_static(%d) _%s =\n"
"{\n"
"    .hp = {\n"
"        .n = ccn_nof(%d),\n"
"        .bitlen = %d,\n"
"        .funcs = CCZP_FUNCS_DEFAULT\n"
"    },\n"
"    .p = {\n"
"        /* prime */\n"
"        %s\n"
"    },\n"
"    .recip = {\n"
"        /* recip */\n"
"        %s\n"
"    },\n"
"    .g = {\n"
"        /* g */\n"
"        %s\n"
"    },\n"
"    .q = {\n"
"        /* q */\n"
"        %s\n"
"    },\n"
"    .l = %zu,\n"
"};\n"
"\n"
"ccdh_const_gp_t %s(void)\n"
"{\n"
"    return (ccdh_const_gp_t)&_%s;\n"
"}\n";

static void sprint_ccnc(char **s, const cc_unit *u, size_t bytes)
{
    bool comma = false;
    *s += sprintf(*s, "CCN%zu_C(", bytes * 8);
    for (size_t i = ((bytes + CCN_UNIT_SIZE - 1) / CCN_UNIT_SIZE); i-- > 0;) {
        cc_unit v = u[i];
        for (size_t j = (CCN_UNIT_SIZE - bytes) % CCN_UNIT_SIZE;
             j < CCN_UNIT_SIZE && bytes > 0; ++j, --bytes) {
            uint8_t byte = (uint8_t)(v >> ((CCN_UNIT_SIZE - 1 - j) * 8));
            *s += sprintf(*s, "%s%.02" PRIx8, comma ? "," :"", byte);
            comma = true;
        }
    }
    *s += sprintf(*s, ")");
}

static void sprint_ccunits(char *s, cc_size n, const cc_unit *u)
{
    size_t i;
    size_t n8 = ((n * CCN_UNIT_SIZE)-1) / 8;
    for (i = 0; i < n8; ++i) {
        if (i)
            s += sprintf(s, ",");
        if ((i%2)==0 && i <= n8 && i) {s += sprintf(s, "\n        ");};
        sprint_ccnc(&s, u, 8);
        u += 8 / CCN_UNIT_SIZE;
    }

    size_t remainder = n * CCN_UNIT_SIZE - n8 * 8;
    if (remainder) {
        size_t bytes_todo = ccn_write_uint_size(remainder / CCN_UNIT_SIZE, u);
        if (!bytes_todo)
            bytes_todo = 1;
        u += (remainder - bytes_todo) / CCN_UNIT_SIZE;
        s += sprintf(s, ",");
        if ((i%2)==0 && i <= n8 && i) {s += sprintf(s, "\n        ");};
        sprint_ccnc(&s, u, bytes_todo);
    }
}

/* Debugger does not like stack arrays with variable size */
#if 0
#define strsize(n) ((n)*(CCN_UNIT_SIZE*4+9))
#else
#define strsize(n) (8192)
#endif

#define H_FILENAME "%s/ccdh/corecrypto/ccdh_gp.h"
#define C_FILENAME "%s/%s/src/%s.c"

static void print_params(FILE *hfile, const char *path, const char *inc, const char *name, ccdh_const_gp_t gp)
{
    FILE *cfile;
    cc_size n = ccdh_gp_n(gp);

    char prime[strsize(n)+n];
    char recip[strsize(n+1)+n];
    char g[strsize(n)+n];
    char q[strsize(n)+n];
    char filename[strlen(C_FILENAME)+strlen(path)+strlen(inc)+strlen(name)];
    size_t l = ccdh_gp_l(gp);

    sprint_ccunits(prime, n, ccdh_gp_prime(gp));
    sprint_ccunits(recip, n+1, ccdh_gp_recip(gp));
    sprint_ccunits(g, n, ccdh_gp_g(gp));
    sprint_ccunits(q, n, ccdh_gp_order(gp));

    sprintf(filename, C_FILENAME, path, inc, name);

    cfile=fopen(filename, "w");
    assert(cfile!=NULL);

    fprintf(cfile, c_template, inc, ccn_bitsof_n(n), name, ccn_bitsof_n(n),
            ccn_bitlen(n, ccdh_gp_prime(gp)), prime, recip, g, q, l, name, name);
    fprintf(hfile, h_template, name);

    fclose(cfile);

}

#define GROUP_VECTOR(_group_) \
    .pLen = sizeof(_group_.p),          \
    .p = _group_.p,                     \
    .gLen = sizeof(_group_.g),          \
    .g = _group_.g,                     \
    .qLen = sizeof(_group_.q),          \
    .q = _group_.q,                     \
    .lLen = sizeof(_group_.l),          \
    .l = _group_.l,                     \

#define GROUP_VECTOR_NO_ORDER(_group_)  \
    .pLen = sizeof(_group_.p),          \
    .p = _group_.p,                     \
    .gLen = sizeof(_group_.g),          \
    .g = _group_.g,                     \
    .qLen = 0,                          \
    .q = NULL,                          \
    .lLen = sizeof(_group_.l),          \
    .l = _group_.l,                     \


#define GROUP_VECTOR_DH(_len_, _group_) \
{                                       \
    .len  = _len_,                      \
    .inc  = "ccdh",                     \
    .name = "ccdh_gp_" #_group_,        \
    GROUP_VECTOR(_group_) \
}

#define GROUP_VECTOR_DH_NO_ORDER(_len_, _group_) \
{                                       \
    .len  = _len_,                      \
    .inc  = "ccdh",                     \
    .name = "ccdh_gp_" #_group_,        \
    GROUP_VECTOR_NO_ORDER(_group_) \
}

#define GROUP_VECTOR_SRP_NO_ORDER(_len_, _group_)\
{                                       \
    .len = _len_,                       \
    .inc  = "ccsrp",               \
    .name = "ccsrp_gp_" #_group_,       \
    GROUP_VECTOR_NO_ORDER(_group_) \
}

static struct ccdh_gen_vectors {
    unsigned int len;
    char *inc;
    char *name;
    size_t pLen;
    const uint8_t *p;
    size_t gLen;
    const uint8_t *g;
    size_t qLen;
    const uint8_t *q;
    size_t lLen;
    const uint8_t *l;
} dh_gen_vectors[] = {
    GROUP_VECTOR_DH_NO_ORDER(768, apple768),

    GROUP_VECTOR_DH(1024, rfc5114_MODP_1024_160),
    GROUP_VECTOR_DH(2048, rfc5114_MODP_2048_224),
    GROUP_VECTOR_DH(2048, rfc5114_MODP_2048_256),

    GROUP_VECTOR_DH_NO_ORDER(1024, rfc2409group02),

    GROUP_VECTOR_DH_NO_ORDER(1536, rfc3526group05),
    GROUP_VECTOR_DH_NO_ORDER(2048, rfc3526group14),
    GROUP_VECTOR_DH_NO_ORDER(3072, rfc3526group15),
    GROUP_VECTOR_DH_NO_ORDER(4096, rfc3526group16),
    GROUP_VECTOR_DH_NO_ORDER(6144, rfc3526group17),
    GROUP_VECTOR_DH_NO_ORDER(8192, rfc3526group18),

    GROUP_VECTOR_SRP_NO_ORDER(1024, rfc5054_1024),
    GROUP_VECTOR_SRP_NO_ORDER(2048, rfc5054_2048),
    GROUP_VECTOR_SRP_NO_ORDER(3072, rfc5054_3072),
    GROUP_VECTOR_SRP_NO_ORDER(4096, rfc5054_4096),
    GROUP_VECTOR_SRP_NO_ORDER(8192, rfc5054_8192),
};

#define N_GROUPS (sizeof(dh_gen_vectors)/sizeof(dh_gen_vectors[0]))

static void generate_static_groups(const char *path)
{
    FILE *hfile;
    char hfilename[strlen(H_FILENAME)+strlen(path)];
    sprintf(hfilename, H_FILENAME, path);
    hfile=fopen(hfilename, "w");
    assert(hfile!=NULL);

    fprintf(hfile,
    "/*\n"
    " *  corecrypto\n"
    " *\n"
    " *  Autogenerated file - Use scheme ccdh_gen_gp\n"
    " *\n"
    " *  Copyright (c) 2011-2018 Apple Inc. All rights reserved.\n"
    " *\n"
    " */\n\n"

    "/* Autogenerated file - Use scheme ccdh_gen_gp to regenerate */\n");
    fprintf(hfile, "#ifndef _CORECRYPTO_CCDH_GP_H_\n");
    fprintf(hfile, "#define _CORECRYPTO_CCDH_GP_H_\n\n");
    fprintf(hfile, "#include <corecrypto/ccdh.h>\n\n");

    for(unsigned int i=0; i<N_GROUPS; i++) {
        struct ccdh_gen_vectors *v = &dh_gen_vectors[i];
        const cc_size n = ccn_nof(v->len);
        ccdh_gp_decl(ccn_sizeof(v->len), gp);
        cc_unit p[n];
        cc_unit g[n];
        cc_unit q[n];
        cc_size l = 0;

        ccn_read_uint(n, p, v->pLen, v->p); /* Prime */
        ccn_read_uint(n, g, v->gLen, v->g); /* Generator */
        for (size_t j = 0; j < v->lLen; ++j) /* Private key length */
            l = (l << 8) |  v->l[j];

        // Order is optional
        if (v->qLen && v->q!=NULL){
            ccn_read_uint(n, q, v->qLen, v->q);
            ccdh_init_gp_with_order(gp, n, p, g, q);
        }
        else {
            ccdh_init_gp(gp, n, p, g, l);
        }

        print_params(hfile, path, v->inc, v->name, gp);
    }

    fprintf(hfile, "\n#endif /* _CORECRYPTO_CCDH_GP_H_ */\n");

    fclose(hfile);
}

int main (void)
{
    // insert code here...
    char *path=getenv("DIR");

    cc_printf("Generating files in %s\n", path);

    generate_static_groups(path);

    return 0;
}
