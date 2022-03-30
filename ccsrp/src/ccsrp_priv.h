/* Copyright (c) (2012-2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCSRP_PRIV_H_
#define _CORECRYPTO_CCSRP_PRIV_H_

#include <stddef.h>
#include <corecrypto/cc.h>
#include "cc_debug.h"
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccsrp.h>
#include "ccdh_internal.h"
#include "cczp_internal.h"
#include <corecrypto/cc_macros.h>

/* Context Dump

 The current context is mapped space containing:

 digest di pointer
 gp pointer
 blinding rng
 authenticated boolean flag (bit field size 1)
 noUsernameInX boolean flag (bit field size 1)
 sessionkey boolean flag (bit field size 1)
 variant (bit field size 16)
 padding to 32 bytes
 cc_unit[n] public key
 cc_unit[n] private key
 cc_unit[n] verifier
 cc_unit[n] shared key (S)
 uint8_t[di->output_size] session key (K)
 [ spare space ]
 uint8_t[di->output_size] M
 uint8_t[di->output_size] HAMK
*/

CC_INLINE const uint8_t *dump_hex(const uint8_t *p, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        cc_printf("%02x", *p);
        p++;
    }
    cc_printf("\n");
    return p;
}

CC_INLINE void dump_hex_label(char *label, const uint8_t *p, size_t len)
{
    cc_printf(">>>>> %s: ", label);
    dump_hex(p, len);
}

CC_INLINE void dump_ctx(char *label, ccsrp_ctx_t srp)
{
    const uint8_t *p = (const uint8_t *)srp;

    size_t bytes_n = ccsrp_exchange_size(srp);
    size_t bytes_d = ccsrp_session_size(srp);
    size_t bytes_s = ccsrp_get_session_key_length(srp);

    cc_printf("______________________%s start ________________________\n\n", label);
    cc_printf("\nHeader Pointers, etc\n");
    p = dump_hex(p, offsetof(struct ccsrp_ctx, ccn));
    cc_printf("public  key: ");
    p = dump_hex(p, bytes_n);
    cc_printf("private key: ");
    p = dump_hex(p, bytes_n);
    cc_printf("verifier(v): ");
    p = dump_hex(p, bytes_n);
    cc_printf("shared key(S): ");
    p = dump_hex(p, bytes_n);
    cc_printf("session key(K): ");
    p = dump_hex(p, bytes_s);
    p += 2 * bytes_d - bytes_s;
    cc_printf("          M: ");
    p = dump_hex(p, bytes_d);
    cc_printf("       HAMK: ");
    dump_hex(p, bytes_d);
    cc_printf("______________________%s end   ________________________\n\n", label);
}

CC_INLINE void srp_lprint(cc_size n, const char *label, const cc_unit *s)
{
    cc_printf(">>>>> %s: ", label);
    dump_hex((const uint8_t *)s, ccn_sizeof_n(n));
    cc_printf("\n");
}

CC_NONNULL((1, 2, 3))
CC_INLINE size_t ccsrp_export_ccn(ccsrp_ctx_t srp, const cc_unit *a, void *bytes)
{
    return (size_t)ccn_write_uint_padded_ct(ccsrp_ctx_n(srp), a, ccsrp_ctx_sizeof_n(srp), bytes);
}

CC_NONNULL((1, 2, 3))
CC_INLINE void ccsrp_import_ccn(ccsrp_ctx_t srp, cc_unit *a, const void *bytes)
{
    ccn_read_uint(ccsrp_ctx_n(srp), a, ccsrp_ctx_sizeof_n(srp), bytes);
}

CC_NONNULL((1, 2, 4))
CC_INLINE void ccsrp_import_ccn_with_len(ccsrp_ctx_t srp, cc_unit *a, size_t len, const void *bytes)
{
    ccn_read_uint(ccsrp_ctx_n(srp), a, len, bytes);
}

CC_NONNULL((1, 2)) int ccsrp_generate_K_from_S(ccsrp_ctx_t srp, const cc_unit *S);

CC_NONNULL((1, 2, 3))
CC_INLINE
void ccsrp_digest_ccn(ccsrp_ctx_t srp, const cc_unit *s, void *dest, bool skip_leading_zeroes)
{
    size_t offset;
    uint8_t buf[ccsrp_ctx_sizeof_n(srp)]; // vla
    offset = ccsrp_export_ccn(srp, s, buf);
    if (!skip_leading_zeroes)
        offset = 0; // Leading zeroes will be hashed
    ccdigest(ccsrp_ctx_di(srp), ccsrp_ctx_sizeof_n(srp) - offset, buf + offset, dest);
}

CC_NONNULL((1, 2, 3))
CC_INLINE void
ccsrp_digest_update_ccn(ccsrp_ctx_t srp, void *ctx, const cc_unit *s, bool skip_leading_zeroes)
{
    size_t offset;
    uint8_t buf[ccsrp_ctx_sizeof_n(srp)]; // vla
    offset = ccsrp_export_ccn(srp, s, buf);
    if (!skip_leading_zeroes)
        offset = 0; // Leading zeroes will be hashed
    ccdigest_update(ccsrp_ctx_di(srp), ctx, ccsrp_ctx_sizeof_n(srp) - offset, buf + offset);
}

// Len is the number of bytes of the digest to be used for "r".
// If len==0 or len> digest length, take the entire digest
CC_NONNULL((1, 2))
CC_INLINE void ccsrp_digest_ccn_ccn(ccsrp_ctx_t srp,
                                    cc_unit *r,
                                    const cc_unit *a,
                                    const cc_unit *b,
                                    size_t len,
                                    bool skip_leading_zeroes)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    uint8_t hash[di->output_size]; // vla
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);
    if (a) {
        ccsrp_digest_update_ccn(srp, ctx, a, skip_leading_zeroes);
    }
    if (b) {
        ccsrp_digest_update_ccn(srp, ctx, b, skip_leading_zeroes);
    }
    ccdigest_final(di, ctx, hash);
    if (len > di->output_size || len <= 0)
        len = di->output_size;
    ccn_read_uint(ccsrp_ctx_n(srp), r, len, hash);
    cc_clear(di->output_size, hash);
    ccdigest_di_clear(di, ctx);
}

// x = SHA(s | SHA(U | ":" | p))
CC_NONNULL((1, 2, 3, 5, 7))
CC_INLINE void ccsrp_generate_x(ccsrp_ctx_t srp,
                                cc_unit *x,
                                const char *username,
                                size_t salt_len,
                                const void *salt,
                                size_t password_len,
                                const void *password)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    uint8_t hash[di->output_size]; // vla
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);
    if (!SRP_FLG(srp).noUsernameInX)
        ccdigest_update(di, ctx, strlen(username), username);
    ccdigest_update(di, ctx, 1, ":");
    ccdigest_update(di, ctx, password_len, password);
    ccdigest_final(di, ctx, hash);
    ccdigest_init(di, ctx);
    ccdigest_update(di, ctx, salt_len, salt);
    ccdigest_update(di, ctx, di->output_size, hash);
    ccdigest_final(di, ctx, hash);
    ccsrp_import_ccn_with_len(srp, x, di->output_size, hash);
    cc_clear(di->output_size, hash);
    ccdigest_di_clear(di, ctx);
}

CC_NONNULL((1, 2)) CC_INLINE void ccsrp_generate_k(ccsrp_ctx_t srp, cc_unit *k)
{
    ccsrp_digest_ccn_ccn(srp,
                         k,
                         ccdh_gp_prime(ccsrp_ctx_gp(srp)),
                         ccsrp_ctx_gp_g(srp),
                         0,
                         (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X));
}

CC_NONNULL((1, 2)) CC_INLINE void ccsrp_generate_v(ccsrp_ctx_t srp, cc_unit *x)
{
    ccdh_power_blinded(SRP_RNG(srp), ccsrp_ctx_gp(srp), ccsrp_ctx_v(srp), ccsrp_ctx_gp_g(srp), x);
}

CC_NONNULL((1, 2, 3, 4))
CC_INLINE void ccsrp_generate_u(ccsrp_ctx_t srp, cc_unit *u, cc_unit *A, cc_unit *B)
{
    if ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) == CCSRP_OPTION_VARIANT_SRP6a) {
        ccsrp_digest_ccn_ccn(
            srp, u, A, B, 0, (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X));
    } else {
        ccsrp_digest_ccn_ccn(srp,
                             u,
                             NULL,
                             B,
                             4, /* 32bits only */
                             (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X));
    }
}

CC_NONNULL((1, 2, 3, 4))
CC_INLINE void ccsrp_generate_server_S(ccsrp_ctx_t srp, cc_unit *S, cc_unit *u, cc_unit *A)
{
    /* S = (A *(v^u)) ^ b */
    cc_unit tmp1[ccsrp_ctx_n(srp)], tmp2[ccsrp_ctx_n(srp)]; // vla
    ccn_zero_multi(ccsrp_ctx_n(srp), tmp1, tmp2, NULL);
    // u is public, ok to use non secure exponentiation
    if (cczp_mm_power_fast(ccsrp_ctx_zp(srp), tmp1, ccsrp_ctx_v(srp), u)) {
        // should only hit this in case of invalid v
        ccn_zero(ccsrp_ctx_n(srp), S);
        goto err;
    }
    cczp_mul(ccsrp_ctx_zp(srp), tmp2, A, tmp1);
    ccdh_power_blinded(SRP_RNG(srp), ccsrp_ctx_gp(srp), S, tmp2, ccsrp_ctx_private(srp));

err:
    ccn_zero_multi(ccsrp_ctx_n(srp), tmp1, tmp2, NULL);
}

CC_NONNULL((1, 2, 3, 4, 5, 6))
CC_INLINE void
ccsrp_generate_client_S(ccsrp_ctx_t srp, cc_unit *S, cc_unit *k, cc_unit *x, cc_unit *u, cc_unit *B)
{
    /* Client Side S = (B - k*(g^x)) ^ (a + ux) */
    cc_size n = ccsrp_ctx_n(srp);
    cc_unit tmp1[2 * n], tmp2[ccsrp_ctx_n(srp)]; // vla
    ccn_zero_multi(n, tmp1, tmp2, NULL);
    cc_unit c;
    // In ccsrp_init
    // tmp1 = a + ux
    ccn_mul(n, tmp1, u, x);
    c = ccn_add(n, tmp1, ccsrp_ctx_private(srp), tmp1);
    if (2 * 8 * ccsrp_ctx_di(srp)->output_size >= ccn_bitlen(n, ccsrp_ctx_prime(srp))) {
        // if u*x is bigger than p in size, need to handle carry
        // and reduction mod p-1
        ccn_add1(n, &tmp1[n], &tmp1[n], c);
        ccn_sub1(n, tmp2, ccsrp_ctx_prime(srp), 1); // p-1
        ccn_mod(n, tmp1, 2 * n, tmp1, n, tmp2);
    } else {
        cc_assert(c == 0); // Carry is not possible here
    }

    // tmp2 = (g^x)
    ccdh_power_blinded(SRP_RNG(srp), ccsrp_ctx_gp(srp), tmp2, ccsrp_ctx_gp_g(srp), x);

    // tmp2 = k * (g^x)
    if ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) == CCSRP_OPTION_VARIANT_SRP6a) {
        cczp_mul(ccsrp_ctx_zp(srp), tmp2, k, tmp2);
    }
    // tmp2 = (B - k*(g^x))
    cczp_sub(ccsrp_ctx_zp(srp), tmp2, B, tmp2);

    // S = tmp2 ^ tmp1
    ccdh_power_blinded(SRP_RNG(srp), ccsrp_ctx_gp(srp), S, tmp2, tmp1);
    ccn_zero_multi(n, tmp1, tmp2, NULL);
}

CC_NONNULL((1, 2, 4, 5, 6))
CC_INLINE void ccsrp_generate_M(ccsrp_ctx_t srp,
                                const char *username,
                                size_t salt_len,
                                const void *salt,
                                const cc_unit *A,
                                const cc_unit *B)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    size_t hashlen = di->output_size;
    if (hashlen == 0)
        return;
    uint8_t hash_n[hashlen]; // vla
    uint8_t hash_g[hashlen]; // vla
    uint8_t H_I[hashlen];    // vla
    uint8_t H_xor[hashlen];  // vla
    ccdigest_di_decl(di, ctx);
    bool skip_leading_zeroes = (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_TOKEN);

    ccsrp_digest_ccn(srp, ccsrp_ctx_prime(srp), hash_n, skip_leading_zeroes);
    ccsrp_digest_ccn(srp, ccsrp_ctx_gp_g(srp), hash_g, skip_leading_zeroes);

    cc_xor(hashlen, H_xor, hash_n, hash_g);

    ccdigest(di, strlen(username), username, H_I);
    ccdigest_init(di, ctx);
    ccdigest_update(di, ctx, hashlen, H_xor);
    ccdigest_update(di, ctx, hashlen, H_I);
    ccdigest_update(di, ctx, salt_len, salt);
    ccsrp_digest_update_ccn(srp, ctx, A, skip_leading_zeroes);
    ccsrp_digest_update_ccn(srp, ctx, B, skip_leading_zeroes);
    ccdigest_update(di, ctx, ccsrp_get_session_key_length(srp), ccsrp_ctx_K(srp));
    ccdigest_final(di, ctx, ccsrp_ctx_M(srp));
    ccdigest_di_clear(di, ctx);
}

CC_NONNULL((1, 2)) CC_INLINE void ccsrp_generate_H_AMK(ccsrp_ctx_t srp, const cc_unit *A)
{
    const struct ccdigest_info *di = ccsrp_ctx_di(srp);
    ccdigest_di_decl(di, ctx);
    ccdigest_init(di, ctx);
    bool skip_leading_zeroes = (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_TOKEN);

    ccsrp_digest_update_ccn(srp, ctx, A, skip_leading_zeroes);
    ccdigest_update(di, ctx, ccsrp_session_size(srp), ccsrp_ctx_M(srp));
    ccdigest_update(di, ctx, ccsrp_get_session_key_length(srp), ccsrp_ctx_K(srp));
    ccdigest_final(di, ctx, ccsrp_ctx_HAMK(srp));
    ccdigest_di_clear(di, ctx);
}

CC_NONNULL((1))
CC_INLINE void ccsrp_generate_client_pubkey(ccsrp_ctx_t srp)
{
    ccdh_power_blinded(SRP_RNG(srp),
                       ccsrp_ctx_gp(srp),
                       ccsrp_ctx_public(srp),
                       ccsrp_ctx_gp_g(srp),
                       ccsrp_ctx_private(srp));
}

CC_NONNULL((1))
CC_INLINE void ccsrp_generate_server_pubkey(ccsrp_ctx_t srp, cc_unit *k)
{
    /* B = kv + g^b */
    cc_unit *kv;
    cc_unit tmp1[ccsrp_ctx_n(srp)], tmp2[ccsrp_ctx_n(srp)]; // vla
    ccn_zero_multi(ccsrp_ctx_n(srp), tmp1, tmp2, NULL);
    ccn_zero(ccsrp_ctx_n(srp), tmp1);
    if (k && ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) == CCSRP_OPTION_VARIANT_SRP6a)) {
        cczp_mul(ccsrp_ctx_zp(srp), tmp1, k, ccsrp_ctx_v(srp));
        kv = tmp1;
    } else {
        kv = ccsrp_ctx_v(srp); // k=1
    }
    ccdh_power_blinded(
        SRP_RNG(srp), ccsrp_ctx_gp(srp), tmp2, ccsrp_ctx_gp_g(srp), ccsrp_ctx_private(srp));
    cczp_add(ccsrp_ctx_zp(srp), ccsrp_ctx_public(srp), kv, tmp2);
    ccn_zero_multi(ccsrp_ctx_n(srp), tmp1, tmp2, NULL);
}

#endif /* _CORECRYPTO_CCSRP_PRIV_H_ */
