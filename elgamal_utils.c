#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include "elgamal_utils.h"

#define BYTE 8

void gcd_bn(const BIGNUM *a, const BIGNUM *b, BIGNUM *result, BN_CTX *ctx)
{
    BN_CTX_start(ctx);
    BIGNUM *r0 = BN_CTX_get(ctx);
    BIGNUM *r1 = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);

    BN_copy(r0, a);
    BN_copy(r1, b);

    while (!BN_is_zero(r1)) {
        BN_mod(tmp, r0, r1, ctx);  // tmp = r0 % r1
        BN_copy(r0, r1);           // r0 = r1
        BN_copy(r1, tmp);          // r1 = tmp
    }

    BN_copy(result, r0);  // result = gcd
    BN_CTX_end(ctx);
}

void extended_gcd_bn(const BIGNUM *a, const BIGNUM *b, BIGNUM *g, BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
    BN_CTX_start(ctx);

    BIGNUM *old_r = BN_CTX_get(ctx);
    BIGNUM *r = BN_CTX_get(ctx);
    BIGNUM *old_s = BN_CTX_get(ctx);
    BIGNUM *s = BN_CTX_get(ctx);
    BIGNUM *old_t = BN_CTX_get(ctx);
    BIGNUM *t = BN_CTX_get(ctx);
    BIGNUM *quotient = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *tmp_mul = BN_CTX_get(ctx);

    BN_copy(old_r, a);
    BN_copy(r, b);

    BN_one(old_s);
    BN_zero(s);

    BN_zero(old_t);
    BN_one(t);

    while (!BN_is_zero(r))
    {
        BN_div(quotient, NULL, old_r, r, ctx); // quotient = old_r / r

        // (old_r, r) := (r, old_r - quotient * r)
        BN_copy(tmp, r);
        BN_mul(tmp_mul, quotient, r, ctx);
        BN_sub(r, old_r, tmp_mul);
        BN_copy(old_r, tmp);

        // (old_s, s) := (s, old_s - quotient * s)
        BN_copy(tmp, s);
        BN_mul(tmp_mul, quotient, s, ctx);
        BN_sub(s, old_s, tmp_mul);
        BN_copy(old_s, tmp);

        // (old_t, t) := (t, old_t - quotient * t)
        BN_copy(tmp, t);
        BN_mul(tmp_mul, quotient, t, ctx);
        BN_sub(t, old_t, tmp_mul);
        BN_copy(old_t, tmp);
    }

    BN_copy(g, old_r);
    BN_copy(x, old_s);
    BN_copy(y, old_t);

    BN_CTX_end(ctx);
}

int mod_inverse(const BIGNUM *a, const BIGNUM *m, BIGNUM *result, BN_CTX *ctx)
{
    BIGNUM *g = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    extended_gcd_bn(a, m, g, x, y, ctx);

    if (!BN_is_one(g))
    {
        BN_free(g);
        BN_free(x);
        BN_free(y);
        return 0; // No modular inverse exists
    }

    BN_mod(result, x, m, ctx);

    BN_free(g);
    BN_free(x);
    BN_free(y);
    return 1; // Modular inverse exists
}

void fast_expo(const BIGNUM *base, const BIGNUM *exp, const BIGNUM *mod, BIGNUM *result, BN_CTX *ctx)
{
    BN_one(result);
    BIGNUM *b = BN_new();
    BN_copy(b, base);
    BN_mod(b, b, mod, ctx);

    BIGNUM *e = BN_new();
    BN_copy(e, exp);

    while (!BN_is_zero(e))
    {
        if (BN_is_odd(e))
        {
            BN_mul(result, result, b, ctx);
            BN_mod(result, result, mod, ctx);
        }
        BN_mul(b, b, b, ctx);
        BN_mod(b, b, mod, ctx);
        BN_rshift1(e, e);
    }

    BN_free(b);
    BN_free(e);
}

int is_prime_lehmen(const BIGNUM *n, int tries, BN_CTX *ctx)
{
    if (BN_cmp(n, BN_value_one()) <= 0)
        return 0;

    if (BN_is_word(n, 2))
        return 1;

    BIGNUM *a = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *result = BN_new();
    BIGNUM *n_minus_1 = BN_new();
    BN_sub(n_minus_1, n, BN_value_one());
    BN_rshift1(e, n_minus_1);

    for (int i = 0; i < tries; i++)
    {
        BN_rand_range(a, n_minus_1);
        BN_add(a, a, BN_value_one());

        fast_expo(a, e, n, result, ctx);

        if (BN_cmp(result, BN_value_one()) != 0 && BN_cmp(result, n_minus_1) != 0)
        {
            BN_free(a);
            BN_free(e);
            BN_free(result);
            BN_free(n_minus_1);
            return 0;
        }
    }

    BN_free(a);
    BN_free(e);
    BN_free(result);
    BN_free(n_minus_1);
    return 1;
}

int is_prime(const BIGNUM *n, BN_CTX *ctx)
{
    static const int small_primes[] = {2, 3, 5, 7, 11, 13, 17, 19};
    BIGNUM *mod = BN_new();

    for (size_t i = 0; i < sizeof(small_primes) / sizeof(small_primes[0]); i++)
    {
        if (BN_is_word(n, small_primes[i]))
        {
            BN_free(mod);
            return 1;
        }

        BIGNUM *small_prime = BN_new();
        BN_set_word(small_prime, small_primes[i]);
        BN_mod(mod, n, small_prime, ctx);
        BN_free(small_prime);

        if (BN_is_zero(mod))
        {
            BN_free(mod);
            return 0;
        }
    }

    BN_free(mod);
    return is_prime_lehmen(n, 100, ctx);
}

int is_safe_prime(const BIGNUM *p, BN_CTX *ctx)
{
    BIGNUM *p1 = BN_new();
    BN_sub(p1, p, BN_value_one());
    BN_rshift1(p1, p1);

    int result = is_prime(p1, ctx);

    BN_free(p1);
    return result;
}

void find_primitive_root(const BIGNUM *p, BIGNUM *g, BN_CTX *ctx)
{
    BN_CTX_start(ctx);

    BIGNUM *p_minus_3 = BN_CTX_get(ctx);
    BIGNUM *a = BN_CTX_get(ctx);
    BIGNUM *q = BN_CTX_get(ctx); // q = (p-1)/2
    BIGNUM *res = BN_CTX_get(ctx);
    BIGNUM *neg_a = BN_CTX_get(ctx);

    // p_minus_3 = p - 3
    BN_copy(p_minus_3, p);
    BN_sub_word(p_minus_3, 3);

    // Generate a -> [2, p-2]
    BN_rand_range(a, p_minus_3); // 0 <= a < p - 3
    BN_add_word(a, 2);           // a -> [2, p - 2]

    // q = (p - 1) / 2
    BN_copy(q, p);
    BN_sub_word(q, 1);
    BN_rshift1(q, q); // q = (p-1)/2

    // res = a^q mod p
    BN_mod_exp(res, a, q, p, ctx);

    if (!BN_is_one(res))
    {
        BN_copy(g, a);
    }
    else
    {
        // g = -a mod p --> p - a
        BN_sub(neg_a, p, a);
        BN_copy(g, neg_a);
    }

    BN_CTX_end(ctx);
}

BIGNUM *bn_get_bits_from_file(int n, const char *filename, BIGNUM *result)
{
    if (result == NULL)
    {
        result = BN_new();
    }

    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("File open failed");
        exit(1);
    }

    // reuse variables
    int byte;
    int shift_pos = 0;
    int bits_to_take = 0;

    int total_bits = 0;
    int found = 0;
    int max_bytes = (n + 7) / 8 + 1;
    unsigned char *buffer = calloc(max_bytes, 1);
    if (!buffer)
    {
        perror("Buffer allocation failed");
        fclose(file);
        exit(1);
    }

    while ((byte = fgetc(file)) != EOF)
    {
        if (!found)
        {
            for (int i = 7; i >= 0; i--)
            {
                int bit = (byte >> i) & 1;
                if (bit == 1)
                {
                    found = 1;
                    bits_to_take = i + 1;
                    byte &= 0xFF >> (8 - bits_to_take);
                    shift_pos = n - bits_to_take;
                    buffer[shift_pos / 8] |= byte << (shift_pos % 8);
                    total_bits += bits_to_take;
                    break;
                }
            }
            continue;
        }

        int bits_left = n - total_bits;
        if (bits_left <= 0)
            break;

        if (bits_left >= 8)
        {
            shift_pos = n - total_bits - 8;
            buffer[shift_pos / 8] |= byte << (shift_pos % 8);
            total_bits += 8;
        }
        else
        {
            byte >>= (8 - bits_left);
            shift_pos = 0;
            buffer[0] |= byte;
            total_bits += bits_left;
            break;
        }
    }

    fclose(file);

    if (!found || total_bits < n)
    {
        fprintf(stderr, "Unable to collect %d bits after first 1-bit\n", n);
        exit(1);
    }

    int byte_len = (n + 7) / 8;
    if (result == NULL)
        result = BN_new();
    BN_bin2bn(buffer, byte_len, result);

    free(buffer);
    return result;
}

void gen_prime(BIGNUM *prime, int bits, const char *filename, BN_CTX *ctx)
{
    BIGNUM *lower = BN_new(), *upper = BN_new(), *cur = BN_new();
    BIGNUM *two = BN_new();
    BN_set_word(two, 2);

    BN_set_bit(lower, bits - 1); // 2^(n-1)
    BN_set_bit(upper, bits);     // 2^n - 1
    BN_sub_word(upper, 1);

    cur = bn_get_bits_from_file(bits, filename, NULL);
    if (!BN_is_odd(cur))
        BN_add_word(cur, 1);

    int i = 0;
    while (BN_cmp(cur, upper) <= 0)
    {
        if (i % 1000 == 0)
        {
            printf("Total: %d, checking: ", i);
            BN_print_fp(stdout, cur);
            printf("\n");
        }
        if (is_prime(cur, ctx) && is_safe_prime(cur, ctx))
        {
            BN_copy(prime, cur);
            break;
        }
        BN_add_word(cur, 2);
        i++;
    }

    BN_free(lower);
    BN_free(upper);
    BN_free(cur);
    BN_free(two);
}

void gen_random_with_inverse(int n)
{
    char filename[100];
    int bits;
    printf("Enter number of bits [more that 2]: ");
    scanf("%d", &bits);
    if (bits < 2)
    {
        fprintf(stderr, "Invalid bit length (must be 2–63)\n");
        exit(1);
    }
    printf("Enter the filename: ");
    scanf("%99s", filename);
    printf("filename: %s\n", filename);

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *primitive_root = BN_new();

    gen_prime(p, bits, filename, ctx);

    BIGNUM *mod = BN_new();
    BN_set_word(mod, n);

    if (!mod_inverse(p, mod, q, ctx))
    {
        fprintf(stderr, "Failed to compute modular inverse\n");
        exit(1);
    }

    printf("prime: ");
    BN_print_fp(stdout, p);
    printf("\n");

    printf("safe prime: ");
    BIGNUM *safe_prime = BN_new();
    BN_sub(safe_prime, p, BN_value_one());
    BN_rshift1(safe_prime, safe_prime);
    BN_print_fp(stdout, safe_prime);
    printf("\n");

    printf("inverse: ");
    BN_print_fp(stdout, q);
    printf("\n");

    find_primitive_root(p, primitive_root, ctx);
    printf("Primitive root: ");
    BN_print_fp(stdout, primitive_root);
    printf("\n");

    BN_free(p);
    BN_free(q);
    BN_free(primitive_root);
    BN_free(safe_prime);
    BN_CTX_free(ctx);
}

void bin2bn_block(const unsigned char *bin, int data_len, int st_bin, int block_len, BIGNUM *r)
{
    BN_zero(r);

    int end_bits = st_bin + block_len;
    int max_bits = data_len * BYTE;

    // 8 bytes = 64 bits
    // start = 60, len = 7, end = 67
    // pad = 67 - 64 = 3
    // data = [0, 63]
    // 60 61 62 63 need 3

    int pad_bits = (end_bits > max_bits) ? (end_bits - max_bits) : 0;

    // copy only the bits that are in the range
    block_len = (end_bits > max_bits) ? (max_bits - st_bin) : block_len;
    // len = 4 read only 60-63

    // 00000000 00000000 00000000 00000000
    //     i                           e

    // first partial bits
    if (st_bin % BYTE != 0)
    {
        int bit_offset = st_bin % BYTE;

        unsigned char byte = bin[st_bin / BYTE];
        unsigned char mask = 0xFF >> bit_offset;

        if (block_len < BYTE - (bit_offset))
        {
            mask >>= (BYTE - bit_offset) - block_len;
            mask <<= (BYTE - bit_offset) - block_len;
        }

        unsigned char bits = byte & mask;
        BN_set_word(r, bits);
        block_len -= BYTE - bit_offset;
        st_bin += BYTE - bit_offset;
    }

    // process full bytes
    if (block_len / BYTE > 0)
    {
        BIGNUM *tmp = BN_bin2bn(bin + st_bin / BYTE, block_len / BYTE, NULL);
        BN_lshift(r, r, BYTE * (block_len / BYTE));
        BN_add(r, r, tmp);
        st_bin += BYTE * (block_len / BYTE);
        block_len %= BYTE;
        BN_free(tmp);
    }

    // printf("st_bin: %d, len: %d\n", st_bin, len);
    // process last partial bits
    if (block_len > 0)
    {
        unsigned char byte = bin[st_bin / BYTE];
        byte = byte >> (BYTE - block_len);
        unsigned char bits = byte & 0xFF;
        BN_lshift(r, r, block_len);
        // printf("bits: %d\n", bits);
        BN_add_word(r, bits);
    }

    // pad bits
    if (pad_bits > 0)
    {
        BN_lshift(r, r, pad_bits);
    }
}
