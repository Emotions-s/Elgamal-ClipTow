#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <math.h>
#include "elgamal_utils.h"
#include "elgamal_signature.h"

#define BYTE 8

void RW_hash(const unsigned char *data, int data_len, const BIGNUM *p, BIGNUM *hash_result)
{
    if (BN_is_zero(p) || BN_is_negative(p))
    {
        fprintf(stderr, "Error: p is invalid\n");
        return;
    }

    int block_size = BN_num_bits(p);
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    int num_blocks = ceil((double)data_len * BYTE / block_size);
    BIGNUM *block = BN_CTX_get(ctx);



    // set h0 = number of bits
    BN_set_word(hash_result, data_len * BYTE);

    // p = 13
    // 8 8 8 8 8 8 8

    char *r_str = NULL;

    // ([h(i-1) + b(i)]^2 mod p) << 2 mod p
    for (int i = 0, s = 0; i < num_blocks; i++, s += block_size)
    {
        bin2bn_block(data, data_len, s, block_size, block);
        r_str = BN_bn2dec(block);
        // printf("block: %s\n", r_str);

        // h(i) = h(i-1) + b(i)
        BN_add(hash_result, hash_result, block);
        // h(i) = h(i)^2 mod p
        BN_mod_sqr(hash_result, hash_result, p, ctx);
        // h(i) = h(i) << 2 mod p
        BN_mod_lshift(hash_result, hash_result, 2, p, ctx);
        r_str = BN_bn2dec(hash_result);
        // printf("hash: %s\n", r_str);
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void elgamal_sign(const BIGNUM *p, const BIGNUM *g, const BIGNUM *x, const char *bin_msg, const int msg_len, BIGNUM *r, BIGNUM *s)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *k = BN_CTX_get(ctx);
    BIGNUM *p_minus_1 = BN_CTX_get(ctx);
    BIGNUM *p_minus_2 = BN_CTX_get(ctx);
    BIGNUM *k_inv = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *h = BN_CTX_get(ctx);

    RW_hash(bin_msg, msg_len, p, h);

    BN_sub(p_minus_1, p, BN_value_one());

    BN_copy(p_minus_2, p);
    BN_sub_word(p_minus_2, 2);

    do
    {
        // k = rand [0, p-2)
        BN_rand_range(k, p_minus_2);

        // k = rand [1, p-2)
        BN_add_word(k, 1);

        gcd_bn(k, p_minus_1, tmp, ctx);
    } while (BN_is_zero(tmp) || !BN_is_one(tmp));
    // find k^(-1)
    mod_inverse(k, p_minus_1, k_inv, ctx);

    // r = (g^k mod p)
    fast_expo(g, k, p, r, ctx);

    // s = (k^-1 * (h - x * r)) mod (p - 1)

    // tmp = x * r mod (p - 1)
    BN_mod_mul(tmp, x, r, p_minus_1, ctx);

    // tmp = h - x * r mod (p - 1)
    BN_mod_sub(tmp, h, tmp, p_minus_1, ctx);

    // s = k^-1 * (h - x * r) mod (p - 1)
    BN_mod_mul(s, k_inv, tmp, p_minus_1, ctx);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

int elgamal_verify(const BIGNUM *p, const BIGNUM *g, const BIGNUM *y, const BIGNUM *r, const BIGNUM *s, const char *bin_msg, const int msg_len)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *h = BN_CTX_get(ctx);
    BIGNUM *left = BN_CTX_get(ctx);
    BIGNUM *right = BN_CTX_get(ctx);
    BIGNUM *y_r = BN_CTX_get(ctx);
    BIGNUM *r_s = BN_CTX_get(ctx);

    RW_hash(bin_msg, msg_len, p, h);

    // check by g^x = y^r * r^s mod p

    fast_expo(g, h, p, left, ctx);
    fast_expo(y, r, p, y_r, ctx);
    fast_expo(r, s, p, r_s, ctx);
    BN_mod_mul(right, y_r, r_s, p, ctx);

    int valid = BN_cmp(left, right) == 0;

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return valid;
}

// PEM format

int read_signed_msg(const char *filename, BIGNUM **r, BIGNUM **s, const BIGNUM *p)
{
    int max_bytes = (BN_num_bits(p) + 7) / 8;
    unsigned char r_buf[max_bytes];
    unsigned char s_buf[max_bytes];

    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        perror("Error opening signature file");
        return 0;
    }

    if (fread(r_buf, 1, max_bytes, fp) != max_bytes ||
        fread(s_buf, 1, max_bytes, fp) != max_bytes)
    {
        fprintf(stderr, "Error reading r or s from file.\n");
        fclose(fp);
        return 0;
    }

    fclose(fp);

    *r = BN_bin2bn(r_buf, max_bytes, NULL);
    *s = BN_bin2bn(s_buf, max_bytes, NULL);

    return (*r && *s) ? 1 : 0;
}

void write_signed_msg(const char *filename, const BIGNUM *r, const BIGNUM *s, const BIGNUM *p)
{
    int max_bytes = (BN_num_bits(p) + 7) / 8;
    unsigned char r_buf[max_bytes];
    unsigned char s_buf[max_bytes];

    if (BN_bn2binpad(r, r_buf, max_bytes) < 0 ||
        BN_bn2binpad(s, s_buf, max_bytes) < 0)
    {
        fprintf(stderr, "Error: r or s is too large.\n");
        return;
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp)
    {
        perror("Error opening file");
        return;
    }

    fwrite(r_buf, 1, max_bytes, fp);
    fwrite(s_buf, 1, max_bytes, fp);

    fclose(fp);
}

void test_hash()
{
    unsigned char data[] = {0b11111111, 0b10111111, 0b10101010, 0b11001100, 0b11110000, 0b00001111, 0b11111111};
    BIGNUM *r = BN_new();
    BIGNUM *p = BN_new();
    BN_set_word(p, 3001);
    RW_hash(data, sizeof(data), p, r);
    char *r_str = BN_bn2dec(r);
    printf("r: %s\n", r_str);
}

void test_sign()
{
    int num_bits = 30;

    unsigned char data[] = {0b11111111, 0b10111111, 0b10101010, 0b11001100, 0b11110000, 0b00001111, 0b11111111};
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *x = BN_new();

    gen_prime(p, num_bits, "data_files/1111111111.bin", ctx);
    find_primitive_root(p, g, ctx);

    // get private key (x) do it later

    elgamal_sign(p, g, x, data, sizeof(data), r, s);
}
