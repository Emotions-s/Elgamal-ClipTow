#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include "elgamal_utils.h"
#include "elgamal_encrypt.h"
#include "data_io.h"

void elgamal_key_gen(BIGNUM *privateKey, BIGNUM *p, BIGNUM *g, BIGNUM *y, int bits, const char *p_file)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *p_minus_1 = BN_CTX_get(ctx);

    gen_prime(p, bits, p_file, ctx);

    find_primitive_root(p, g, ctx);

    BN_copy(p_minus_1, p);
    BN_sub_word(p_minus_1, 1);

    // random private key u
    BN_rand_range(privateKey, p_minus_1); // u = rand [0, p-1)
    BN_add_word(privateKey, 1);           // +1 => u = [1, p-2)

    fast_expo(g, privateKey, p, y, ctx); // y = g^privateKey mod p

    printf("Generated Keys:\n");
    printf("p = ");
    BN_print_fp(stdout, p);
    printf("\n");
    printf("g = ");
    BN_print_fp(stdout, g);
    printf("\n");
    printf("Private key x = ");
    BN_print_fp(stdout, privateKey);
    printf("\n");
    printf("Public key y = ");
    BN_print_fp(stdout, y);
    printf("\n");

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

void elgamal_en(BIGNUM *p, BIGNUM *g, BIGNUM *y, const char *inputFile, const char *cipherFile)
{
    if (BN_num_bits(p) % 8 != 0)
    {
        printf("Error: p is not a multiple of 8 bits.\n");
        exit(1);
    }

    FILE *in = fopen(inputFile, "rb");
    FILE *out = fopen(cipherFile, "wb");
    if (!in || !out)
    {
        perror("File error in encryption");
        exit(1);
    }

    // add file length to the beginning of the file for decryption
    fseek(in, 0, SEEK_END);
    uint32_t file_len = (uint32_t)ftell(in);
    rewind(in);
    fwrite(&file_len, sizeof(uint32_t), 1, out);
    printf("File length: %u bytes\n", file_len);

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *m = BN_CTX_get(ctx);
    BIGNUM *k = BN_CTX_get(ctx);
    BIGNUM *a = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);
    BIGNUM *p_minus_1 = BN_CTX_get(ctx);
    BIGNUM *p_minus_2 = BN_CTX_get(ctx);

    BN_sub(p_minus_1, p, BN_value_one());

    BN_copy(p_minus_2, p);
    BN_sub_word(p_minus_2, 2);

    int block_size = BN_num_bytes(p) - 1; // Safe: ensures m < p
    unsigned char *buffer = malloc(block_size);
    if (!buffer)
    {
        perror("Failed to allocate buffer");
        exit(1);
    }

    size_t read_bytes;
    while ((read_bytes = fread(buffer, 1, block_size, in)) > 0)
    {
        // If final block, pad remaining bytes with 0
        if (read_bytes < (size_t)block_size)
        {
            memset(buffer + read_bytes, 0, block_size - read_bytes);
        }

        BN_bin2bn(buffer, block_size, m);
        do
        {
            // k -> [1, p-2]
            BN_rand_range(k, p_minus_2);
            BN_add_word(k, 1);

            // gcd(k, p-1) == 1
            gcd_bn(k, p_minus_1, tmp, ctx);
        } while (!BN_is_one(tmp));

        fast_expo(g, k, p, a, ctx);    // a = g^k mod p
        fast_expo(y, k, p, tmp, ctx);  // tmp = y^k mod p
        BN_mod_mul(b, tmp, m, p, ctx); // b = (y^k * m) mod p

        write_cipher_pair(out, a, b);
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    fclose(in);
    fclose(out);
    printf("Encrypted to file: %s\n", cipherFile);
}

void elgamal_de(BIGNUM *x, BIGNUM *p, const char *ciph_file, const char *out_file)
{
    if (BN_num_bits(p) % 8 != 0)
    {
        printf("Error: p is not a multiple of 8 bits.\n");
        exit(1);
    }

    FILE *in = fopen(ciph_file, "rb");
    FILE *out = fopen(out_file, "wb");
    if (!in || !out)
    {
        perror("File error in decryption");
        exit(1);
    }

    // Read original plaintext file length
    uint32_t file_len = 0;
    if (fread(&file_len, sizeof(uint32_t), 1, in) != 1)
    {
        fprintf(stderr, "Error reading original file length.\n");
        exit(1);
    }
    printf("Original file length: %u bytes\n", file_len);

    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *a = BN_CTX_get(ctx);
    BIGNUM *b = BN_CTX_get(ctx);
    BIGNUM *s = BN_CTX_get(ctx);
    BIGNUM *m = BN_CTX_get(ctx);
    BIGNUM *tmp = BN_CTX_get(ctx);

    int block_size = BN_num_bytes(p) - 1;
    unsigned char *buffer = malloc(block_size);
    if (!buffer)
    {
        perror("Memory allocation failed");
        exit(1);
    }

    uint32_t total_written = 0;

    while (read_cipher_pair(in, a, b))
    {
        // s = a^(p-1-x) mod p
        BN_sub(tmp, p, BN_value_one());
        BN_sub(tmp, tmp, x);
        fast_expo(a, tmp, p, s, ctx);

        // m = (s * b) mod p
        BN_mod_mul(m, s, b, p, ctx);

        int bytes = BN_bn2binpad(m, buffer, block_size);

        int to_write = (file_len - total_written > block_size)
                         ? block_size
                         : (file_len - total_written);
        fwrite(buffer, 1, to_write, out);
        total_written += to_write;
    }
    free(buffer);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    fclose(in);
    fclose(out);
    printf("Decrypted to file: %s\n", out_file);
}
