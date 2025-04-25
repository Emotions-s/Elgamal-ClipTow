#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "elgamal_utils.h"
#include "key_io.h"
#include "elgamal_encrypt.h"

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *x = BN_CTX_get(ctx);
    BIGNUM *p = BN_CTX_get(ctx);
    BIGNUM *g = BN_CTX_get(ctx);
    BIGNUM *y = BN_CTX_get(ctx);

    char rand_file[100];
    int bits;
    printf("Enter number of bits [more that 2]: ");
    scanf("%d", &bits);
    if (bits < 2)
    {
        fprintf(stderr, "Invalid bit length (must be more than 2)\n");
        exit(1);
    }
    printf("Enter the filename: ");
    scanf("%99s", rand_file);
    printf("filename: %s\n", rand_file);

    if (!x || !p || !g || !y)
    {
        perror("Failed to allocate BIGNUMs");
        return 1;
    }

    // Generate keys
    elgamal_key_gen(x, p, g, y, bits, rand_file);

    // Save keys to files
    save_pri_key("keys/private_key.bin", x);
    save_pub_key("keys/public_key.bin", p, g, y);
    return 0;
}