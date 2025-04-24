#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "elgamal_encrypt.h"
#include "key_io.h"

// Generate decrypted filename
void get_cipher_and_output(char *cipher_filename, char *output_filename) {
    printf("Enter ciphertext filename: ");
    scanf("%99s", cipher_filename);

    const char *dot = strrchr(cipher_filename, '.');
    if (!dot) {
        sprintf(output_filename, "%s_decrypted", cipher_filename);
    } else {
        size_t len = dot - cipher_filename;
        strncpy(output_filename, cipher_filename, len);
        output_filename[len] = '\0';
        strcat(output_filename, "_decrypted");
        strcat(output_filename, dot);
    }
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    BIGNUM *x = BN_CTX_get(ctx);
    BIGNUM *p = BN_CTX_get(ctx);
    BIGNUM *g = BN_CTX_get(ctx);
    BIGNUM *y = BN_CTX_get(ctx);
    char cipher_filename[100];
    char decrypted_filename[150];

    read_pri_key("keys/private_key.bin", &x);
    read_pub_key("keys/public_key.bin", &p, &g, &y);
    get_cipher_and_output(cipher_filename, decrypted_filename);

    elgamal_de(x, p, cipher_filename, decrypted_filename);

    printf("Decrypted output saved to %s\n", decrypted_filename);

    // Free BIGNUMs
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return 0;
}
