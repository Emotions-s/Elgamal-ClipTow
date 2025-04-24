#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "elgamal_signature.h"
#include "key_io.h"

void bn_to_hex_file(const BIGNUM *bn, FILE *fp) {
    char *hex = BN_bn2hex(bn);
    fprintf(fp, "%s\n", hex);
    OPENSSL_free(hex);
}

int main() {
    BIGNUM *x = NULL, *p = NULL, *g = NULL, *y = NULL;

    read_pri_key("keys/private_key.bin", &x);
    read_pub_key("keys/public_key.bin", &p, &g, &y);

    char input_type[10];
    char input_filename[100];
    unsigned char data[4096];
    int data_len = 0;

    printf("Enter input type ('text' or 'file'): ");
    scanf("%9s", input_type);

    if (strcmp(input_type, "text") == 0) {
        printf("Enter plaintext: ");
        getchar(); // flush newline after scanf
        fgets((char *)data, sizeof(data), stdin);
        data_len = strlen((char *)data);
    } else if (strcmp(input_type, "file") == 0) {
        printf("Enter filename: ");
        scanf("%99s", input_filename);
        FILE *fp = fopen(input_filename, "rb");
        if (!fp) {
            perror("Failed to open input file");
            return 1;
        }
        data_len = fread(data, 1, sizeof(data), fp);
        fclose(fp);
    } else {
        printf("Invalid input type.\n");
        return 1;
    }

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();

    elgamal_sign(p, g, x, (const char *)data, data_len, r, s);

    FILE *out = fopen("data/signature.txt", "w");
    if (!out) {
        perror("Failed to open signature.txt");
        return 1;
    }
    bn_to_hex_file(r, out);
    bn_to_hex_file(s, out);
    fclose(out);

    printf("Signature saved to data/signature.txt\n");

    BN_free(r);
    BN_free(s);
    BN_free(x);
    BN_free(p);
    BN_free(g);
    BN_CTX_free(ctx);

    return 0;
}