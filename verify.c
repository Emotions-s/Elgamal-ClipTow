

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "elgamal_signature.h"
#include "key_io.h"

void read_bn_from_hex_line(FILE *fp, BIGNUM **bn) {
    char hex[1024];
    if (fgets(hex, sizeof(hex), fp) == NULL) {
        fprintf(stderr, "Failed to read BIGNUM hex line\n");
        exit(1);
    }
    hex[strcspn(hex, "\n")] = 0;  // Remove newline
    *bn = NULL;
    BN_hex2bn(bn, hex);
}

int main() {
    BIGNUM *p = NULL, *g = NULL, *y = NULL;
    read_pub_key("keys/public_key.bin", &p, &g, &y);

    char input_type[10];
    char input_filename[100];
    unsigned char data[4096];
    int data_len = 0;

    printf("Enter input type ('text' or 'file'): ");
    scanf("%9s", input_type);

    if (strcmp(input_type, "text") == 0) {
        printf("Enter plaintext: ");
        getchar(); // flush newline
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

    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    char sig_filename[100];
    printf("Enter signature filename: ");
    scanf("%99s", sig_filename);
    FILE *sig_fp = fopen(sig_filename, "r");
    if (!sig_fp) {
        perror("Failed to open signature file");
        return 1;
    }
    read_bn_from_hex_line(sig_fp, &r);
    read_bn_from_hex_line(sig_fp, &s);
    fclose(sig_fp);

    BN_CTX *ctx = BN_CTX_new();
    int valid = elgamal_verify(p, g, y, r, s, (const char *)data, data_len);

    if (valid) {
        printf("Signature is VALID.\n");
    } else {
        printf("Signature is INVALID.\n");
    }

    BN_free(p);
    BN_free(g);
    BN_free(y);
    BN_free(r);
    BN_free(s);
    BN_CTX_free(ctx);
    return 0;
}