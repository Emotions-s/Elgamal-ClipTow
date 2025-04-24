#include <stdio.h>
#include <openssl/bn.h>

void save_pri_key(const char *filename, const BIGNUM *x) {
    FILE *fp = fopen(filename, "wb");

    if (!fp) {
        perror("Failed to open private key file for writing");
        exit(EXIT_FAILURE);
    }

    int x_len = BN_num_bytes(x);
    printf("x_len = %d\n", x_len);
    unsigned char *x_buf = malloc(x_len);
    if (!x_buf) {
        printf("Failed to allocate memory for private key buffer.\n");
        perror("Memory allocation failed");
        fclose(fp);
        exit(EXIT_FAILURE);
    }


    BN_bn2bin(x, x_buf);


    fwrite(&x_len, sizeof(int32_t), 1, fp);     // Write length
    fwrite(x_buf, 1, x_len, fp);                // Write x value

    free(x_buf);
    fclose(fp);

    printf("Private key saved to %s\n", filename);
}

void read_pri_key(const char *filename, BIGNUM **x) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open private key file for reading");
        exit(EXIT_FAILURE);
    }

    int32_t x_len;
    if (fread(&x_len, sizeof(int32_t), 1, fp) != 1) {
        fprintf(stderr, "Failed to read private key length.\n");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    unsigned char *x_buf = malloc(x_len);
    if (!x_buf) {
        perror("Memory allocation failed");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    if (fread(x_buf, 1, x_len, fp) != x_len) {
        fprintf(stderr, "Failed to read private key value.\n");
        free(x_buf);
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    *x = BN_bin2bn(x_buf, x_len, NULL);
    if (!*x) {
        fprintf(stderr, "Failed to convert private key to BIGNUM.\n");
        exit(EXIT_FAILURE);
    }

    free(x_buf);
    fclose(fp);
}

void save_pub_key(const char *filename, const BIGNUM *p, const BIGNUM *g, const BIGNUM *y) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to open public key file for writing");
        exit(EXIT_FAILURE);
    }

    const BIGNUM *bns[] = {p, g, y};

    for (int i = 0; i < 3; i++) {
        int len = BN_num_bytes(bns[i]);
        unsigned char *buf = malloc(len);
        if (!buf) {
            perror("Memory allocation failed");
            fclose(fp);
            exit(EXIT_FAILURE);
        }

        BN_bn2bin(bns[i], buf);
        fwrite(&len, sizeof(int32_t), 1, fp);  // length prefix
        fwrite(buf, 1, len, fp);               // binary data
        free(buf);
    }

    fclose(fp);
    printf("Public key saved to %s\n", filename);
}

void read_pub_key(const char *filename, BIGNUM **p, BIGNUM **g, BIGNUM **y) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open public key file for reading");
        exit(EXIT_FAILURE);
    }

    BIGNUM **out[] = {p, g, y};

    for (int i = 0; i < 3; i++) {
        int32_t len;
        if (fread(&len, sizeof(int32_t), 1, fp) != 1) {
            fprintf(stderr, "Failed to read length of public key part %d.\n", i);
            fclose(fp);
            exit(EXIT_FAILURE);
        }

        unsigned char *buf = malloc(len);
        if (!buf) {
            perror("Memory allocation failed");
            fclose(fp);
            exit(EXIT_FAILURE);
        }

        if (fread(buf, 1, len, fp) != len) {
            fprintf(stderr, "Failed to read public key part %d.\n", i);
            free(buf);
            fclose(fp);
            exit(EXIT_FAILURE);
        }

        *out[i] = BN_bin2bn(buf, len, NULL);
        free(buf);
    }

    fclose(fp);
}