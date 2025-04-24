#include <stdio.h>
#include <openssl/bn.h>

void write_cipher_pair(FILE *fp, const BIGNUM *a, const BIGNUM *b)
{
    int a_len = BN_num_bytes(a);
    int b_len = BN_num_bytes(b);

    // Write length and data for a
    fwrite(&a_len, sizeof(int), 1, fp);
    unsigned char *a_buf = malloc(a_len);
    BN_bn2bin(a, a_buf);
    fwrite(a_buf, 1, a_len, fp);
    free(a_buf);

    // Write length and data for b
    fwrite(&b_len, sizeof(int), 1, fp);
    unsigned char *b_buf = malloc(b_len);
    BN_bn2bin(b, b_buf);
    fwrite(b_buf, 1, b_len, fp);
    free(b_buf);
}

int read_cipher_pair(FILE *fp, BIGNUM *a, BIGNUM *b)
{
    int a_len, b_len;

    // Read a_len
    if (fread(&a_len, sizeof(int), 1, fp) != 1)
        return 0;

    unsigned char *a_buf = malloc(a_len);
    if (!a_buf || fread(a_buf, 1, a_len, fp) != (size_t)a_len)
    {
        free(a_buf);
        return 0;
    }
    BN_bin2bn(a_buf, a_len, a);
    free(a_buf);

    // Read b_len
    if (fread(&b_len, sizeof(int), 1, fp) != 1)
        return 0;

    unsigned char *b_buf = malloc(b_len);
    if (!b_buf || fread(b_buf, 1, b_len, fp) != (size_t)b_len)
    {
        free(b_buf);
        return 0;
    }
    BN_bin2bn(b_buf, b_len, b);
    free(b_buf);

    return 1;
}