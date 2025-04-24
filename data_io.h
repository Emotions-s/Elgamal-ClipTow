#include <stdio.h>
#include <openssl/bn.h>

void write_cipher_pair(FILE *fp, const BIGNUM *a, const BIGNUM *b);
int read_cipher_pair(FILE *fp, BIGNUM *a, BIGNUM *b);
