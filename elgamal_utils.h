#include <openssl/bn.h>

// utils
void gcd_bn(const BIGNUM *a, const BIGNUM *b, BIGNUM *result, BN_CTX *ctx);
BIGNUM *bn_get_bits_from_file(int n, const char *filename, BIGNUM *result);
void extended_gcd_bn(const BIGNUM *a, const BIGNUM *b, BIGNUM *g, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
int mod_inverse(const BIGNUM *a, const BIGNUM *m, BIGNUM *result, BN_CTX *ctx);
void fast_expo(const BIGNUM *base, const BIGNUM *exp, const BIGNUM *mod, BIGNUM *result, BN_CTX *ctx);
void find_primitive_root(const BIGNUM *p, BIGNUM *result, BN_CTX *ctx);
void bin2bn_block(const unsigned char *bin, int data_len, int st_bin, int block_len, BIGNUM *r);

// generate prime
void gen_prime(BIGNUM *prime, int bits, const char *filename, BN_CTX *ctx);
void gen_random_with_inverse(int n);




