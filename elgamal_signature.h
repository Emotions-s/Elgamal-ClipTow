#include <openssl/bn.h>

void RW_hash(const unsigned char *data, int data_len, const BIGNUM *p, BIGNUM *hash_result);
void elgamal_sign(const BIGNUM *p, const BIGNUM *g, const BIGNUM *x, const char *bin_msg, const int msg_len, BIGNUM *r, BIGNUM *s);
int elgamal_verify(const BIGNUM *p, const BIGNUM *g, const BIGNUM *y, const BIGNUM *r, const BIGNUM *s, const char *bin_msg, const int msg_len);

int read_signed_msg(const char *filename, BIGNUM **r, BIGNUM **s, const BIGNUM *p);
void write_signed_msg(const char *filename, const BIGNUM *r, const BIGNUM *s, const BIGNUM *p);

void test_hash();
void test_sign();
