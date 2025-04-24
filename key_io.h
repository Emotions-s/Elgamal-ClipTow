#include <stdio.h>
#include <openssl/bn.h>

void save_pri_key(const char *filename, const BIGNUM *x);

void read_pri_key(const char *filename, BIGNUM **x);

void save_pub_key(const char *filename, const BIGNUM *p, const BIGNUM *g, const BIGNUM *y);

void read_pub_key(const char *filename, BIGNUM **p, BIGNUM **g, BIGNUM **y);