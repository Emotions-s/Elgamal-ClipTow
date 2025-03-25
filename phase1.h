#include <stdint.h>

int32_t gcd(int32_t a, int32_t b);
int32_t extended_gcd(int32_t a, int32_t b, int32_t *x, int32_t *y);
int32_t mod_inverse(int32_t a, int32_t m);
int32_t fast_expo(int32_t a, int32_t b, int32_t n);
int is_prime_lehmen(int32_t n, int32_t tries);
int32_t gen_prime(int32_t n, const char *filename);
void gen_random_with_inverse(int n);
