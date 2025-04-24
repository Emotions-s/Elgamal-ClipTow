#include <openssl/bn.h>

void elgamal_key_gen(BIGNUM *privateKey, BIGNUM *p, BIGNUM *g, BIGNUM *y, int bits, const char *filename);
void elgamal_en(BIGNUM *p, BIGNUM *g, BIGNUM *y, const char *inputFile, const char *cipherFile);
void elgamal_de(BIGNUM *privateKey, BIGNUM *p, const char *cipherFile, const char *outputFile);
