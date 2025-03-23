#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Lehmann Primality Test

// Function to perform modular exponentiation (a^e mod n)
long long int mod_exp(long long int base, long long int exp, long long int mod) {
    long long int result = 1;
    while (exp > 0) {
        if (exp % 2 == 1)  // If exp is odd, multiply base with result
            result = (result * base) % mod;
        base = (base * base) % mod;  // Square the base
        exp /= 2;  // Reduce exponent
    }
    return result;
}

int lehman_test(long long int n, int tries) {
    if (n < 2) return 0;
    if (n == 2) return 1;

    for (int i = 0; i < tries; i++) {
        long long int a = (rand() % (n - 3)) + 2;
        long long int e = (n - 1) / 2;
        long long int result = mod_exp(a, e, n);
        if (result != 1 && result != n - 1) return 0;
    }
    return 1;  // Probably prime
}

int is_prime(long long int n) {
    long small_primes[] = {2, 3, 5, 7, 11, 13, 17, 19};
    for (int i = 0; i < sizeof(small_primes) / sizeof(small_primes[0]); i++) {
        if (n == small_primes[i]) return 1;
        if (n % small_primes[i] == 0) return 0;
    }
    return lehman_test(n, 100); // Increased the number of tries
}

int main() {
    srand(time(NULL));  // Seed random number generator
    long long int number_to_test = 1023898923260683L;
    int ans = is_prime(number_to_test);
    printf("%d\n", ans);
    return 0;
}