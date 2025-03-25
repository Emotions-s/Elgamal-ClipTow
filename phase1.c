#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int64_t gcd(int64_t a, int64_t b)
{
    if (b == 0)
    {
        return a;
    }
    return gcd(b, a % b);
}

int64_t extended_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y)
{
    if (b == 0)
    {
        *x = 1;
        *y = 0;
        return a;
    }

    int64_t x1, y1;
    int64_t gcd = extended_gcd(b, a % b, &x1, &y1);

    *x = y1;
    *y = x1 - (a / b) * y1;

    return gcd;
}

int64_t mod_inverse(int64_t a, int64_t m)
{
    int64_t x, y;
    int64_t g = extended_gcd(a, m, &x, &y);
    if (g != 1)
    {
        return -1;
    }
    return (x % m + m) % m;
}

int64_t fast_expo(int64_t base, int64_t exp, int64_t mod)
{
    int64_t result = 1;
    base %= mod;
    while (exp > 0)
    {
        if (exp & 1)
        {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

int is_prime_lehmen(int64_t n, int64_t tries)
{
    if (n < 2)
        return 0;
    if (n == 2)
        return 1;

    for (int64_t i = 0; i < tries; i++)
    {
        int64_t a = (rand() % (n - 3)) + 2;
        int64_t e = (n - 1) / 2;
        int64_t result = fast_expo(a, e, n);
        if (result != 1 && result != n - 1)
            return 0;
    }
    return 1;
}

int is_prime(int64_t n)
{
    long small_primes[] = {2, 3, 5, 7, 11, 13, 17, 19};
    for (int i = 0; i < (int)(sizeof(small_primes) / sizeof(small_primes[0])); i++)
    {
        if (n == small_primes[i])
            return 1;
        if (n % small_primes[i] == 0)
            return 0;
    }
    return is_prime_lehmen(n, 100);
}

int is_safe_prime(int64_t p)
{
    int64_t p1 = (p - 1) / 2;
    ;
    return is_prime(p1);
}

int64_t find_primitive_root(int64_t p)
{
    int64_t p1 = (p - 1) / 2;
    for (int64_t a = 2; a < p - 1; a++)
    {
        if (fast_expo(a, p1, p) != 1)
        {
            return a;
        }
    }

    return -1;
}

int64_t get_bits_from_file(int n, const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("File open failed");
        exit(1);
    }

    uint64_t result = 0;
    int bits_collected = 0;
    int found = 0;
    int byte;

    while ((byte = fgetc(file)) != EOF)
    {
        if (!found)
        {
            for (int i = 7; i >= 0; i--)
            {
                int bit = (byte >> i) & 1;
                if (bit == 1)
                {
                    found = 1;
                    int bitsInByte = i + 1;
                    uint8_t mask = 0xFF >> (8 - i - 1);
                    result = byte & mask;
                    bits_collected = bitsInByte;
                    break;
                }
            }
        }
        else
        {
            int bits_left = n - bits_collected;
            if (bits_left >= 8)
            {
                result = (result << 8) | byte;
                bits_collected += 8;
            }
            else
            {
                result = (result << bits_left) | (byte >> (8 - bits_left));
                bits_collected += bits_left;
                break;
            }
        }

        if (bits_collected >= n)
            break;
    }

    fclose(file);

    if (!found || bits_collected < n)
    {
        fprintf(stderr, "Unable to collect %d bits after first 1-bit\n", n);
        exit(1);
    }

    return (int64_t)result;
}

int64_t gen_prime(int n, const char *filename)
{
    int64_t lower_bound = 1ULL << (n - 1);
    int64_t upper_bound = (1ULL << n) - 1;

    int64_t first_candidate = get_bits_from_file(n, filename);
    if ((first_candidate % 2) == 0)
    {
        first_candidate++;
    }
    int64_t cur_candidate = first_candidate;
    while (cur_candidate <= upper_bound)
    {
        if (is_prime(cur_candidate))
        {
            if (is_safe_prime(cur_candidate))
                return cur_candidate;
        }

        cur_candidate += 2;
    }
    while (cur_candidate >= lower_bound)
    {
        if (is_prime(cur_candidate))
            if (is_safe_prime(cur_candidate))
                return cur_candidate;

        cur_candidate -= 2;
    }

    fprintf(stderr, "Failed to generate prime within %d-bit range %d %x\n", n, first_candidate, first_candidate);
    exit(1);
}
void gen_random_with_inverse(int n)
{
    char filename[100];
    int bits;
    printf("Enter number of bis [2, 31]: ");
    scanf("%d", &bits);
    if (bits < 2 || bits > 31)
    {
        fprintf(stderr, "Invalid bit length (must be 2–63)\n");
        exit(1);
    }
    printf("Enter the filename: ");
    scanf("%99s", &filename);
    printf("filename: %s\n", filename);
    int64_t p = gen_prime(bits, filename);
    int64_t q = mod_inverse(p, n);
    printf("prime  %d\n", p);
    printf("safe prime %d\n", (p - 1) / 2);
    printf("inverse %d\n", q);
    printf("%d * %d = 1 mod %d\n", p, q, n);
    int primitive_root = find_primitive_root(p);
    printf("Primitive root: %d\n", primitive_root);
}
