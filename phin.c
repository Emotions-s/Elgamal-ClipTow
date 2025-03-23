long long GCD(long long a, long long b, long long *x, long long *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }

    long long x1, y1;
    long long gcd = GCD(b, a % b, &x1, &y1);

    *x = y1;
    *y = x1 - (a / b) * y1;

    return gcd;
}

long long FindInverse(long long a, long long p)
{
    long long x, y;
    long long g = GCD(a, p, &x, &y);
    if (g != 1)
    {
        printf("Inverse doesn't exist\n");
        return -1;
    }
    else
    {
        return (x % p + p) % p;
    }
}

long long FastExpo(long long a, long long b, long long n)
{
    long long result = 1;
    a %= n;
    while (b > 0)
    {
        if (b % 2 == 1)
        {
            result = (result * a) % n;
        }
        a = (a * a) % n;
        b /= 2;
    }
    return result;
}