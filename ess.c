#include <stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

// Helper to get n bits from a file
long getRandomBitsFromFile(int n, const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        perror("File open failed");
        exit(1);
    }

    // Allocate enough bytes
    int totalBytes = (n + 7) / 8;
    unsigned char *buffer = malloc(totalBytes);
    if (fread(buffer, 1, totalBytes, file) < totalBytes)
    {
        perror("Not enough data in file");
        fclose(file);
        exit(1);
    }

    fclose(file);

    // Convert to long (max 64 bits)
    long result = 0;
    int bitIndex = 0;

    // Search for the first bit == 1
    int foundStart = 0;
    for (int i = 0; i < totalBytes * 8; i++)
    {
        int byteIndex = i / 8;
        int bitOffset = 7 - (i % 8);
        int bit = (buffer[byteIndex] >> bitOffset) & 1;

        if (!foundStart && bit == 1)
        {
            foundStart = 1;
            bitIndex = 0;
            result = 1;
        }
        else if (foundStart && bitIndex < n - 1)
        {
            result = (result << 1) | bit;
            bitIndex++;
        }

        if (bitIndex == n - 1)
            break;
    }

    free(buffer);

    // If no starting 1 found, fallback
    if (!foundStart)
    {
        fprintf(stderr, "Couldn't find starting bit 1\n");
        exit(1);
    }

    return result;
}

long GenPrime(int n, const char *filename)
{
    if (n < 2 || n > 63)
    {
        fprintf(stderr, "n must be between 2 and 63\n");
        exit(1);
    }

    long lowerBound = 1L << (n - 1); // 2^(n-1)
    long upperBound = (1L << n) - 1; // 2^n - 1
    long candidate = 0;

    while (1)
    {
        candidate = getRandomBitsFromFile(n, filename);
        if (candidate >= lowerBound && candidate <= upperBound)
        {
            break;
        }
    }

    return candidate;
}

// === Test ===
int main()
{
    int n = 50;
    const char *filename = "test.txt";

    long primeCandidate = GenPrime(n, filename);
    printf("Generated number (n=%d): %ld\n", n, primeCandidate);
    printf("Generated number (n=%d): 0x%lX\n", n, primeCandidate);

    return 0;
}