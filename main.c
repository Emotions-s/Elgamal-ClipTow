#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "phase1.h"

int main()
{
    int n;
    printf("Enter n: ");
    scanf("%d", &n);
    printf("%d\n", gen_random_with_inverse(n));
    return 0;
}