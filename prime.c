#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "elgamal_utils.h"

int main()
{
    int n = 71;
    gen_random_with_inverse(n);
    return 0;
}