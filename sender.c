#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include "elgamal_encrypt.h"
#include "elgamal_encrypt_png.h"
#include "elgamal_utils.h"
#include "key_io.h"

void generate_output_filenames(const char *input_filename, char *cipher_filename)
{
    const char *dot = strrchr(input_filename, '.');
    if (!dot)
    {
        sprintf(cipher_filename, "%s_encrypted", input_filename);
    }
    else
    {
        size_t base_len = dot - input_filename;
        strncpy(cipher_filename, input_filename, base_len);
        cipher_filename[base_len] = '\0';
        strcat(cipher_filename, "_encrypted");
        strcat(cipher_filename, dot);
    }
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    BIGNUM *p = BN_CTX_get(ctx);
    BIGNUM *g = BN_CTX_get(ctx);
    BIGNUM *y = BN_CTX_get(ctx);

    read_pub_key("keys/public_key.bin", &p, &g, &y);

    // Get user input for encryption type
    char input_type[10];
    char input_filename[100];
    char output_cipher[150];

    printf("Enter input type ('text' or 'file'): ");
    scanf("%9s", input_type);

    if (strcmp(input_type, "text") == 0)
    {
        // Get plaintext input and write it to "plaintext.txt"
        char buffer[2048];
        printf("Enter plaintext: ");
        getchar(); // flush newline left in buffer
        fgets(buffer, sizeof(buffer), stdin);

        // remove newline if any
        buffer[strcspn(buffer, "\n")] = 0;

        FILE *fp = fopen("data/plaintext.txt", "w");
        if (!fp)
        {
            perror("Failed to open plaintext.txt for writing");
            return 1;
        }
        fputs(buffer, fp);
        fclose(fp);
        printf("Saved to plaintext.txt\n");

        elgamal_en(p, g, y, "data/plaintext.txt", "data/output_cipher.txt");
    }
    else if (strcmp(input_type, "file") == 0)
    {
        printf("Enter filename (with extension): ");
        scanf("%99s", input_filename);

        generate_output_filenames(input_filename, output_cipher);

        elgamal_en(p, g, y, input_filename, output_cipher);
        printf("Encrypted to %s\n", output_cipher);
    }
    else
    {
        printf("Invalid input type.\n");
        return 1;
    }
    printf("Encryption complete.\n");

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return 0;
}
