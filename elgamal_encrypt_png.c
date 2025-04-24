// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <stdint.h>
// #include <arpa/inet.h>
// #include <zlib.h>
// #include <openssl/bn.h>
// #include "elgamal_utils.h"
// #include "data_io.h"

// int write_cipher_pair_buf(unsigned char *dest, const BIGNUM *a, const BIGNUM *b)
// {
//     int a_len = BN_num_bytes(a);
//     int b_len = BN_num_bytes(b);

//     memcpy(dest, &a_len, sizeof(int));
//     BN_bn2bin(a, dest + sizeof(int));

//     memcpy(dest + sizeof(int) + a_len, &b_len, sizeof(int));
//     BN_bn2bin(b, dest + sizeof(int) + a_len + sizeof(int));

//     return sizeof(int) + a_len + sizeof(int) + b_len;
// }

// int read_cipher_pair_buf(const unsigned char *src, BIGNUM *a, BIGNUM *b)
// {
//     int a_len = 0, b_len = 0;
//     memcpy(&a_len, src, sizeof(int));
//     BN_bin2bn(src + sizeof(int), a_len, a);

//     memcpy(&b_len, src + sizeof(int) + a_len, sizeof(int));
//     BN_bin2bn(src + sizeof(int) + a_len + sizeof(int), b_len, b);

//     return sizeof(int) + a_len + sizeof(int) + b_len;
// }

// // Helper: write a PNG chunk
// void write_png_chunk(FILE *out, const char *type, const unsigned char *data, uint32_t len)
// {
//     uint32_t net_len = htonl(len);
//     fwrite(&net_len, sizeof(uint32_t), 1, out);
//     fwrite(type, 1, 4, out);
//     fwrite(data, 1, len, out);

//     uLong crc = crc32(0L, Z_NULL, 0);
//     crc = crc32(crc, (const Bytef *)type, 4);
//     crc = crc32(crc, (const Bytef *)data, len);
//     uint32_t crc_be = htonl(crc);
//     fwrite(&crc_be, sizeof(uint32_t), 1, out);
// }

// void elgamal_en_png(BIGNUM *p, BIGNUM *g, BIGNUM *y, const char *in_file, const char *cip_file)
// {
//     FILE *in = fopen(in_file, "rb");
//     FILE *out = fopen(cip_file, "wb");
//     if (!in || !out)
//     {
//         perror("File open failed");
//         exit(1);
//     }

//     unsigned char sig[8];
//     fread(sig, 1, 8, in);
//     fwrite(sig, 1, 8, out);

//     unsigned char *idat_data = malloc(1);
//     size_t idat_size = 0;
//     char chunk_type[5] = {0};
//     while (1)
//     {
//         uint32_t len;
//         if (fread(&len, 4, 1, in) != 1)
//             break;
//         len = ntohl(len);

//         fread(chunk_type, 1, 4, in);
//         unsigned char *data = malloc(len);
//         fread(data, 1, len, in);
//         unsigned char crc[4];
//         fread(crc, 1, 4, in);

//         if (memcmp(chunk_type, "IDAT", 4) == 0)
//         {
//             idat_data = realloc(idat_data, idat_size + len);
//             memcpy(idat_data + idat_size, data, len);
//             idat_size += len;
//         }
//         else
//         {
//             write_png_chunk(out, chunk_type, data, len);
//         }
//         free(data);
//         if (memcmp(chunk_type, "IEND", 4) == 0)
//             break;
//     }

//     BN_CTX *ctx = BN_CTX_new();
//     BN_CTX_start(ctx);
//     BIGNUM *m = BN_CTX_get(ctx);
//     BIGNUM *k = BN_CTX_get(ctx);
//     BIGNUM *a = BN_CTX_get(ctx);
//     BIGNUM *b = BN_CTX_get(ctx);
//     BIGNUM *tmp = BN_CTX_get(ctx);
//     BIGNUM *p1 = BN_CTX_get(ctx);
//     BIGNUM *p2 = BN_CTX_get(ctx);

//     BN_sub(p1, p, BN_value_one());
//     BN_copy(p2, p);
//     BN_sub_word(p2, 2);

//     int block_size = BN_num_bytes(p) - 1;
//     unsigned char *buf = malloc(block_size);
//     unsigned char *enc_buf = malloc(idat_size * 4);
//     size_t enc_size = 0;

//     for (size_t i = 0; i < idat_size; i += block_size)
//     {
//         size_t chunk = (i + block_size <= idat_size) ? block_size : idat_size - i;
//         memset(buf, 0, block_size);
//         memcpy(buf, idat_data + i, chunk);

//         BN_bin2bn(buf, block_size, m);
//         do
//         {
//             BN_rand_range(k, p2);
//             BN_add_word(k, 1);
//             gcd_bn(k, p1, tmp, ctx);
//         } while (!BN_is_one(tmp));

//         fast_expo(g, k, p, a, ctx);
//         fast_expo(y, k, p, tmp, ctx);
//         BN_mod_mul(b, tmp, m, p, ctx);

//         enc_size += write_cipher_pair_buf(enc_buf + enc_size, a, b);
//     }

//     write_png_chunk(out, "IDAT", enc_buf, (uint32_t)enc_size);
//     write_png_chunk(out, "IEND", NULL, 0);

//     free(idat_data);
//     free(buf);
//     free(enc_buf);
//     BN_CTX_end(ctx);
//     BN_CTX_free(ctx);
//     fclose(in);
//     fclose(out);
// }

// void elgamal_de_png(BIGNUM *x, BIGNUM *p, const char *ciph_file, const char *out_file)
// {
//     FILE *in = fopen(ciph_file, "rb");
//     FILE *out = fopen(out_file, "wb");
//     if (!in || !out)
//     {
//         perror("File open failed");
//         exit(1);
//     }

//     unsigned char sig[8];
//     fread(sig, 1, 8, in);
//     fwrite(sig, 1, 8, out);

//     BN_CTX *ctx = BN_CTX_new();
//     BN_CTX_start(ctx);
//     BIGNUM *a = BN_CTX_get(ctx);
//     BIGNUM *b = BN_CTX_get(ctx);
//     BIGNUM *s = BN_CTX_get(ctx);
//     BIGNUM *m = BN_CTX_get(ctx);
//     BIGNUM *tmp = BN_CTX_get(ctx);

//     int block_size = BN_num_bytes(p) - 1;
//     unsigned char *buf = malloc(block_size);

//     char chunk_type[5] = {0};
//     while (1)
//     {
//         uint32_t len;
//         if (fread(&len, 4, 1, in) != 1)
//             break;
//         len = ntohl(len);

//         fread(chunk_type, 1, 4, in);
//         unsigned char *data = malloc(len);
//         fread(data, 1, len, in);
//         fread(tmp, 1, 4, in); // CRC, skip

//         if (memcmp(chunk_type, "IDAT", 4) == 0)
//         {
//             size_t offset = 0;
//             while (offset < len)
//             {
//                 offset += read_cipher_pair_buf(data + offset, a, b);
//                 BN_sub(tmp, p, BN_value_one());
//                 BN_sub(tmp, tmp, x);
//                 fast_expo(a, tmp, p, s, ctx);
//                 BN_mod_mul(m, s, b, p, ctx);
//                 BN_bn2binpad(m, buf, block_size);
//                 fwrite(buf, 1, block_size, out);
//             }
//         }
//         else
//         {
//             write_png_chunk(out, chunk_type, data, len);
//         }
//         free(data);
//         if (memcmp(chunk_type, "IEND", 4) == 0)
//             break;
//     }

//     free(buf);
//     BN_CTX_end(ctx);
//     BN_CTX_free(ctx);
//     fclose(in);
//     fclose(out);
// }
