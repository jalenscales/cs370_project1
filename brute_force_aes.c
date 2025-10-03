#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define MAX_WORD_LEN 128

int hex_to_bytes(const char *hex, unsigned char *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2*i, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

int main(void) {
    const char *wordlist = "words.txt";
    FILE *fp = fopen(wordlist, "r");
    if (!fp) {
        perror("Failed to open words.txt");
        return 1;
    }

    const unsigned char iv[16] = {0}; 
    const char *plaintext = "This is a top secret.";
    const size_t pt_len = strlen(plaintext);

    const char *target_hex = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";
    unsigned char target_ct[32];
    if (hex_to_bytes(target_hex, target_ct, 32) != 0) {
        fprintf(stderr, "Invalid target hex\n");
        fclose(fp);
        return 1;
    }

    char line[MAX_WORD_LEN];
    unsigned char key[16];
    unsigned char outbuf[64]; 
    int found = 0;


    while (fgets(line, sizeof(line), fp)) {

        line[strcspn(line, "\r\n")] = '\0';

        size_t wlen = strlen(line);
        if (wlen == 0) continue;         
        if (wlen > 16) continue;        

        memset(key, 0x20, sizeof(key));
        memcpy(key, line, wlen);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
            fclose(fp);
            return 1;
        }

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            fprintf(stderr, "EVP_EncryptInit_ex failed\n");
            fclose(fp);
            return 1;
        }

        int outlen1 = 0, outlen2 = 0;
        if (1 != EVP_EncryptUpdate(ctx, outbuf, &outlen1, (const unsigned char*)plaintext, (int)pt_len)) {
            EVP_CIPHER_CTX_free(ctx);
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            fclose(fp);
            return 1;
        }
        if (1 != EVP_EncryptFinal_ex(ctx, outbuf + outlen1, &outlen2)) {
            EVP_CIPHER_CTX_free(ctx);
            continue;
        }
        int ct_len = outlen1 + outlen2;


        if (ct_len == 32 && memcmp(outbuf, target_ct, 32) == 0) {
            printf("Key found: \"%s\"\n", line);
            found = 1;
            EVP_CIPHER_CTX_free(ctx);
            break;
        }

        EVP_CIPHER_CTX_free(ctx);
    }

    if (!found) {
        printf("Key not found in %s\n", wordlist);
    }

    fclose(fp);
    return (found ? 0 : 2);
}