#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

static void usage(const char *pname) {
    printf("Usage: %s [options]\n", pname);
    printf("Options:\n");
    printf("  -w <n>    : number of weak trials (default 20)\n");
    printf("  -s <n>    : number of strong trials (default 200)\n");
    printf("  -m <len>  : candidate message length in bytes (default 16)\n");
    printf("  -d <name> : digest name: sha256 (default) or sha512\n");
    printf("  --help    : show this help\n");
}


static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int compute_digest(const EVP_MD *md, const unsigned char *data, size_t dlen,
                          unsigned char *out, unsigned int *out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    if (1 != EVP_DigestInit_ex(ctx, md, NULL)) { EVP_MD_CTX_free(ctx); return -1; }
    if (1 != EVP_DigestUpdate(ctx, data, dlen)) { EVP_MD_CTX_free(ctx); return -1; }
    if (1 != EVP_DigestFinal_ex(ctx, out, out_len)) { EVP_MD_CTX_free(ctx); return -1; }
    EVP_MD_CTX_free(ctx);
    return 0;
}

static inline uint32_t trunc24(const unsigned char *digest)
{
    return ((uint32_t)digest[0] << 16) | ((uint32_t)digest[1] << 8) | (uint32_t)digest[2];
}

static uint64_t one_weak_trial(const EVP_MD *md, const unsigned char *msg, size_t msglen,
                               size_t cand_len, uint64_t max_attempts)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    if (compute_digest(md, msg, msglen, digest, &dlen) != 0) {
        fprintf(stderr, "digest failed\n"); return 0;
    }
    uint32_t target = trunc24(digest);

    uint64_t attempts = 0;
    unsigned char *cand = malloc(cand_len);
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    if (!cand) { fprintf(stderr, "malloc failed\n"); exit(1); }

    while (1) {
        if (max_attempts && attempts >= max_attempts) break;
        if (1 != RAND_bytes(cand, (int)cand_len)) { fprintf(stderr,"RAND_bytes failed\n"); break; }
        attempts++;
        if (compute_digest(md, cand, cand_len, out, &outlen) != 0) { fprintf(stderr,"digest failed\n"); break; }
        if (trunc24(out) == target) break;
    }

    free(cand);
    return attempts;
}
static uint64_t one_strong_trial(const EVP_MD *md, size_t cand_len, uint64_t max_attempts)
{
    const uint32_t MAP_BITS = (1u << 24);
    const uint32_t MAP_BYTES = MAP_BITS / 8;
    unsigned char *bitmap = calloc(MAP_BYTES, 1);
    if (!bitmap) { fprintf(stderr, "bitmap alloc failed\n"); exit(1); }

    unsigned char *cand = malloc(cand_len);
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    if (!cand) { fprintf(stderr, "malloc failed\n"); exit(1); }

    uint64_t attempts = 0;
    while (1) {
        if (max_attempts && attempts >= max_attempts) break;
        if (1 != RAND_bytes(cand, (int)cand_len)) { fprintf(stderr,"RAND_bytes failed\n"); break; }
        attempts++;
        if (compute_digest(md, cand, cand_len, out, &outlen) != 0) { fprintf(stderr,"digest failed\n"); break; }
        uint32_t idx = trunc24(out);
        uint32_t byte_idx = idx >> 3;
        uint32_t bit_idx = idx & 7;
        unsigned char mask = (unsigned char)(1u << bit_idx);
        if (bitmap[byte_idx] & mask) {
            break;
        } else {
            bitmap[byte_idx] |= mask;
        }
    }

    free(cand);
    free(bitmap);
    return attempts;
}

int main(int argc, char **argv)
{
    int weak_runs = 20;
    int strong_runs = 200;
    int cand_len = 16;
    const char *digest_name = "sha256";

    for (int i=1;i<argc;i++) {
        if (strcmp(argv[i],"--help")==0) { usage(argv[0]); return 0; }
        if (strcmp(argv[i],"-w")==0 && i+1<argc) { weak_runs = atoi(argv[++i]); continue; }
        if (strcmp(argv[i],"-s")==0 && i+1<argc) { strong_runs = atoi(argv[++i]); continue; }
        if (strcmp(argv[i],"-m")==0 && i+1<argc) { cand_len = atoi(argv[++i]); continue; }
        if (strcmp(argv[i],"-d")==0 && i+1<argc) { digest_name = argv[++i]; continue; }
        fprintf(stderr, "Unknown arg: %s\n", argv[i]); usage(argv[0]); return 1;
    }

    OpenSSL_add_all_algorithms();

    const EVP_MD *md = NULL;
    if (strcmp(digest_name, "sha256")==0) md = EVP_sha256();
    else if (strcmp(digest_name, "sha512")==0) md = EVP_sha512();
    else {
        fprintf(stderr, "Unsupported digest: %s\n", digest_name);
        return 1;
    }

    printf("Experiment settings:\n");
    printf("  digest = %s (truncated to 24 bits)\n", digest_name);
    printf("  candidate message length = %d bytes\n", cand_len);
    printf("  weak runs = %d\n", weak_runs);
    printf("  strong runs = %d\n", strong_runs);
    printf("\n");

    const unsigned char fixed_msg[] = "This is a sample fixed message for weak test.";
    const size_t fixed_msg_len = sizeof(fixed_msg)-1;

    printf("Running weak experiment (fixed message) ...\n");
    uint64_t total_attempts_weak = 0;
    double t0 = now_seconds();
    for (int i=0;i<weak_runs;i++) {
        uint64_t attempts = one_weak_trial(md, fixed_msg, fixed_msg_len, (size_t)cand_len, 0);
        printf("  weak trial %3d attempts = %" PRIu64 "\n", i+1, attempts);
        total_attempts_weak += attempts;
    }
    double t1 = now_seconds();
    double avg_weak = (double)total_attempts_weak / (double)weak_runs;
    printf("Weak experiment average attempts = %.2f (total %" PRIu64 ", time %.2f s)\n\n",
           avg_weak, total_attempts_weak, t1 - t0);

    printf("Running strong (birthday) experiment ...\n");
    uint64_t total_attempts_strong = 0;
    t0 = now_seconds();
    for (int i=0;i<strong_runs;i++) {
        uint64_t attempts = one_strong_trial(md, (size_t)cand_len, 0);
        printf("  strong trial %4d attempts = %" PRIu64 "\n", i+1, attempts);
        total_attempts_strong += attempts;
    }
    t1 = now_seconds();
    double avg_strong = (double)total_attempts_strong / (double)strong_runs;
    printf("Strong experiment average attempts = %.2f (total %" PRIu64 ", time %.2f s)\n\n",
           avg_strong, total_attempts_strong, t1 - t0);

    printf("Summary:\n");
    printf(" - Average attempts to break weak collision resistance (preimage) ≈ %.2f\n", avg_weak);
    printf(" - Average attempts to break strong collision resistance (birthday) ≈ %.2f\n", avg_strong);
    printf("\nHint (theoretical): For 24-bit truncation, expected weak trials ≈ 2^24 ≈ 1.6777e7\n");
    printf("                    expected birthday trials ≈ ~1.25 * 2^(24/2) ≈ ~5130\n");
    return 0;
}