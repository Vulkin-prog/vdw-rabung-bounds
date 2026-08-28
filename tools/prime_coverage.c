/* Independent segmented sieve used for count and prime-identity audits.
 *
 * It shares no code with sieve_primes() in src/scan_gpu.cu.  The canonical
 * stream mode is intentionally textual and records both requested endpoints;
 * the interval itself is half-open, [lo, hi):
 *
 *   VDW-PRIMES-v1
 *   <lo>
 *   <hi>
 *   <p1>
 *   ...
 *
 * Build: gcc -O2 -std=c11 tools/prime_coverage.c -o tools/prime_coverage
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CAMPAIGN_LO 970000000ULL
#define CAMPAIGN_HI 2000000000ULL
#define CAMPAIGN_CHUNK 2000000ULL

typedef struct {
    uint32_t *items;
    size_t count;
} prime_base;

static prime_base make_base(uint64_t hi) {
    uint64_t limit = 1;
    while (limit * limit < hi) ++limit;
    uint8_t *composite = calloc((size_t)limit + 1, 1);
    uint32_t *items = malloc(((size_t)limit + 1) * sizeof(*items));
    if (!composite || !items) {
        fprintf(stderr, "allocation failure\n");
        exit(2);
    }
    size_t count = 0;
    for (uint64_t p = 2; p <= limit; ++p) {
        if (composite[p]) continue;
        items[count++] = (uint32_t)p;
        if (p <= limit / p)
            for (uint64_t j = p * p; j <= limit; j += p) composite[j] = 1;
    }
    free(composite);
    prime_base result = {items, count};
    return result;
}

typedef void (*prime_callback)(uint64_t prime, void *context);

static uint64_t segmented_sieve(uint64_t lo, uint64_t hi,
                                prime_callback callback, void *context) {
    if (hi < lo || hi - lo > 100000000ULL) {
        fprintf(stderr, "invalid or excessively wide interval\n");
        exit(2);
    }
    size_t width = (size_t)(hi - lo);
    uint8_t *composite = calloc(width ? width : 1, 1);
    if (!composite) {
        fprintf(stderr, "allocation failure\n");
        exit(2);
    }
    prime_base base = make_base(hi);
    for (size_t index = 0; index < base.count; ++index) {
        uint64_t p = base.items[index];
        uint64_t start = lo / p + (lo % p != 0);
        start *= p;
        if (start < p * p) start = p * p;
        for (uint64_t value = start; value < hi; value += p)
            composite[value - lo] = 1;
    }
    uint64_t count = 0;
    for (uint64_t value = lo; value < hi; ++value) {
        if (value < 2 || composite[value - lo]) continue;
        ++count;
        if (callback) callback(value, context);
    }
    free(base.items);
    free(composite);
    return count;
}

static void print_prime(uint64_t prime, void *context) {
    (void)context;
    printf("%" PRIu64 "\n", prime);
}

typedef struct {
    uint64_t by_modulus[10];
} count_context;

static void count_classes(uint64_t prime, void *raw) {
    count_context *context = raw;
    for (int r = 2; r <= 9; ++r)
        if ((prime - 1) % (uint64_t)r == 0) ++context->by_modulus[r];
}

static int dump_stream(uint64_t lo, uint64_t hi) {
    printf("VDW-PRIMES-v1\n%" PRIu64 "\n%" PRIu64 "\n", lo, hi);
    segmented_sieve(lo, hi, print_prime, NULL);
    return 0;
}

static int campaign_counts(void) {
    uint64_t total = 0, totals[10] = {0};
    printf("# chunk_lo chunk_hi n_primes n_r2 n_r3 n_r4 n_r5 n_r6 n_r7 n_r8 n_r9\n");
    for (uint64_t lo = CAMPAIGN_LO; lo < CAMPAIGN_HI; lo += CAMPAIGN_CHUNK) {
        uint64_t hi = lo + CAMPAIGN_CHUNK;
        if (hi > CAMPAIGN_HI) hi = CAMPAIGN_HI;
        count_context context = {{0}};
        uint64_t count = segmented_sieve(lo, hi, count_classes, &context);
        printf("%" PRIu64 " %" PRIu64 " %" PRIu64, lo, hi, count);
        for (int r = 2; r <= 9; ++r) {
            printf(" %" PRIu64, context.by_modulus[r]);
            totals[r] += context.by_modulus[r];
        }
        printf("\n");
        total += count;
    }
    fprintf(stderr, "TOTAL primes [9.7e8, 2e9) = %" PRIu64 "\n", total);
    for (int r = 2; r <= 9; ++r)
        fprintf(stderr, "TOTAL r=%d (p=1 mod %d) = %" PRIu64 "\n",
                r, r, totals[r]);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "--dump-primes") == 0) {
        char *end_lo = NULL, *end_hi = NULL;
        uint64_t lo = strtoull(argv[2], &end_lo, 10);
        uint64_t hi = strtoull(argv[3], &end_hi, 10);
        if (!end_lo || *end_lo || !end_hi || *end_hi || hi < lo ||
            hi > (uint64_t)UINT32_MAX + 1) {
            fprintf(stderr, "usage: %s --dump-primes LO HI\n", argv[0]);
            return 2;
        }
        return dump_stream(lo, hi);
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--dump-primes LO HI]\n", argv[0]);
        return 2;
    }
    return campaign_counts();
}
