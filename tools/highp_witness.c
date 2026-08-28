// highp_witness.c — TÉMOIN INDÉPENDANT DE HAUTE PLAGE pour le scanner Rabung.
//
// RAISON D'ÊTRE (2026-07-25). Le nouveau scanner sm_120 corrige une perte de
// retenue dans montmul qui rendait l'ancien code faux pour p >= 2^32*(V5-1)/2
// ~ 2,654e9 (mesuré : 5,8 % de produits faux a 3,46e9, 25 % pres de 2^32).
// La campagne passee (<= 2e9) est intacte, mais la plage NEUVE [2e9, 2^32]
// n'est validee que sur les PRIMITIVES (--montcheck), jamais sur le scanner
// complet. Ce programme fournit le temoin manquant.
//
// INDEPENDANCE (c'est tout l'objet) :
//   - AUCUN code partage avec src/scan_gpu.cu : fichier autonome, zero include projet ;
//   - AUCUN Montgomery : mulmod = (u64)a*b % p, exact par construction pour p < 2^32
//     (a*b < 2^64), donc structurellement insensible au bug teste ;
//   - AUCUN CUB, aucun monoide de segments, aucune reduction parallele :
//     balayage SEQUENTIEL de x = 1..p-1 ;
//   - INTERVALLE PLEIN : ne suppose pas la symetrie miroir, donc valide AUSSI
//     le recollement central de V2a (qui, lui, ne scanne qu'un demi-intervalle) ;
//   - racine primitive recalculee ici, jamais recue du programme teste.
//
// COUT : memoire 2*p octets (8,6 Go a p ~ 4,29e9) ; temps O(p).
//
// SORTIES : maxrun_r pour chaque r de RMIN..RMAX divisant p-1, plus quatre
// autocontroles du temoin lui-meme (un temoin non valide ne prouve rien) :
//   [C1] g est bien une racine primitive (g^((p-1)/q) != 1 pour tout q | p-1) ;
//   [C2] la marche revient a 1 apres exactement p-1 pas et couvre tout ;
//   [C3] echantillon : col(x) par la marche == col(x) par caractere x^((p-1)/r) ;
//   [C4] echantillon : identite miroir col(p-x) == col(x) + col(-1) mod r
//        (c'est l'hypothese exacte sur laquelle V2a repose).
//
// USAGE : highp_witness <p> [nb_echantillons_C3C4]
// Compilation : gcc -O2 -std=c17 -Wall -Wextra -o highp_witness highp_witness.c

#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

typedef uint32_t u32;
typedef uint64_t u64;

#define RMIN 2
#define RMAX 9
#define LCM_ALL 2520u   /* ppcm(1..9) : permet de deriver tous les r d'une seule marche */

/* Meme encodage canonique que tools/claim_audit.py : mots u64 little-endian. */
static u64 fnv1a_u64_le(u64 h, u64 value) {
    for (int i = 0; i < 8; ++i) {
        h ^= value & 0xffu;
        h *= 1099511628211ull;
        value >>= 8;
    }
    return h;
}

static u64 mulmod(u64 a, u64 b, u64 p) { return (a * b) % p; }   /* exact : p < 2^32 */

static u64 powmod(u64 b, u64 e, u64 p) {
    u64 r = 1; b %= p;
    while (e) { if (e & 1) r = mulmod(r, b, p); b = mulmod(b, b, p); e >>= 1; }
    return r;
}

static int is_prime(u64 n) {
    if (n < 2) return 0;
    if (!(n & 1)) return n == 2;
    for (u64 d = 3; d * d <= n; d += 2) if (n % d == 0) return 0;
    return 1;
}

/* facteurs premiers distincts de n (n < 2^32 : division d'essai suffit) */
static int factor_distinct(u64 n, u64 *out) {
    int k = 0;
    for (u64 d = 2; d * d <= n; ++d)
        if (n % d == 0) { out[k++] = d; while (n % d == 0) n /= d; }
    if (n > 1) out[k++] = n;
    return k;
}

/* plus petite racine primitive, recalculee ici (jamais recue de l'exterieur) */
static u32 primitive_root(u64 p, u64 *fac, int nf) {
    for (u64 g = 2; g < p; ++g) {
        int ok = 1;
        for (int i = 0; i < nf && ok; ++i)
            if (powmod(g, (p - 1) / fac[i], p) == 1) ok = 0;
        if (ok) return (u32)g;
    }
    return 0;
}

static double now_s(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + 1e-9 * ts.tv_nsec;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <p> [nsamples]\n", argv[0]); return 2; }
    u64 p = strtoull(argv[1], 0, 10);
    long nsamp = (argc > 2) ? atol(argv[2]) : 20000;

    if (p < 5 || p >= (1ull << 32)) { fprintf(stderr, "p doit verifier 5 <= p < 2^32\n"); return 2; }
    if (!is_prime(p)) { fprintf(stderr, "p=%llu n'est pas premier\n", (unsigned long long)p); return 2; }

    u64 fac[64]; int nf = factor_distinct(p - 1, fac);
    u32 g = primitive_root(p, fac, nf);
    if (!g) { fprintf(stderr, "racine primitive introuvable\n"); return 2; }

    /* [C1] g est primitive : verification explicite, re-jouee et affichee */
    int c1 = 1;
    for (int i = 0; i < nf; ++i) if (powmod(g, (p - 1) / fac[i], p) == 1) c1 = 0;
    if (powmod(g, p - 1, p) != 1) c1 = 0;

    printf("# TEMOIN HAUTE PLAGE  p=%llu  g=%u  p-1 = ", (unsigned long long)p, g);
    for (int i = 0; i < nf; ++i) printf("%s%llu", i ? "*" : "", (unsigned long long)fac[i]);
    printf("(...)   memoire=%.2f Go\n", 2.0 * (double)p / 1e9);
    printf("[C1] racine primitive : %s\n", c1 ? "OK" : "ECHEC");
    if (!c1) return 1;

    uint16_t *val = (uint16_t *)malloc((size_t)p * sizeof(uint16_t));
    if (!val) { fprintf(stderr, "allocation de %.2f Go refusee\n", 2.0 * (double)p / 1e9); return 2; }
    memset(val, 0xff, (size_t)p * sizeof(uint16_t));   /* 0xffff = jamais ecrit */

    /* marche multiplicative : x = g^i, val[x] = i mod 2520 */
    double t0 = now_s();
    u64 x = 1; u32 im = 0;
    for (u64 i = 0; i < p - 1; ++i) {
        val[x] = (uint16_t)im;
        if (++im == LCM_ALL) im = 0;
        x = mulmod(x, g, p);
    }
    double t_walk = now_s() - t0;

    /* [C2] la marche boucle exactement et couvre tout 1..p-1 */
    int c2 = (x == 1);
    u64 unwritten = 0;
    for (u64 y = 1; y < p; ++y) if (val[y] == 0xffff) unwritten++;
    if (unwritten) c2 = 0;
    printf("[C2] marche fermee (x=1 apres p-1 pas) et couverture complete : %s"
           " (retour=%d, non ecrits=%llu)\n", c2 ? "OK" : "ECHEC",
           (int)(x == 1), (unsigned long long)unwritten);
    if (!c2) { free(val); return 1; }

    /* [C3] echantillon : marche vs caractere.  col_r(x) = j  <=>  x^((p-1)/r) = zeta_r^j */
    /* [C4] echantillon : miroir col(p-x) = col(x) + col(-1) mod r  (hypothese de V2a) */
    long c3_cmp = 0, c3_bad = 0, c4_cmp = 0, c4_bad = 0;
    u64 seed = 0x9E3779B97F4A7C15ull ^ p;
    for (int r = RMIN; r <= RMAX; ++r) {
        if ((p - 1) % (u64)r) continue;
        u64 zeta = powmod(g, (p - 1) / (u64)r, p);
        u64 *root = (u64 *)malloc((size_t)r * sizeof(u64));
        root[0] = 1; for (int j = 1; j < r; ++j) root[j] = mulmod(root[j - 1], zeta, p);
        int colm1 = (int)(((p - 1) / 2) % (u64)r);     /* col(-1) = ind(-1) mod r */
        for (long s = 0; s < nsamp; ++s) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            u64 xx = 1 + (seed >> 1) % (p - 1);
            int cw = val[xx] % r;                       /* par la marche */
            u64 y = powmod(xx, (p - 1) / (u64)r, p);    /* par le caractere */
            int cc = -1; for (int j = 0; j < r; ++j) if (root[j] == y) { cc = j; break; }
            c3_cmp++; if (cc != cw) c3_bad++;
            int cmir = val[p - xx] % r;
            c4_cmp++; if (cmir != (cw + colm1) % r) c4_bad++;
        }
        free(root);
    }
    printf("[C3] marche vs caractere : %ld comparaisons, %ld desaccords -> %s\n",
           c3_cmp, c3_bad, c3_bad ? "ECHEC" : "OK");
    printf("[C4] identite miroir (hypothese V2a) : %ld comparaisons, %ld desaccords -> %s\n",
           c4_cmp, c4_bad, c4_bad ? "ECHEC" : "OK");

    /* maxrun : UNE passe sequentielle sur x = 1..p-1, tous les r actifs a la fois */
    int prev[RMAX + 1], run[RMAX + 1], best[RMAX + 1], active[RMAX + 1];
    for (int r = RMIN; r <= RMAX; ++r) {
        active[r] = ((p - 1) % (u64)r == 0);
        prev[r] = -1; run[r] = 0; best[r] = 0;
    }
    t0 = now_s();
    for (u64 y = 1; y < p; ++y) {
        int v = val[y];
        for (int r = RMIN; r <= RMAX; ++r) {
            if (!active[r]) continue;
            int c = v % r;
            if (c == prev[r]) run[r]++; else { prev[r] = c; run[r] = 1; }
            if (run[r] > best[r]) best[r] = run[r];
        }
    }
    double t_scan = now_s() - t0;

    /* Le checksum engage d'abord p : deux premiers au meme profil ne peuvent
       plus recevoir le meme identifiant par construction de l'entree. */
    u64 cs = fnv1a_u64_le(14695981039346656037ull, p);
    printf("# maxrun par r (balayage sequentiel plein intervalle)\n");
    for (int r = RMIN; r <= RMAX; ++r) {
        if (!active[r]) continue;
        printf("WITNESS p=%llu r=%d maxrun=%d\n", (unsigned long long)p, r, best[r]);
        cs = fnv1a_u64_le(cs, (u64)r);
        cs = fnv1a_u64_le(cs, (u64)best[r]);
    }
    printf("WITNESS_CHECKSUM %llu\n", (unsigned long long)cs);
    printf("# temps : marche %.1f s, balayage %.1f s\n", t_walk, t_scan);
    printf("VERDICT_TEMOIN : %s\n",
           (c1 && c2 && !c3_bad && !c4_bad) ? "VALIDE" : "INVALIDE");

    free(val);
    return (c1 && c2 && !c3_bad && !c4_bad) ? 0 : 1;
}
