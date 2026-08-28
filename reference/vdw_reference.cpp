// ============================================================================
// vdw_reference.cpp — Oracle de référence + générateur Rabung (Brief A)
// ----------------------------------------------------------------------------
// RÔLE : ancre de correction du projet. Tout résultat important doit passer
// par cet oracle (lent, simple, évidemment correct). Le code GPU ne fait
// qu'accélérer la RECHERCHE ; il ne participe jamais à la PREUVE.
//
// Contenu :
//   1. check_naive   : oracle triple-boucle (évidemment correct)
//   2. check_bitset  : oracle bitset shift-AND (motif algorithmique à porter
//                      sur GPU) — validé par comparaison croisée avec (1)
//   3. compute_W     : calcul exhaustif de W(r,k) par backtracking (tiny cases)
//   4. Générateur Rabung périodique + variantes de bord (règle Q0 empirique)
//   5. Self-tests : valeurs connues, comparaison croisée, test de mutation,
//                   known-answer Rabung (W(4,3)=76 via p=37 ; W(2,4)=35 via p=11)
//
// Compilation : g++ -O2 -std=c++17 -o vdw_ref vdw_reference.cpp
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <random>
#include <algorithm>
#include <string>

using namespace std;
typedef uint64_t u64;
typedef __uint128_t u128;

static int g_failures = 0;
#define CHECK(cond, ...) do { if(!(cond)) { printf("  [ECHEC] "); printf(__VA_ARGS__); printf("\n"); g_failures++; } else { printf("  [ok] "); printf(__VA_ARGS__); printf("\n"); } } while(0)

// ============================================================================
// 1. ORACLE NAÏF — coloration c[1..N], valeurs 0..r-1.
//    Retourne true si AUCUNE progression arithmétique monochrome de longueur k.
// ============================================================================
struct Violation { long a, d; int color; };

static bool check_naive(const vector<uint8_t>& c, long N, int k, Violation* out = nullptr) {
    for (long d = 1; (long)(k - 1) * d <= N - 1; ++d) {
        for (long a = 1; a + (long)(k - 1) * d <= N; ++a) {
            uint8_t col = c[a];
            bool mono = true;
            for (int i = 1; i < k; ++i)
                if (c[a + (long)i * d] != col) { mono = false; break; }
            if (mono) { if (out) *out = { a, d, (int)col }; return false; }
        }
    }
    return true;
}

// ============================================================================
// 2. ORACLE BITSET — même sémantique, via T &= (T >> d), répété (k-1) fois,
//    par couleur. C'est exactement le motif décalage+AND(+popcount) destiné
//    au portage GPU/AVX-512. Bit (i-1) du bitset <=> entier i.
// ============================================================================
static void shift_right_into(const vector<u64>& src, long sh, vector<u64>& dst) {
    long W = (long)src.size();
    long ws = sh >> 6; int bs = (int)(sh & 63);
    for (long t = 0; t < W; ++t) {
        u64 v = 0;
        if (t + ws < W) {
            v = src[t + ws] >> bs;
            if (bs && t + ws + 1 < W) v |= src[t + ws + 1] << (64 - bs);
        }
        dst[t] = v;
    }
}

static bool check_bitset(const vector<uint8_t>& c, long N, int r, int k) {
    long W = (N + 63) / 64;
    vector<vector<u64>> B(r, vector<u64>(W, 0));
    for (long i = 1; i <= N; ++i)
        B[c[i]][(i - 1) >> 6] |= 1ull << ((i - 1) & 63);
    vector<u64> T(W), S(W);
    for (int col = 0; col < r; ++col) {
        long dmax = (N - 1) / (k - 1);
        for (long d = 1; d <= dmax; ++d) {
            T = B[col];
            bool alive = true;
            for (int j = 1; j < k; ++j) {            // T &= (T >> d), k-1 fois
                shift_right_into(T, d, S);
                u64 acc = 0;
                for (long t = 0; t < W; ++t) { T[t] &= S[t]; acc |= T[t]; }
                if (!acc) { alive = false; break; }
            }
            if (alive) return false;                  // bit survivant = AP monochrome
        }
    }
    return true;
}

// ============================================================================
// 3. CALCUL EXHAUSTIF DE W(r,k) (backtracking) — pour les très petits cas.
//    Vérité terrain indépendante de tout le reste.
// ============================================================================
static bool extend(vector<uint8_t>& c, long N, int r, int k) {
    long pos = (long)c.size();           // prochaine position à colorier (1-indexé)
    if (pos > N) return true;
    for (int col = 0; col < r; ++col) {
        c.push_back((uint8_t)col);
        bool ok = true;                  // ne tester que les AP finissant en pos
        for (long d = 1; pos - (long)(k - 1) * d >= 1; ++d) {
            bool mono = true;
            for (int i = 1; i < k; ++i)
                if (c[pos - (long)i * d] != col) { mono = false; break; }
            if (mono) { ok = false; break; }
        }
        if (ok && extend(c, N, r, k)) return true;
        c.pop_back();
    }
    return false;
}

static long compute_W(int r, int k, long cap) {
    // Plus petit N tel qu'aucune coloration valide de [1,N] n'existe.
    for (long N = 1; N <= cap; ++N) {
        vector<uint8_t> c{ 0 };          // c[0] inutilisé
        if (!extend(c, N, r, k)) return N;
    }
    return -1;
}

static bool find_valid_coloring(int r, int k, long N, vector<uint8_t>& out) {
    out.assign(1, 0);
    return extend(out, N, r, k);
}

// ============================================================================
// 4. GÉNÉRATEUR RABUNG
//    p premier, p ≡ 1 (mod r), g racine primitive mod p.
//    Coloration périodique : c(x) = ind_g(x mod p) mod r pour x non multiple
//    de p ; les multiples de p reçoivent une couleur spéciale sp (paramètre).
//    Variantes de bord testées (question Q0, réglée EMPIRIQUEMENT ici) :
//      - L = (k-1)p           (périodique pur)
//      - L = (k-1)p + 1, dernier élément recolorié en 'app' (essai des r choix)
// ============================================================================
static u64 mulmod(u64 a, u64 b, u64 m) { return (u64)((u128)a * b % m); }
static u64 powmod(u64 b, u64 e, u64 m) {
    u64 r = 1; b %= m;
    while (e) { if (e & 1) r = mulmod(r, b, m); b = mulmod(b, b, m); e >>= 1; }
    return r;
}
static bool is_prime_u64(u64 n) {
    if (n < 2) return false;
    for (u64 p : {2ull,3ull,5ull,7ull,11ull,13ull,17ull,19ull,23ull,29ull,31ull,37ull}) {
        if (n % p == 0) return n == p;
    }
    u64 d = n - 1; int s = 0;
    while (!(d & 1)) { d >>= 1; s++; }
    for (u64 a : {2ull,3ull,5ull,7ull,11ull,13ull,17ull,19ull,23ull,29ull,31ull,37ull}) {
        u64 x = powmod(a % n, d, n);
        if (x == 1 || x == n - 1) continue;
        bool comp = true;
        for (int i = 1; i < s; ++i) { x = mulmod(x, x, n); if (x == n - 1) { comp = false; break; } }
        if (comp) return false;
    }
    return true;
}
static vector<u64> prime_factors(u64 n) {
    vector<u64> f;
    for (u64 p = 2; p * p <= n; ++p)
        if (n % p == 0) { f.push_back(p); while (n % p == 0) n /= p; }
    if (n > 1) f.push_back(n);
    return f;
}
static u64 primitive_root(u64 p) {
    vector<u64> f = prime_factors(p - 1);
    for (u64 g = 2; g < p; ++g) {
        bool ok = true;
        for (u64 q : f) if (powmod(g, (p - 1) / q, p) == 1) { ok = false; break; }
        if (ok) return g;
    }
    return 0;
}

// Coloration périodique de [1,L] ; ind précalculé (taille p). sp = couleur des multiples de p.
static void build_periodic(const vector<int>& ind, u64 p, int r, long L, int sp, vector<uint8_t>& c) {
    c.assign(L + 1, 0);
    for (long x = 1; x <= L; ++x) {
        long m = (long)(x % (long)p);
        c[x] = (m == 0) ? (uint8_t)sp : (uint8_t)(ind[m] % r);
    }
}

// Meilleure longueur valide trouvée pour (r,k,p) parmi les variantes de bord.
// Retourne 0 si rien ne passe. Renseigne la description de la variante gagnante.
static long rabung_best_length(u64 p, int r, int k, string& desc, vector<uint8_t>* best_col = nullptr) {
    if (p < 3 || (p - 1) % r != 0 || !is_prime_u64(p)) return 0;
    u64 g = primitive_root(p);
    vector<int> ind((size_t)p, 0);
    u64 x = 1;
    for (u64 i = 0; i < p - 1; ++i) { ind[(size_t)x] = (int)i; x = mulmod(x, g, p); }

    long L0 = (long)(k - 1) * (long)p;
    long best = 0; desc = "";
    vector<uint8_t> c;
    for (int sp = 0; sp < r; ++sp) {
        // Variante A : périodique pur, longueur (k-1)p
        build_periodic(ind, p, r, L0, sp, c);
        if (check_naive(c, L0, k)) {
            if (L0 > best) { best = L0; desc = "periodique L=(k-1)p, sp=" + to_string(sp); if (best_col) *best_col = c; }
            // Variante B : append 1 élément recolorié, longueur (k-1)p+1
            for (int app = 0; app < r; ++app) {
                build_periodic(ind, p, r, L0 + 1, sp, c);
                c[L0 + 1] = (uint8_t)app;
                if (check_naive(c, L0 + 1, k)) {
                    if (L0 + 1 > best) { best = L0 + 1; desc = "append L=(k-1)p+1, sp=" + to_string(sp) + ", app=" + to_string(app); if (best_col) *best_col = c; }
                }
            }
        }
    }
    return best;
}

// ============================================================================
// 5. SELF-TESTS
// ============================================================================
int main() {
    printf("=== vdw_reference : self-tests ===\n");

    // --- 5.1 Vérité terrain exhaustive (valeurs connues) -------------------
    printf("\n[5.1] Valeurs exactes par backtracking exhaustif\n");
    long w23 = compute_W(2, 3, 50);
    CHECK(w23 == 9, "W(2,3) = %ld (attendu 9)", w23);
    long w33 = compute_W(3, 3, 50);
    CHECK(w33 == 27, "W(3,3) = %ld (attendu 27)", w33);
    long w24 = compute_W(2, 4, 60);
    CHECK(w24 == 35, "W(2,4) = %ld (attendu 35)", w24);

    // --- 5.2 Comparaison croisée naive vs bitset ----------------------------
    printf("\n[5.2] Comparaison croisee check_naive / check_bitset (400 colorations aleatoires)\n");
    {
        mt19937_64 rng(20260612ull);     // seed loggee
        int agree = 0, total = 0, disagreements = 0;
        for (int t = 0; t < 400; ++t) {
            int r = 2 + (int)(rng() % 3);            // 2..4 couleurs
            int k = 3 + (int)(rng() % 4);            // 3..6
            long N = 50 + (long)(rng() % 350);       // 50..399
            vector<uint8_t> c(N + 1);
            for (long i = 1; i <= N; ++i) c[i] = (uint8_t)(rng() % r);
            bool a = check_naive(c, N, k);
            bool b = check_bitset(c, N, r, k);
            total++;
            if (a == b) agree++; else disagreements++;
        }
        CHECK(disagreements == 0, "accord naive/bitset : %d/%d", agree, total);
    }

    // --- 5.3 Test de mutation (l'oracle detecte une AP implantee) ----------
    printf("\n[5.3] Test de mutation : implantation d'une AP monochrome\n");
    {
        vector<uint8_t> c;
        bool found = find_valid_coloring(2, 4, 34, c);   // longueur W(2,4)-1
        CHECK(found, "coloration valide de [1,34] pour (r=2,k=4) trouvee");
        if (found) {
            CHECK(check_naive(c, 34, 4) && check_bitset(c, 34, 2, 4), "la coloration passe les deux oracles");
            long a = 5, d = 7;                            // implanter a, a+d, a+2d, a+3d
            for (int i = 0; i < 4; ++i) c[a + (long)i * d] = 1;
            CHECK(!check_naive(c, 34, 4), "naive rejette apres mutation");
            CHECK(!check_bitset(c, 34, 2, 4), "bitset rejette apres mutation");
        }
    }

    // --- 5.4 Known-answer Rabung + experience Q0 ----------------------------
    // Litterature (Herwig et al. EJC 2007, citant Rabung) : p=37 fournit le
    // certificat optimal de longueur 75 pour W(4,3)=76, soit (k-1)p + 1.
    // Constat empirique : la forme periodique pure atteint exactement (k-1)p
    // (l'AP {1, 1+p, ..., 1+(k-1)p} est residu-constante, donc le +1 exige une
    // modification). Q0 : quelle modification ? On cherche ici par force brute
    // une retouche d'UNE seule position realisant le +1.
    printf("\n[5.4] Known-answer Rabung + experience Q0 (forme exacte du +1)\n");
    {
        string d1, d2;
        long b1 = rabung_best_length(37, 4, 3, d1);
        printf("  p=37, (r=4,k=3) -> periodique/append : meilleure longueur %ld [%s]\n", b1, d1.c_str());
        CHECK(b1 == 74, "forme periodique pure = (k-1)p = 74 pour p=37 (base saine)");
        long b2 = rabung_best_length(11, 2, 4, d2);
        printf("  p=11, (r=2,k=4) -> periodique/append : meilleure longueur %ld [%s]\n", b2, d2.c_str());
        CHECK(b2 == 33, "forme periodique pure = (k-1)p = 33 pour p=11 (base saine)");

        // Experience Q0 : retouche mono-position sur [1,(k-1)p+1]
        auto q0_experiment = [&](u64 p, int r, int k) {
            u64 g = primitive_root(p);
            vector<int> ind((size_t)p, 0);
            u64 x = 1;
            for (u64 i = 0; i < p - 1; ++i) { ind[(size_t)x] = (int)i; x = mulmod(x, g, p); }
            long L = (long)(k - 1) * (long)p + 1;
            int found = 0; long ex_pos = -1; int ex_col = -1, ex_sp = -1;
            for (int sp = 0; sp < r; ++sp) {
                vector<uint8_t> c;
                build_periodic(ind, p, r, L, sp, c);
                for (long pos = 1; pos <= L; ++pos) {
                    uint8_t save = c[pos];
                    for (int col = 0; col < r; ++col) {
                        if ((uint8_t)col == save) continue;
                        c[pos] = (uint8_t)col;
                        if (check_naive(c, L, k)) {
                            found++;
                            if (ex_pos < 0) { ex_pos = pos; ex_col = col; ex_sp = sp; }
                        }
                    }
                    c[pos] = save;
                }
            }
            printf("  Q0 p=%llu (r=%d,k=%d), L=%ld : %d retouche(s) mono-position valides",
                   (unsigned long long)p, r, k, L, found);
            if (found) printf(" — ex. pos=%ld -> couleur %d (sp=%d)", ex_pos, ex_col, ex_sp);
            printf("\n");
            return found;
        };
        int f1 = q0_experiment(37, 4, 3);
        int f2 = q0_experiment(11, 2, 4);
        printf("  -> Retouche mono-position : %s.\n", (f1 > 0 || f2 > 0) ? "atteignable" : "NON atteignable");

        // Variante C (hypothese structurelle) : indexation decalee
        //   c(x) = classe((x-1) mod p) pour x non-congru a 1 (mod p) ;
        //   les k positions x = 1, p+1, ..., (k-1)p+1 deviennent des JOKERS.
        //   L'unique AP residu-constante de difference p ({1,1+p,...,1+(k-1)p})
        //   tombe alors entierement sur les jokers -> brisable par choix.
        auto q0_variantC = [&](u64 p, int r, int k) {
            u64 g = primitive_root(p);
            vector<int> ind((size_t)p, 0);
            u64 x = 1;
            for (u64 i = 0; i < p - 1; ++i) { ind[(size_t)x] = (int)i; x = mulmod(x, g, p); }
            long L = (long)(k - 1) * (long)p + 1;
            vector<uint8_t> c(L + 1, 0);
            vector<long> wild;
            for (long t = 1; t <= L; ++t) {
                long m = (long)((t - 1) % (long)p);
                if (m == 0) { wild.push_back(t); c[t] = 0; }
                else c[t] = (uint8_t)(ind[m] % r);
            }
            // (a) tous les jokers de la MEME couleur (r essais)
            int same_ok = -1;
            for (int col = 0; col < r; ++col) {
                for (long w : wild) c[w] = (uint8_t)col;
                if (check_naive(c, L, k)) { same_ok = col; break; }
            }
            // (b) jokers libres (r^k essais, k jokers)
            long combos = 1; for (int i = 0; i < (int)wild.size(); ++i) combos *= r;
            int free_count = 0; vector<int> first_assign;
            for (long m = 0; m < combos; ++m) {
                long mm = m;
                for (size_t i = 0; i < wild.size(); ++i) { c[wild[i]] = (uint8_t)(mm % r); mm /= r; }
                if (check_naive(c, L, k)) {
                    free_count++;
                    if (first_assign.empty())
                        for (long w : wild) first_assign.push_back((int)c[w]);
                }
            }
            printf("  Q0/C p=%llu (r=%d,k=%d), L=%ld, %zu jokers : meme-couleur=%s, libres=%d/%ld",
                   (unsigned long long)p, r, k, L, wild.size(),
                   same_ok >= 0 ? ("oui(col=" + to_string(same_ok) + ")").c_str() : "non",
                   free_count, combos);
            if (free_count && same_ok < 0) {
                printf(" — ex. [");
                for (size_t i = 0; i < first_assign.size(); ++i) printf("%s%d", i ? "," : "", first_assign[i]);
                printf("]");
            }
            printf("\n");
            return free_count;
        };
        int c1 = q0_variantC(37, 4, 3);
        int c2 = q0_variantC(11, 2, 4);
        CHECK(c1 > 0, "variante C atteint L=(k-1)p+1=75 pour p=37 (hypothese structurelle Q0)");
        CHECK(c2 > 0, "variante C atteint L=(k-1)p+1=34 pour p=11 (hypothese structurelle Q0)");
        printf("     -> A confirmer en T1 contre Rabung (1979) / Rabung-Lotts (2012) ; le\n");
        printf("        certificat final est de toute facon prouve par l'oracle, pas par la theorie.\n");
    }

    // --- 5.5 Mini-scan de coherence (r=2, k=5) ------------------------------
    // W(2,5) = 178 : toute longueur Rabung valide doit etre <= 177.
    printf("\n[5.5] Mini-scan (r=2,k=5), p < 200 : coherence avec W(2,5)=178\n");
    {
        long global_best = 0; u64 best_p = 0; string bd, dsc;
        for (u64 p = 3; p < 200; ++p) {
            if (!is_prime_u64(p)) continue;
            long b = rabung_best_length(p, 2, 5, dsc);
            if (b > global_best) { global_best = b; best_p = p; bd = dsc; }
        }
        printf("  meilleur : L=%ld via p=%llu [%s]\n", global_best, (unsigned long long)best_p, bd.c_str());
        CHECK(global_best > 0, "au moins un premier valide trouve");
        CHECK(global_best <= 177, "aucune longueur ne depasse W(2,5)-1=177 (coherence)");
    }

    // --- 5.6 Statistique de rarete (illustration de la question Q1) --------
    printf("\n[5.6] Taux de validite des premiers (r=2) : illustration de Q1\n");
    {
        for (int k = 4; k <= 6; ++k) {
            int tested = 0, valid = 0; long bestL = 0; u64 bestp = 0; string dsc;
            for (u64 p = 3; p < 600; ++p) {
                if (!is_prime_u64(p) || (p - 1) % 2 != 0) continue;
                tested++;
                long b = rabung_best_length(p, 2, k, dsc);
                if (b > 0) { valid++; if (b > bestL) { bestL = b; bestp = p; } }
            }
            printf("  k=%d : %d/%d premiers valides (p<600), meilleur L=%ld (p=%llu)\n",
                   k, valid, tested, bestL, (unsigned long long)bestp);
        }
        printf("  (attendu : effondrement du taux quand p >> r^(k-1) — a quantifier en T1)\n");
    }

    printf("\n=== %s : %d echec(s) ===\n", g_failures ? "RESULTAT" : "TOUS LES TESTS PASSENT", g_failures);
    return g_failures ? 1 : 0;
}
