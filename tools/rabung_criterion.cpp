// ============================================================================
// tools/rabung_criterion.cpp — T1.1 : critère de validité de Rabung (1979),
// transcrit VERBATIM, + preuve d'équivalence critère ⟺ oracle par test exhaustif.
// ----------------------------------------------------------------------------
// reference/vdw_reference.cpp reste GELÉ : on recopie ici, à l'identique, les
// oracles check_naive / check_bitset (mêmes algorithmes, evidemment corrects).
//
// THÉORÈME (Rabung, Canad. Math. Bull. 22(1), 1979, p.88), notation de l'auteur
//   (son k = nb de COULEURS = notre r ; son l = LONGUEUR de progression = notre k ;
//    p premier ≡ 1 (mod k_lui)=(mod r), p > l) :
//
//   Soit ϑ' : [0,(l-1)p] -> G_k telle que ϑ'(n)=ϑ(n) si (n,p)=1 et telle que
//   ϑ' n'est PAS constante sur {0,p,2p,...,(l-1)p}. Alors la k-partition imposée
//   par ϑ' sur [0,(l-1)p] est libre de l-progressions mono-classe SI ET
//   SEULEMENT SI :
//     (a) aucune l-string mono-classe n'apparaît dans [1,p-1] ; et
//     (b) si ϑ(-1)=1, les entiers 1,2,...,⌈(l-1)/2⌉ ne sont pas dans la même
//         classe ; tandis que si ϑ(-1)=-1, les entiers 1,2,...,(l-1) ne sont
//         pas dans la même classe.
//   ⚠️ CE COMMENTAIRE PORTAIT ⌊·⌋ (transcription fautive, cf. docs/01 §T1.1) et a
//      induit une erreur dans un brouillon du papier. CORRIGÉ 2026-07-13 : c'est ⌈·⌉,
//      et un SINGLETON compte comme « même classe » (donc échoue (b)). Le code, lui,
//      teste (B*) — qui a toujours été correct (oracle : 0 désaccord).
//   [Si (a) et (b) : W(k_lui,l) > (l-1)p + 1.]   << il n'y a PAS de condition (c) >>
//
// Lecture précise (corrige la paraphrase suspecte du kit) :
//   * "ne sont pas dans la même classe" = "ne sont pas TOUS dans une seule
//     classe" (non-monochromes entre eux). Un singleton est donc monochromatique
//     et échoue la condition. Le plafond est essentiel : pour k=4 on teste
//     {1,2}, et non le singleton produit à tort par le plancher.
//   * ϑ(-1) ∈ {+1,-1} : c'est la couleur de (p-1). Comme ν(-1)=(p-1)/2,
//     col(p-1)=((p-1)/2) mod r ∈ {0, r/2}. ϑ(-1)=+1 ⟺ col(p-1)=0 ;
//     ϑ(-1)=-1 ⟺ col(p-1)=r/2 (n'arrive que si r pair et t=(p-1)/r impair).
//
// CONVENTION DE TEST : notre certificat (variante C du projet) = ϑ' de Rabung
//   translaté de +1 (positions entières 0..(l-1)p ↦ indices 1..(l-1)p+1 du
//   tableau de l'oracle). La translation préserve les progressions arithmétiques.
//   Les positions LIBRES (multiples de p) reçoivent un coloriage non-constant
//   canonique : 0->couleur 0, les autres multiples->couleur 1. Le théorème
//   garantit que TOUT coloriage non-constant des libres donne le même verdict ;
//   un test fort (énumération complète, petits cas) le revérifie plus bas.
//
// Build : g++ -O2 -std=c++17 -o rabung_criterion rabung_criterion.cpp
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>

using namespace std;
typedef uint64_t u64;
typedef __uint128_t u128;

// ---- oracles recopiés VERBATIM de reference/vdw_reference.cpp ---------------
static bool check_naive(const vector<uint8_t>& c, long N, int k) {
    for (long d = 1; (long)(k - 1) * d <= N - 1; ++d) {
        for (long a = 1; a + (long)(k - 1) * d <= N; ++a) {
            uint8_t col = c[a];
            bool mono = true;
            for (int i = 1; i < k; ++i)
                if (c[a + (long)i * d] != col) { mono = false; break; }
            if (mono) return false;
        }
    }
    return true;
}
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
            for (int j = 1; j < k; ++j) {
                shift_right_into(T, d, S);
                u64 acc = 0;
                for (long t = 0; t < W; ++t) { T[t] &= S[t]; acc |= T[t]; }
                if (!acc) { alive = false; break; }
            }
            if (alive) return false;
        }
    }
    return true;
}

// ---- arithmétique modulaire (recopiée de reference) ------------------------
static u64 mulmod(u64 a, u64 b, u64 m) { return (u64)((u128)a * b % m); }
static u64 powmod(u64 b, u64 e, u64 m) {
    u64 r = 1; b %= m;
    while (e) { if (e & 1) r = mulmod(r, b, m); b = mulmod(b, b, m); e >>= 1; }
    return r;
}
static bool is_prime_u64(u64 n) {
    if (n < 2) return false;
    for (u64 p : {2ull,3ull,5ull,7ull,11ull,13ull,17ull,19ull,23ull,29ull,31ull,37ull})
        if (n % p == 0) return n == p;
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
    for (u64 p = 2; p * p <= n; ++p) if (n % p == 0) { f.push_back(p); while (n % p == 0) n /= p; }
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

// ind[n] = index (log discret) de n base g, pour n=1..p-1 ; ind[0] inutilisé.
static void build_index(u64 p, vector<int>& ind) {
    u64 g = primitive_root(p);
    ind.assign((size_t)p, 0);
    u64 x = 1;
    for (u64 i = 0; i < p - 1; ++i) { ind[(size_t)x] = (int)i; x = mulmod(x, g, p); }
}

// color(n) = ind(n) mod r pour n in [1,p-1] (le coloriage caractère ϑ).
static inline int charcolor(const vector<int>& ind, long n, int r) { return ind[(size_t)n] % r; }

// ============================================================================
// LE CRITÈRE (a)∧(b) — transcription verbatim. r=couleurs, k=longueur (=l de R.)
// ============================================================================
struct CritInfo { bool applicable; bool a; bool b; int theta_m1; int max_run; int m_b; };

static bool rabung_criterion(u64 p, int r, int k, CritInfo* info = nullptr) {
    CritInfo nfo{}; nfo.applicable = false;
    if (info) *info = nfo;
    if (r < 2 || k < 2) return false;
    if (!is_prime_u64(p)) return false;
    if ((p - 1) % (u64)r != 0) return false;   // besoin p ≡ 1 (mod r)
    if (p <= (u64)k) return false;             // hypothèse de Rabung : p > l
    nfo.applicable = true;

    vector<int> ind; build_index(p, ind);

    // (a) : aucune l-string (= k entiers consécutifs même couleur) dans [1,p-1].
    int run = 1, maxrun = 1;
    for (long n = 2; n <= (long)p - 1; ++n) {
        if (charcolor(ind, n, r) == charcolor(ind, n - 1, r)) { run++; if (run > maxrun) maxrun = run; }
        else run = 1;
    }
    bool condA = (maxrun < k);
    nfo.max_run = maxrun;

    // ϑ(-1) : couleur de (p-1) ∈ {0, r/2}. 0 -> +1 ; r/2 -> -1. (Reporting + lien
    // avec la forme littérale de Rabung ; le test (B*) ci-dessous est, lui,
    // indépendant du signe.)
    int colm1 = charcolor(ind, (long)p - 1, r);
    int theta_m1;
    if (colm1 == 0) theta_m1 = +1;
    else if ((r % 2 == 0) && colm1 == r / 2) theta_m1 = -1;
    else theta_m1 = 0;  // ne devrait jamais arriver (anomalie théorique)
    nfo.theta_m1 = theta_m1;

    // (b) FORME OPÉRATIONNELLE (B*) — équivalente à (b) de Rabung, dérivée
    //   rigoureusement et sans hypothèse de parité : pour CHAQUE décalage
    //   j ∈ {0,...,k-1}, les k-1 positions-caractère de la k-string
    //   {-j,...,-1, 1,...,k-1-j} (centrée sur un multiple de p) ne doivent PAS
    //   être toutes de la même couleur. (Si une seule l'est, la dilatation par d
    //   réalise toutes les couleurs -> le multiple devient incoloriable.)
    // Couleur d'un entier t (t≠0 mod p) : charcolor de ((t mod p)+p) mod p.
    auto col_at = [&](long t) -> int {
        long rmod = ((t % (long)p) + (long)p) % (long)p;   // ∈ [0,p-1], ≠0 ici
        return charcolor(ind, rmod, r);
    };
    bool condB = true;
    int worst_j = -1;
    for (int j = 0; j <= k - 1 && condB; ++j) {
        // positions t = -j..-1 et 1..(k-1-j)
        int first = 0; bool have = false, allsame = true;
        for (int t = -j; t <= (k - 1 - j); ++t) {
            if (t == 0) continue;
            int ct = col_at(t);
            if (!have) { first = ct; have = true; }
            else if (ct != first) { allsame = false; break; }
        }
        if (have && allsame) { condB = false; worst_j = j; }   // string mono -> (b) viole
    }
    nfo.m_b = worst_j;   // décalage fautif (-1 si aucun)

    nfo.a = condA; nfo.b = condB;
    if (info) *info = nfo;
    return condA && condB && (theta_m1 != 0);
}

// ============================================================================
// ORACLE — construit ϑ' sur [0,(k-1)p] (indices 1..(k-1)p+1), libres = multiples
// de p, coloriage canonique non-constant (0->0, autres->1), puis check_bitset.
// ============================================================================
static void build_certificate(const vector<int>& ind, u64 p, int r, int k,
                              const vector<int>& freecolors, vector<uint8_t>& c, long& N) {
    N = (long)(k - 1) * (long)p + 1;        // entiers 0..(k-1)p  (N positions)
    c.assign(N + 1, 0);
    int fidx = 0;
    for (long integer = 0; integer <= (long)(k - 1) * (long)p; ++integer) {
        long idx = integer + 1;             // 1-indexé pour l'oracle
        long m = integer % (long)p;
        if (m == 0) c[idx] = (uint8_t)freecolors[fidx++];   // position libre
        else c[idx] = (uint8_t)(ind[(size_t)m] % r);
    }
}

// canonique non-constant : free[0]=0, free[1..]=1
static bool oracle_valid_canonical(u64 p, int r, int k) {
    vector<int> ind; build_index(p, ind);
    vector<int> fc(k, 1); fc[0] = 0;        // k positions libres (0,p,...,(k-1)p)
    vector<uint8_t> c; long N;
    build_certificate(ind, p, r, k, fc, c, N);
    return check_bitset(c, N, r, k);
}

// ============================================================================
// TEST FORT (petits cas) : énumère TOUS les coloriages des libres et vérifie
//   - "∃ coloriage non-constant valide" ⟺ critère ;
//   - uniformité : si critère vrai, TOUT coloriage non-constant est valide ;
//     si critère faux, AUCUN coloriage (même constant) n'est valide.
//   Utilise check_naive (le plus simple). Justifie le raccourci canonique.
// ============================================================================
static void strong_check(u64 p, int r, int k, int& mism, int& checked) {
    vector<int> ind; build_index(p, ind);
    long ncombos = 1; for (int i = 0; i < k; ++i) ncombos *= r;   // r^k coloriages des libres
    bool exists_nonconst_valid = false;
    bool all_nonconst_valid = true; int nonconst_count = 0;
    bool any_valid_at_all = false;
    for (long mcomb = 0; mcomb < ncombos; ++mcomb) {
        vector<int> fc(k); long mm = mcomb; bool constant = true;
        for (int i = 0; i < k; ++i) { fc[i] = (int)(mm % r); mm /= r; if (fc[i] != fc[0]) constant = false; }
        vector<uint8_t> c; long N;
        build_certificate(ind, p, r, k, fc, c, N);
        bool valid = check_naive(c, N, k);
        if (valid) any_valid_at_all = true;
        if (!constant) {
            nonconst_count++;
            if (valid) exists_nonconst_valid = true; else all_nonconst_valid = false;
        }
    }
    bool crit = rabung_criterion(p, r, k);
    checked++;
    // équivalence existence
    if (crit != exists_nonconst_valid) {
        mism++;
        printf("  [FORT-MISMATCH existence] p=%llu r=%d k=%d : crit=%d exists_nonconst_valid=%d\n",
               (unsigned long long)p, r, k, crit, exists_nonconst_valid);
    }
    // uniformité
    if (crit && !all_nonconst_valid) {
        mism++;
        printf("  [FORT-MISMATCH uniformite] p=%llu r=%d k=%d : crit vrai mais coloriage non-const invalide\n",
               (unsigned long long)p, r, k);
    }
    if (!crit && any_valid_at_all) {
        mism++;
        printf("  [FORT-MISMATCH non-validite] p=%llu r=%d k=%d : crit faux mais un coloriage est valide\n",
               (unsigned long long)p, r, k);
    }
}

int main(int argc, char** argv) {
    if (argc == 5 && !strcmp(argv[1], "-q")) {   // CLI : -q p r k -> "1"/"0" (pour cross-check)
        u64 p = strtoull(argv[2], 0, 10); int r = atoi(argv[3]), k = atoi(argv[4]);
        bool accepted = rabung_criterion(p, r, k);
        printf("%d\n", accepted ? 1 : 0);
        return accepted ? 0 : 1;
    }
    if (argc == 5 && !strcmp(argv[1], "-count")) {  // -count Pmax r k : rareté rejet-(b)
        long Pmax = atol(argv[2]); int r = atoi(argv[3]), k = atoi(argv[4]);
        long na = 0, nab = 0, nb_rej = 0;           // (a)-valides, (a∧b)-valides, rejets-(b)
        for (long p = 2; p < Pmax; ++p) {
            if (!is_prime_u64(p) || (p - 1) % r != 0 || p <= k) continue;
            CritInfo nfo; rabung_criterion((u64)p, r, k, &nfo);
            if (!nfo.applicable || !nfo.a) continue;  // seulement les (a)-valides
            na++;
            if (nfo.b && nfo.theta_m1 != 0) nab++; else nb_rej++;
        }
        printf("(r=%d,k=%d) p<%ld : (a)-valides=%ld ; (a∧b)-valides=%ld ; rejets-(b)=%ld ; "
               "taux rejet-(b) parmi (a) = %.4f%%\n", r, k, Pmax, na, nab, nb_rej,
               na ? 100.0*nb_rej/na : 0.0);
        return 0;
    }
    long Pmax = (argc > 1) ? atol(argv[1]) : 10000;
    printf("=== T1.1 : equivalence critere de Rabung (1979) <-> oracle ===\n");
    printf("Domaine principal : p < %ld premiers, r in [2,6], k in [3,8], p > k, p ≡ 1 (mod r).\n\n", Pmax);

    // --- Known answers : trace explicite -----------------------------------
    printf("[KA] Reponses connues :\n");
    struct KA { u64 p; int r, k; const char* note; };
    for (KA ka : { KA{37,4,3,"W(4,3)=76, cert 75"}, KA{11,2,4,"W(2,4)=35, cert 34"},
                   KA{5,2,4,"oracle accepte (cas singleton de (b))"} }) {
        CritInfo nfo; bool crit = rabung_criterion(ka.p, ka.r, ka.k, &nfo);
        bool orac = oracle_valid_canonical(ka.p, ka.r, ka.k);
        long L = (long)(ka.k - 1) * (long)ka.p + 1;
        printf("  p=%llu (r=%d,k=%d) %-32s crit=%d (a=%d b=%d theta(-1)=%+d maxrun=%d m_b=%d) oracle=%d  L=(k-1)p+1=%ld\n",
               (unsigned long long)ka.p, ka.r, ka.k, ka.note, crit, nfo.a, nfo.b, nfo.theta_m1, nfo.max_run, nfo.m_b, orac, L);
    }
    printf("\n");

    // --- Test FORT (énumération complète des libres) sur petits cas --------
    printf("[FORT] Enumeration complete des coloriages libres (p<150, r<=4, k<=5) :\n");
    {
        int mism = 0, checked = 0;
        for (int r = 2; r <= 4; ++r)
            for (int k = 3; k <= 5; ++k)
                for (u64 p = 3; p < 150; ++p)
                    if (is_prime_u64(p) && (p - 1) % (u64)r == 0 && p > (u64)k)
                        strong_check(p, r, k, mism, checked);
        printf("  -> %d cas testes, %d incoherence(s) fortes.\n\n", checked, mism);
    }

    // --- Sweep principal : critere vs oracle canonique ---------------------
    printf("[SWEEP] critere vs oracle (coloriage libre canonique non-constant) :\n");
    int total = 0, mismatches = 0, valid_by_crit = 0;
    for (int r = 2; r <= 6; ++r) {
        for (int k = 3; k <= 8; ++k) {
            for (u64 p = 3; p < (u64)Pmax; ++p) {
                if (!is_prime_u64(p) || (p - 1) % (u64)r != 0 || p <= (u64)k) continue;
                bool crit = rabung_criterion(p, r, k);
                bool orac = oracle_valid_canonical(p, r, k);
                total++;
                if (crit) valid_by_crit++;
                if (crit != orac) {
                    mismatches++;
                    if (mismatches <= 30) {
                        CritInfo nfo; rabung_criterion(p, r, k, &nfo);
                        printf("  [MISMATCH] p=%llu r=%d k=%d : crit=%d (a=%d b=%d th=%+d) oracle=%d\n",
                               (unsigned long long)p, r, k, crit, nfo.a, nfo.b, nfo.theta_m1, orac);
                    }
                }
            }
        }
    }
    printf("\n  -> %d (p,r,k) testes ; %d valides selon critere ; %d MISMATCH(es).\n",
           total, valid_by_crit, mismatches);

    printf("\n=== %s ===\n",
           mismatches == 0 ? "EQUIVALENCE PROUVEE sur le domaine (0 mismatch) : Q0 = proven"
                           : "ECHEC : mismatch(es) -> erreur de transcription a corriger");
    return mismatches ? 1 : 0;
}
