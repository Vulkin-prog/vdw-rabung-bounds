// ============================================================================
// tools/verify_claim.cpp — VÉRIFICATEUR TIERS autonome (artefact de repro, PF1b).
// Entrée (p, r, k) : recalcule le coloriage col(x)=ind(x) mod r par POWMOD sur
// [1,p-1] (méthode indépendante du walk log-discret et de la voie GPU), teste le
// critère de Rabung 1979 (a)∧(b) [concordant avec l'oracle sur le domaine
// exhaustif T1.1], O(p·log p).
// -> ACCEPT certifie W(r,k) > (k-1)p+1. REJECT n'etablit pas la reciproque.
//    Pour records L~10^10 où l'oracle explicite check_naive (~(kp)^2/... ops)
//    est infaisable ; ici O(p log p) est faisable.
//
// THÉORÈME (Rabung, Canad. Math. Bull. 22(1) 1979 p.88 ; son l=notre k, son k=notre r ;
//   p premier ≡1 mod r, p>k) : ϑ' libre de k-progressions mono sur [0,(k-1)p] ⟺
//   (a) aucune k-string mono dans [1,p-1] ET (b) condition de bord (forme B* ci-dessous).
//
// Build : g++ -O2 -std=c++17 -o verify_claim verify_claim.cpp
// Usage : ./verify_claim <p> <r> <k>     |     ./verify_claim --selftest
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <ctime>
using namespace std;
typedef uint64_t u64; typedef __uint128_t u128;

static u64 mulm(u64 a, u64 b, u64 m) {
    return (u64)((u128)a * b % m);
}

static u64 powm(u64 b, u64 e, u64 m) {
    u64 r = 1;
    b %= m;
    while (e) {
        if (e & 1) r = mulm(r, b, m);
        b = mulm(b, b, m);
        e >>= 1;
    }
    return r;
}

static bool is_prime(u64 n) {
    if (n < 2) return false;
    for (u64 q : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        if (n % q == 0) return n == q;
    }
    u64 d = n - 1;
    int s = 0;
    while (!(d & 1)) {
        d >>= 1;
        s++;
    }
    for (u64 a : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        u64 x = powm(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool witness_passed = false;
        for (int i = 1; i < s; i++) {
            x = mulm(x, x, n);
            if (x == n - 1) {
                witness_passed = true;
                break;
            }
        }
        if (!witness_passed) return false;
    }
    return true;
}

static u64 prim_root(u64 p) {
    if (p == 2) return 1;
    u64 n = p - 1;
    vector<u64> factors;
    u64 m = n;
    for (u64 q = 2; q * q <= m; ++q) {
        if (m % q == 0) {
            factors.push_back(q);
            while (m % q == 0) m /= q;
        }
    }
    if (m > 1) factors.push_back(m);
    for (u64 g = 2; g < p; ++g) {
        bool ok = true;
        for (u64 q : factors) {
            if (powm(g, n / q, p) == 1) {
                ok = false;
                break;
            }
        }
        if (ok) return g;
    }
    return 0;
}

// Stockage compact sans tronquer les classes lorsque r > 256. Les claims publies
// n'utilisent que r=2 ou 3, pour lesquels le cout memoire reste d'un octet par x.
class ColorTable {
public:
    ColorTable(size_t count, int colors) {
        if (colors <= 256) {
            width_ = 1;
            col8_.resize(count);
        } else if (colors <= 65536) {
            width_ = 2;
            col16_.resize(count);
        } else {
            width_ = 4;
            col32_.resize(count);
        }
    }

    void set(size_t index, uint32_t color) {
        if (width_ == 1) col8_[index] = static_cast<uint8_t>(color);
        else if (width_ == 2) col16_[index] = static_cast<uint16_t>(color);
        else col32_[index] = color;
    }

    uint32_t operator[](size_t index) const {
        if (width_ == 1) return col8_[index];
        if (width_ == 2) return col16_[index];
        return col32_[index];
    }

private:
    int width_ = 1;
    vector<uint8_t> col8_;
    vector<uint16_t> col16_;
    vector<uint32_t> col32_;
};

// verifie (p,r,k). Renvoie 1=ACCEPT, 0=REJECT ; *why rempli.
static int verify(u64 p,int r,int k,const char** why){
    if(r<2||k<2){*why="params";return 0;}
    if(!is_prime(p)){*why="p non premier";return 0;}
    if((p-1)%(u64)r){*why="p != 1 (mod r)";return 0;}
    if(p<=(u64)k){*why="p <= k";return 0;}
    u64 g=prim_root(p);
    // ζ = g^((p-1)/r) : racine r-ième primitive ; roots[j]=ζ^j -> classe j=ind(x) mod r.
    u64 zeta=powm(g,(p-1)/r,p); vector<u64> roots(r); roots[0]=1; for(int j=1;j<r;j++)roots[j]=mulm(roots[j-1],zeta,p);
    // col(x)=ind(x) mod r via powmod : y=x^((p-1)/r) puis index dans roots.
    ColorTable col(static_cast<size_t>(p), r); // col[x] pour x=1..p-1
    // progression + ETA (règle 2 ; coût negligeable : throttle par pas de p/20, stderr).
    time_t t0=time(0); u64 stepp=(p/20)?(p/20):1;
    for(u64 x=1;x<p;++x){ u64 y=powm(x,(p-1)/r,p); int j=0; while(j<r && roots[j]!=y) j++;
        if(j==r){*why="racine de classe introuvable";return 0;}
        col.set(static_cast<size_t>(x), static_cast<uint32_t>(j));
        if(p>2000000 && x%stepp==0){ double f=(double)x/p; double el=(double)(time(0)-t0);
            fprintf(stderr,"\r  [verify p=%llu] coloriage %.0f%% ; %.0fs ecoule, ETA %.0fs   ",
                (unsigned long long)p, 100*f, el, f>0?el*(1-f)/f:0); fflush(stderr); } }
    if(p>2000000) fprintf(stderr,"\r  [verify p=%llu] coloriage 100%% ; test (a)(b)...            \n",(unsigned long long)p);
    // (a) : pas de k-string mono dans [1,p-1].
    int run=1,maxrun=1; for(u64 n=2;n<p;++n){ if(col[n]==col[n-1]){run++;if(run>maxrun)maxrun=run;} else run=1; }
    if(maxrun>=k){*why="(a) viole : run mono >= k";return 0;}
    // ϑ(-1) : col(p-1) doit valoir 0 ou r/2 (sinon anomalie).
    int colm1=col[p-1]; int th=(colm1==0)?1:(((r%2==0)&&colm1==r/2)?-1:0);
    if(th==0){*why="theta(-1) anormal";return 0;}
    // (b) forme B* : pour chaque j in 0..k-1, les k-1 positions {-j..-1,1..k-1-j}
    //   (couleur de t = col[((t%p)+p)%p]) ne sont PAS toutes de la meme couleur.
    // int64_t is required here: on 64-bit Windows, long remains 32-bit (LLP64),
    // while the frozen high-prime claims exceed INT32_MAX.
    auto cat=[&](int64_t t)->int{
        int64_t modulus=static_cast<int64_t>(p);
        int64_t m=((t%modulus)+modulus)%modulus;
        return col[static_cast<u64>(m)];
    };
    for(int j=0;j<=k-1;++j){ int first=0; bool have=false,same=true;
        for(int t=-j;t<=k-1-j;++t){ if(!t)continue; int c=cat(t); if(!have){first=c;have=true;} else if(c!=first){same=false;break;} }
        if(have&&same){*why="(b) viole (B*)";return 0;} }
    *why="ACCEPT : (a) et (b) OK"; return 1;
}

int main(int argc,char**argv){
    if(argc==4){ u64 p=strtoull(argv[1],0,10); int r=atoi(argv[2]),k=atoi(argv[3]); const char*why;
        int a=verify(p,r,k,&why);
        printf("%s  W(%d,%d) %s %llu  [%s]\n", a?"ACCEPT":"REJECT", r,k, a?">":"(borne non etablie:)",
               a?(u64)(k-1)*p+1:0ull, why);
        return a?0:1; }
    bool records = (argc==2 && !strcmp(argv[1],"--records"));
    // selftest : 5 valides (ACCEPT) + 5 invalides (REJECT), vérités-terrain
    // confirmées vs rabung_criterion (concordance finie T1.1 ; 550/550 accord).
    struct C{u64 p;int r,k;int exp;const char*note;};
    C fast[]={
        {11,2,4,1,"(2,4) valide {5,7,11}"}, {29,2,5,1,"(2,5) valide"},
        {521,520,3,1,"regression classes >255 sans troncature"},
        {43,3,8,1,"(3,8) valide"}, {409,3,9,1,"(3,9) valide"},
        {13,2,4,0,"(2,4) invalide"}, {17,2,4,0,"(2,4) invalide"}, {23,2,4,0,"(2,4) invalide"},
        {101,2,6,0,"(2,6) invalide"}, {163,4,8,0,"(4,8) invalide"} };
    C recs[]={ {969347371ull,3,17,1,"record Monroe W(3,17)>15,5e9"}, {958485937ull,2,25,1,"record Monroe W(2,25)>23,0e9"} };
    int fails=0, n=0;
    C* set = records? recs : fast; int ns = records? 2 : 10;
    if(records) printf("# verification des records publiés Monroe (p~10^9, ~min chacun)\n");
    for(int i=0;i<ns;i++){ C&c=set[i]; const char*why; int a=verify(c.p,c.r,c.k,&why); n++;
        bool ok=(a==c.exp); if(!ok)fails++;
        printf("[%s] (p=%llu r=%d k=%d) -> %s (attendu %s) : %s  {%s}\n", ok?"OK":"**FAIL**",
            (unsigned long long)c.p,c.r,c.k, a?"ACCEPT":"REJECT", c.exp?"ACCEPT":"REJECT", why, c.note); }
    printf("\n== %s : %d/%d OK ==\n", records?"RECORDS":"SELFTEST", n-fails, n);
    return fails?1:0;
}
