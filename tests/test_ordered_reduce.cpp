// ============================================================================
// tests/test_ordered_reduce.cpp — property-test PERMANENT du monoïde de runs.
// Réplique EXACTEMENT le Summ / SummOp / résumé-par-segment de src/scan_gpu.cu et
// vérifie : (résumé par segments SEG puis fold ORDONNÉ gauche→droite).best ==
// plus long run calculé séquentiellement. Garde anti-régression du bug détecté PF3
// (SummOp associatif NON commutatif : DeviceReduce recombinait dans le désordre).
// Cas : aléatoires (r,N variés) + ADVERSARIAUX (runs à cheval sur segments, whole,
// N non multiple de SEG / dégénéré / alternant / mono / nseg grand non-2^k).
// De plus : un fold en ORDRE MÉLANGÉ DOIT parfois différer (prouve que l'ordre
// est nécessaire — c'est pourquoi on utilise InclusiveScan, pas DeviceReduce).
// Build : g++ -O2 -std=c++17 -o test_ordered_reduce tests/test_ordered_reduce.cpp
// Sortie : "== N/N OK ==" et code retour 0 ssi tout passe (pour le hook de commit).
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <vector>
#include <random>
#include <algorithm>
using namespace std;
static const int SEG=512;                 // == src/scan_gpu.cu

struct Summ{ int len,whole,color,pL,pC,sL,sC,best; };
// merge ORDONNÉ (A gauche, B droite) — copie verbatim de SummOp de scan_gpu.cu.
static Summ merge(const Summ&A,const Summ&B){
    if(A.len==0) return B; if(B.len==0) return A;
    Summ r; r.len=A.len+B.len;
    int cross=(A.sC==B.pC)?(A.sL+B.pL):0;
    r.best=A.best; if(B.best>r.best)r.best=B.best; if(cross>r.best)r.best=cross;
    r.whole=(A.whole&&B.whole&&A.color==B.color)?1:0; r.color=A.color;
    if(A.whole){ r.pC=A.color; r.pL=(A.color==B.pC)?A.len+B.pL:A.len; } else { r.pC=A.pC; r.pL=A.pL; }
    if(B.whole){ r.sC=B.color; r.sL=(B.color==A.sC)?B.len+A.sL:B.len; } else { r.sC=B.sC; r.sL=B.sL; }
    return r;
}
// résumé d'un segment [s,e) de c[] — copie verbatim de k_scan_fused (pour un r).
static Summ seg_summary(const vector<int>& c,long s,long e){
    Summ z; if(s>=e){ z.len=0; return z; }
    int prevc=c[s],run=1,best=1,pL=1,pC=c[s]; bool pdone=false;
    for(long j=s+1;j<e;++j){ int cc=c[j];
        if(cc==prevc){ run++; if(!pdone)pL++; } else { prevc=cc; run=1; pdone=true; }
        if(run>best)best=run; }
    long len=e-s; z.len=(int)len; z.color=pC; z.pC=pC; z.pL=pL; z.sC=prevc; z.sL=run; z.best=best;
    z.whole=(pL==(int)len)?1:0; return z;
}
// maxrun de référence : scan séquentiel direct.
static int direct_maxrun(const vector<int>& c){
    if(c.empty())return 0; int run=1,best=1;
    for(size_t i=1;i<c.size();++i){ if(c[i]==c[i-1])run++; else run=1; if(run>best)best=run; } return best;
}
// résumé par segments SEG puis fold ORDONNÉ gauche->droite.
static int ordered_reduce_best(const vector<int>& c){
    long N=(long)c.size(); if(N==0)return 0;
    long nseg=(N+SEG-1)/SEG; Summ acc; acc.len=0;
    for(long s=0;s<N;s+=SEG) acc=merge(acc, seg_summary(c,s,min(s+(long)SEG,N)));
    return acc.best;
}

int main(){
    mt19937_64 rng(20260702ull); int fails=0,tot=0;
    auto check=[&](const vector<int>& c,const char*name){ tot++;
        int a=direct_maxrun(c), b=ordered_reduce_best(c);
        if(a!=b){ fails++; printf("[FAIL] %s : direct=%d ordered=%d (N=%zu)\n",name,a,b,c.size()); } };

    // 1) aléatoires : r in {2..9}, N in [1, ~30*SEG], densités variées
    for(int it=0;it<4000;++it){ int r=2+(int)(rng()%8); long N=1+(long)(rng()% (30*SEG));
        // biais vers des runs longs la moitié du temps (proba de répéter)
        double prep=(it&1)? 0.8 : 0.0; vector<int> c(N); c[0]=(int)(rng()%r);
        for(long i=1;i<N;++i){ if((rng()%1000)/1000.0 < prep) c[i]=c[i-1]; else c[i]=(int)(rng()%r); }
        check(c,"random"); }

    // 2) adversariaux
    { vector<int> c(3*SEG,0); check(c,"tout mono (whole, run=N)"); }          // run traverse plusieurs segments
    { vector<int> c(3*SEG); for(size_t i=0;i<c.size();++i)c[i]=i&1; check(c,"alternance r=2"); }
    { // run à cheval EXACT sur une frontière de segment
      vector<int> c(2*SEG,0); for(int i=0;i<SEG-5;++i)c[i]=1; for(size_t i=SEG-5;i<c.size();++i)c[i]=0;
      check(c,"run a cheval sur frontiere SEG"); }
    { // run maximal centré sur une frontière
      vector<int> c(4*SEG,7); for(int i=0;i<50;++i)c[2*SEG-25+i]=3; check(c,"run 50 centre sur frontiere"); }
    for(long N: {1L,2L,(long)SEG-1,(long)SEG,(long)SEG+1,2L*SEG-1,2L*SEG,2L*SEG+1,5L*SEG+123}){   // N non multiple / degenere
      vector<int> c(N); for(long i=0;i<N;++i)c[i]=(int)(rng()%3); check(c,"N degenere"); }
    { // nseg GRAND non 2^k : ~7001 segments, runs sporadiques longs
      long N=7001L*SEG+17; vector<int> c(N); for(long i=0;i<N;++i)c[i]=(int)(rng()%2);
      // implante un run de 33 a une frontiere lointaine
      long b=5000L*SEG-16; for(int i=0;i<33;++i)c[b+i]=1; check(c,"nseg grand non-2^k + run implante"); }

    // 3) l'ordre est NÉCESSAIRE : un fold en ordre inverse des segments PEUT différer.
    //    (démontre pourquoi DeviceReduce (commutatif) était faux -> InclusiveScan.)
    { long N=6*SEG; vector<int> c(N); for(long i=0;i<N;++i)c[i]=(int)(rng()%2);
      for(int i=0;i<40;++i)c[SEG-20+i]=1;   // run a cheval
      // fold inverse (mauvais ordre)
      long nseg=(N+SEG-1)/SEG; vector<Summ> segs; for(long s=0;s<N;s+=SEG)segs.push_back(seg_summary(c,s,min(s+(long)SEG,N)));
      Summ acc; acc.len=0; for(long i=nseg-1;i>=0;--i)acc=merge(acc,segs[i]);   // ORDRE INVERSE
      int rev=acc.best, ok=ordered_reduce_best(c);
      printf("[info] ordre inverse best=%d vs ordonne=%d (l'ordre compte : %s)\n",
             rev,ok, rev!=ok? "DIFFERENT (attendu possible)":"identique ici"); }

    printf("\n== test_ordered_reduce : %d/%d OK ==\n", tot-fails, tot);
    return fails?1:0;
}
