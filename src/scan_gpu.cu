// ============================================================================
// src/scan_gpu.cu — T3 ÉTAGE 1 : pipeline GPU v1 (2e implémentation indépendante).
//
//   génération SEGMENTÉE (marche multiplicative g^i) -> ordre additif S2
//   (CUB SortPairs clé32=position, val16=i mod 2520) -> scan de runs multi-r
//   (maxrun via inclusive-scan segmenté custom) -> [confirmation CPU = oracle].
//
// Sémantique alignée sur q1_scan / rabung_criterion :
//   pour x in 1..p-1 : color_r(x) = ind(x) mod r = (i mod 2520) mod r  où x=g^i.
//   maxrun(p,r) = plus long run mono-couleur en ORDRE ADDITIF (positions 1..p-1).
//
// B7 (ADOPTÉ 2026-07-02, results/t3_b7.md) : éval de caractère fusionnée SANS tri
//   ni val16 — ordre additif gratuit (x=1..p-1), color via z=x^((p-1)/6) (r=2,3,
//   zéro table) ou table m-racines (multi-r). 5,56×10¹⁰ él/s @p~1,2×10⁹ (2× le tri).
//   ⇒ étage 2 annulé, plafond VRAM levé (X≤4,29×10⁹). Tri gardé = 2ᵉ impl. indép.
//
// Modes :
//   --validate <Pmax>       : différentiel 3 voies (tri, char B7, CPU), accord 100%.
//   --b6 <lo> <hi> <n>      : débit pipeline TRI (2ᵉ impl.).
//   --b7 <lo> <hi> <n>      : débit B7 multi-r (table).
//   --b7fast <lo> <hi> <n>  : débit B7 rapide r=2(+3) zéro-table (+ valide vs CPU).
//
// Domaine : p < 2^32 (Montgomery 32b). ASSERT dur. Compile sm_120 uniquement :
//   nvcc -O3 -gencode arch=compute_120,code=sm_120 \
//        -gencode arch=compute_120,code=compute_120 -o scan_gpu src/scan_gpu.cu
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cerrno>
#include <climits>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>
#include <utility>
#include <cuda_runtime.h>
#include <cub/cub.cuh>

#define CK(x) do{ cudaError_t e=(x); if(e!=cudaSuccess){ \
  fprintf(stderr,"CUDA err %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(e)); exit(1);} }while(0)

using u32=uint32_t; using u64=uint64_t; using u16=uint16_t;
static const int RMIN=2, RMAX=9;   // couleurs actives pour le scan multi-r (campagne r<=9)

// FNV-1a canonique sur des mots u64 encodes little-endian. Ce digest n'est pas
// une primitive cryptographique : il sert a engager sans ambiguite l'identite
// du claim et le profil scientifique dans la sortie machine de --verify1. Le
// manifeste externe SHA-256 engage ensuite les octets bruts de cette sortie.
static u64 fnv1a_u64_le(u64 h,u64 value){
    for(int i=0;i<8;++i){h^=(u32)(value&0xffu);h*=1099511628211ull;value>>=8;}
    return h;
}

// ---------------- Montgomery 32 bits (n impair < 2^32) ----------------------
// REDC avec conservation explicite de la retenue de l'addition 64 bits.
// La version source perd cette retenue lorsque n>2^31.
__host__ __device__ __forceinline__ u32 montmul(u32 a,u32 b,u32 n,u32 ninv){
    u64 t=(u64)a*b, mn=(u64)((u32)t*ninv)*n, s=t+mn;
    u32 u=(u32)(s>>32); bool carry=(s<t);
    return (carry || u>=n)?(u32)(u-n):u;
}
static u32 mont_ninv(u32 n){ u32 x=1; for(int i=0;i<5;i++) x*=(2u-n*x); return (u32)(0u-x); }
// R^2 mod n, R=2^32
static u32 mont_r2(u32 n){ u64 r=(1ull<<32)%n; return (u32)(( (unsigned __int128)r*r)%n); }
// Exponentiation LTR/MSB-first. Tous les exposants du domaine p<2^32 tiennent en u32.
__device__ __forceinline__ u32 mont_pow(u32 bm,u32 e,u32 n,u32 ninv,u32 one_m){
    if(!e) return one_m;
    int bit=31-__clz(e); u32 r=bm;
    for(--bit;bit>=0;--bit){ r=montmul(r,r,n,ninv); if((e>>bit)&1u) r=montmul(r,bm,n,ninv); }
    return r;
}
__host__ __device__ __forceinline__ u32 addmod32(u32 a,u32 b,u32 n){
    u32 s=a+b; return (s<a || s>=n)?(u32)(s-n):s;
}

// ---------------- CPU helpers (référence + racine primitive) ----------------
static u32 h_mulmod(u32 a,u32 b,u32 m){ return (u32)(((u64)a*b)%m); }
static u32 h_powmod(u32 b,u64 e,u32 m){ u32 r=1; b%=m; while(e){ if(e&1)r=h_mulmod(r,b,m); b=h_mulmod(b,b,m); e>>=1;} return r; }
static std::vector<u32> h_factors(u32 n){ std::vector<u32> f; for(u32 p=2;(u64)p*p<=n;++p) if(n%p==0){ f.push_back(p); while(n%p==0)n/=p; } if(n>1)f.push_back(n); return f; }
static u32 primitive_root(u32 p){ if(p==2)return 1; auto f=h_factors(p-1); for(u32 g=2;g<p;++g){ bool ok=true; for(u32 q:f) if(h_powmod(g,(p-1)/q,p)==1){ok=false;break;} if(ok)return g; } return 0; }
static u32 h_gcd(u32 a,u32 b){ while(b){u32 t=a%b;a=b;b=t;} return a; }
static u32 h_lcm(u32 a,u32 b){ return a/h_gcd(a,b)*b; }
// Jacobi binaire (indépendant : réciprocité, pas de log discret) ; =Legendre si p premier.
static int h_jacobi(u64 a,u64 n){ a%=n; if(!a)return 0; int s=1;
    while(a){ while(!(a&1)){a>>=1;u64 r=n&7;if(r==3||r==5)s=-s;} u64 t=a;a=n;n=t; if((a&3)==3&&(n&3)==3)s=-s; a%=n; } return (n==1)?s:0; }
// maxrun r=2 via Jacobi (col(x)=[x non-résidu]) sur [1,p-1] — CPU O(p log p), indépendant.
static int cpu_maxrun_jacobi_r2(u64 p){ int run=0,best=0,prev=-1;
    for(u64 x=1;x<p;++x){ int c=(h_jacobi(x,p)==-1)?1:0; if(c==prev)run++; else{prev=c;run=1;} if(run>best)best=run; } return best; }

// ---------------- Génération segmentée : (key=x=g^i, val16=i%2520) ----------
// T threads ; thread t couvre [t*L, (t+1)*L) : seed = g^(t*L), puis marche x*=g.
__global__ void k_generate(u32 p,u32 g_mont,u32 ninv,u32 one_m,u64 L,u32 T,
                           u32* __restrict__ keys,u16* __restrict__ vals){
    u64 t=blockIdx.x*(u64)blockDim.x+threadIdx.x; if(t>=T) return;
    u64 i0=t*L; if(i0>=p-1) return;
    u32 x=mont_pow(g_mont,(u32)i0,p,ninv,one_m); // i0<p<2^32
    u64 iend=i0+L; if(iend>p-1) iend=p-1;
    for(u64 i=i0;i<iend;++i){
        // sortir de Montgomery : montmul(x,1) = x*R^{-1} = valeur réelle
        u32 xr=montmul(x,1u,p,ninv);            // position réelle dans 1..p-1
        keys[i]=xr; vals[i]=(u16)(i%2520u);
        x=montmul(x,g_mont,p,ninv);
    }
}

// ---------------- maxrun FUSIONNÉ single-pass (B5-style) --------------------
// Chaque thread résume un SEGMENT de SEG éléments contigus (val16 lu UNE fois,
// couleurs r=RMIN..RMAX (actuellement 2..9) dérivées en registres) : {len, whole, color, prefLen/Col,
// sufLen/Col, best}. Puis réduction associative (monoïde « plus long run »)
// par r -> maxrun[r]. Lecture mémoire = n×2 o une seule fois.
static const int SEG=1024;
static const int NR=RMAX-RMIN+1;   // actuellement r=2..9
struct Summ{ int pL,sL,best; u32 meta; }; // 16 o: pC[3:0],sC[7:4],whole[8]
static_assert(sizeof(Summ)==16,"Summ doit rester a 16 octets");
struct SummOp{ __device__ __host__ __forceinline__ Summ operator()(const Summ&A,const Summ&B)const{
    if(A.pL==0) return B; if(B.pL==0) return A;
    const int ap=A.meta&15,as=(A.meta>>4)&15,aw=(A.meta>>8)&1;
    const int bp=B.meta&15,bs=(B.meta>>4)&15,bw=(B.meta>>8)&1;
    Summ r; int cross=(as==bp)?(A.sL+B.pL):0;
    r.best=A.best; if(B.best>r.best)r.best=B.best; if(cross>r.best)r.best=cross;
    int rw=(aw&&bw&&ap==bp)?1:0;
    r.pL=aw?((ap==bp)?A.pL+B.pL:A.pL):A.pL;
    r.sL=bw?((bs==as)?B.sL+A.sL:B.sL):B.sL;
    r.meta=(u32)ap|((u32)bs<<4)|((u32)rw<<8);
    return r; } };
// résumé par segment, pour les NR valeurs de r, en une passe. out[r*nseg + seg].
__global__ void k_scan_fused(const u16* __restrict__ v,long n,long nseg,Summ* __restrict__ out){
    long seg=blockIdx.x*(long)blockDim.x+threadIdx.x; if(seg>=nseg) return;
    long s=seg*SEG, e=s+SEG; if(e>n)e=n; if(s>=n){ for(int t=0;t<NR;t++){ Summ z{}; out[(long)t*nseg+seg]=z; } return; }
    int prevc[NR],runlen[NR],best[NR],pL[NR],pC[NR]; bool pdone[NR];
    { u16 v0=v[s]; for(int t=0;t<NR;t++){ int r=RMIN+t; int c=v0%r; prevc[t]=c;runlen[t]=1;best[t]=1;pL[t]=1;pC[t]=c;pdone[t]=false; } }
    for(long j=s+1;j<e;++j){ u16 vj=v[j];
        #pragma unroll
        for(int t=0;t<NR;t++){ int r=RMIN+t; int c=vj%r;
            if(c==prevc[t]){ runlen[t]++; if(!pdone[t])pL[t]++; }
            else { prevc[t]=c; runlen[t]=1; pdone[t]=true; }
            if(runlen[t]>best[t])best[t]=runlen[t]; } }
    long len=e-s;
    for(int t=0;t<NR;t++){ Summ z; z.pL=pL[t]; z.sL=runlen[t]; z.best=best[t];
        z.meta=(u32)(pC[t]&15)|((u32)(prevc[t]&15)<<4)|((u32)(pL[t]==(int)len)<<8);
        out[(long)t*nseg+seg]=z; }
}

// ============================ pipeline pour un premier =======================
static const int MMAX=2560;    // m = lcm{r|p-1, r<=9} <= 2520
struct Buffers{
    u32 *keys,*keys_out; u16 *vals,*vals_out;
    Summ* summ;            // NR * nseg_max
    Summ* d_sout;          // NR (résultat réduit par r)
    Summ* h_sout;          // pinned host
    u32 *d_sval,*d_sj;     // B7 : table des m racines (valeurs triées + indice j)
    u16 *d_val16;          // V2b : val16[x-1]=ind(x) mod m matérialisé (x=1..(p-1)/2)
    long nseg_max;
    void* cub_sort; size_t cub_sort_bytes;
    void* cub_scan; size_t cub_scan_bytes;   // InclusiveScan ORDONNÉ (SummOp non commutatif)
    long cap;
};
// gather du DERNIER élément (= réduction ORDONNÉE) de chaque bloc-r après scan inclusif.
__global__ void k_lastgather(const Summ* __restrict__ s,long nseg,int nr,Summ* __restrict__ out){
    int t=blockIdx.x*blockDim.x+threadIdx.x; if(t<nr) out[t]=s[(long)t*nseg+nseg-1];
}
// réduction ORDONNÉE par r (SummOp associatif NON commutatif -> scan, pas reduce).
static void ordered_reduce(Buffers& b,long nseg){
    SummOp op;
    for(int t=0;t<NR;t++)
        cub::DeviceScan::InclusiveScan(b.cub_scan,b.cub_scan_bytes,b.summ+(long)t*nseg,b.summ+(long)t*nseg,op,nseg);
    k_lastgather<<<1,NR>>>(b.summ,nseg,NR,b.d_sout);
}
static void alloc_buffers(Buffers& b,long cap){
    b.cap=cap; b.nseg_max=(cap+SEG-1)/SEG+1;
    CK(cudaMalloc(&b.keys,cap*4)); CK(cudaMalloc(&b.keys_out,cap*4));
    CK(cudaMalloc(&b.vals,cap*2)); CK(cudaMalloc(&b.vals_out,cap*2));
    CK(cudaMalloc(&b.summ,(size_t)NR*b.nseg_max*sizeof(Summ)));
    CK(cudaMalloc(&b.d_sout,NR*sizeof(Summ)));
    CK(cudaHostAlloc(&b.h_sout,NR*sizeof(Summ),cudaHostAllocDefault));
    CK(cudaMalloc(&b.d_sval,MMAX*4)); CK(cudaMalloc(&b.d_sj,MMAX*4));
    CK(cudaMalloc(&b.d_val16,(size_t)(cap/2+64)*2));
    b.cub_sort=nullptr;b.cub_sort_bytes=0;
    cub::DeviceRadixSort::SortPairs(b.cub_sort,b.cub_sort_bytes,b.keys,b.keys_out,b.vals,b.vals_out,cap);
    CK(cudaMalloc(&b.cub_sort,b.cub_sort_bytes));
    b.cub_scan=nullptr;b.cub_scan_bytes=0;{SummOp op;cub::DeviceScan::InclusiveScan(b.cub_scan,b.cub_scan_bytes,b.summ,b.summ,op,b.nseg_max);}CK(cudaMalloc(&b.cub_scan,b.cub_scan_bytes));
}
// alloc MINIMALE pour B7 (pas de buffers de tri : ni keys/vals ni cub_sort)
static void alloc_buffers_b7(Buffers& b,long cap){
    b.cap=cap; b.nseg_max=(cap+SEG-1)/SEG+1;
    b.keys=b.keys_out=nullptr; b.vals=b.vals_out=nullptr; b.cub_sort=nullptr; b.cub_sort_bytes=0;
    CK(cudaMalloc(&b.summ,(size_t)NR*b.nseg_max*sizeof(Summ)));
    CK(cudaMalloc(&b.d_sout,NR*sizeof(Summ)));
    CK(cudaHostAlloc(&b.h_sout,NR*sizeof(Summ),cudaHostAllocDefault));
    CK(cudaMalloc(&b.d_sval,MMAX*4)); CK(cudaMalloc(&b.d_sj,MMAX*4));
    CK(cudaMalloc(&b.d_val16,(size_t)(cap/2+64)*2));   // V2b : val16 demi-intervalle
    b.cub_scan=nullptr;b.cub_scan_bytes=0;{SummOp op;cub::DeviceScan::InclusiveScan(b.cub_scan,b.cub_scan_bytes,b.summ,b.summ,op,b.nseg_max);}CK(cudaMalloc(&b.cub_scan,b.cub_scan_bytes));
}
// calcule maxrun[r] pour RMIN..RMAX pour un premier p ; renvoie via out[] (indices r)
static void process_prime(Buffers& b,u32 p,u32 g,int* out_maxrun){
    long n=p-1;
    // --- génération segmentée ---
    u32 ninv=mont_ninv(p), r2=mont_r2(p), one_m=(u32)((1ull<<32)%p);
    u32 g_mont=montmul(g,r2,p,ninv);
    u32 T=1u<<16; if((u64)T> (u64)n) T=(u32)n; u64 L=(n+T-1)/T;
    int th=256; long bl=(T+th-1)/th;
    k_generate<<<bl,th>>>(p,g_mont,ninv,one_m,L,T,b.keys,b.vals);
    // --- ordre additif (S2) : trie par clé=position ---
    cub::DeviceRadixSort::SortPairs(b.cub_sort,b.cub_sort_bytes,b.keys,b.keys_out,b.vals,b.vals_out,n);
    // --- scan maxrun fusionné (une passe val16, NR couleurs) ---
    long nseg=(n+SEG-1)/SEG;
    long bl2=(nseg+th-1)/th;
    k_scan_fused<<<bl2,th>>>(b.vals_out,n,nseg,b.summ);
    ordered_reduce(b,nseg);
    CK(cudaMemcpy(b.h_sout,b.d_sout,NR*sizeof(Summ),cudaMemcpyDeviceToHost));
    for(int t=0;t<NR;t++) out_maxrun[RMIN+t]=b.h_sout[t].best;
}

// ---------------- référence CPU : maxrun par r (indépendante) ----------------
static void cpu_maxrun(u32 p,u32 g,int* out,std::vector<u16>* keep_val=nullptr){
    // color(x)=ind(x)%r ; on parcourt x=1..p-1 en ordre ADDITIF via table ind.
    std::vector<u16> val(p); // val[x] = i%2520 tel que g^i=x
    u32 x=1; for(u64 i=0;i<p-1;++i){ val[x]=(u16)(i%2520u); x=h_mulmod(x,g,p); }
    for(int r=RMIN;r<=RMAX;++r){
        int best=0,run=0,prev=-1;
        for(u32 y=1;y<p;++y){ int c=val[y]%r; if(c==prev)run++; else {run=1;prev=c;} if(run>best)best=run; }
        out[r]=best;
    }
    if(keep_val)*keep_val=std::move(val);
}

// Condition de bord Rabung B*: chacune des k fenêtres centrées sur le joker 0
// doit contenir au moins deux classes parmi ses k-1 positions non nulles.
static bool boundary_ok_pow(u32 p,u32 g,int r,int k){
    assert(p>(u32)k&&(p-1)%(u32)r==0);
    u32 zeta=h_powmod(g,(p-1)/r,p);std::vector<u32>root(r);root[0]=1;
    for(int j=1;j<r;j++)root[j]=h_mulmod(root[j-1],zeta,p);
    auto col=[&](int t){u32 x=t<0?p-(u32)(-t):(u32)t;u32 y=h_powmod(x,(p-1)/r,p);
        for(int j=0;j<r;j++)if(root[j]==y)return j;return -1;};
    for(int j=0;j<k;j++){int first=-1;bool same=true;
        for(int t=-j;t<=k-1-j;t++)if(t){int c=col(t);if(first<0)first=c;else if(c!=first){same=false;break;}}
        if(same)return false;
    }
    return true;
}
static bool boundary_ok_walk(u32 p,int r,int k,const std::vector<u16>&val){
    for(int j=0;j<k;j++){int first=-1;bool same=true;
        for(int t=-j;t<=k-1-j;t++)if(t){u32 x=t<0?p-(u32)(-t):(u32)t;int c=val[x]%r;
            if(first<0)first=c;else if(c!=first){same=false;break;}}
        if(same)return false;
    }
    return true;
}

// =================== B7 : éval de caractère fusionnée (SANS tri) =============
// Ordre additif GRATUIT (x = 1,2,...,p-1 en clair). Pour chaque x :
//   y = x^((p-1)/m) mod p (Montgomery)  ->  y = g^{ind(x)·(p-1)/m}, une des m
//   racines m-ièmes de l'unité ; recherche binaire (table de m entrées en shared)
//   -> j = ind(x) mod m ; color_r = j mod r (exact car r|m|p-1).
// AUCUNE matérialisation de val16, AUCUN tri. Fusionné au résumé de runs multi-r.
__global__ void k_scan_char(u32 p,u32 ninv,u32 R2,u32 one_m,u64 e,int m,
        const u32* __restrict__ gval,const u32* __restrict__ gj,
        long n,long nseg,Summ* __restrict__ out){
    extern __shared__ u32 smem[]; u32* sval=smem; u32* sj=smem+m;
    for(int i=threadIdx.x;i<m;i+=blockDim.x){ sval[i]=gval[i]; sj[i]=gj[i]; }
    __syncthreads();
    long seg=blockIdx.x*(long)blockDim.x+threadIdx.x; if(seg>=nseg) return;
    long s=seg*SEG, en=s+SEG; if(en>n)en=n;
    if(s>=n){ for(int t=0;t<NR;t++){Summ z{};out[(long)t*nseg+seg]=z;} return; }
    int prevc[NR],runlen[NR],best[NR],pL[NR],pC[NR]; bool pdone[NR];
    for(long jpos=s;jpos<en;++jpos){
        u32 x=(u32)(jpos+1);                       // position j -> entier j+1
        u32 xm=montmul(x,R2,p,ninv);
        u32 ym=mont_pow(xm,e,p,ninv,one_m);
        u32 y=montmul(ym,1u,p,ninv);
        int lo=0,hi=m-1,idx=0; while(lo<=hi){int mid=(lo+hi)>>1;u32 v=sval[mid];
            if(v==y){idx=mid;break;} if(v<y)lo=mid+1; else hi=mid-1; }
        int jj=sj[idx];
        if(jpos==s){ for(int t=0;t<NR;t++){int r=RMIN+t;int c=jj%r;prevc[t]=c;runlen[t]=1;best[t]=1;pL[t]=1;pC[t]=c;pdone[t]=false;} }
        else{
            #pragma unroll
            for(int t=0;t<NR;t++){int r=RMIN+t;int c=jj%r;
                if(c==prevc[t]){runlen[t]++;if(!pdone[t])pL[t]++;}
                else{prevc[t]=c;runlen[t]=1;pdone[t]=true;}
                if(runlen[t]>best[t])best[t]=runlen[t];} }
    }
    long len=en-s;
    for(int t=0;t<NR;t++){Summ z;z.pL=pL[t];z.sL=runlen[t];z.best=best[t];
        z.meta=(u32)(pC[t]&15)|((u32)(prevc[t]&15)<<4)|((u32)(pL[t]==(int)len)<<8);
        out[(long)t*nseg+seg]=z;}
}

// --- best_templ_u32 : V2a spécialisé pour les 36 masques réalisables --------
template<int T> __device__ __forceinline__ void best_init_one(int jj,int*p,int*r,int*b,int*l,int*c,bool*d){
    constexpr int mod=RMIN+T; int x=jj%mod; p[T]=x;r[T]=b[T]=l[T]=1;c[T]=x;d[T]=false;
}
template<int T> __device__ __forceinline__ void best_update_one(int jj,int*p,int*r,int*b,int*l,bool*d){
    constexpr int mod=RMIN+T; int x=jj%mod;
    if(x==p[T]){r[T]++;if(!d[T])l[T]++;}else{p[T]=x;r[T]=1;d[T]=true;}if(r[T]>b[T])b[T]=r[T];
}
template<int MASK> __device__ __forceinline__ void best_init_mask(int jj,int*p,int*r,int*b,int*l,int*c,bool*d){
    if constexpr(MASK&0x01)best_init_one<0>(jj,p,r,b,l,c,d);if constexpr(MASK&0x02)best_init_one<1>(jj,p,r,b,l,c,d);
    if constexpr(MASK&0x04)best_init_one<2>(jj,p,r,b,l,c,d);if constexpr(MASK&0x08)best_init_one<3>(jj,p,r,b,l,c,d);
    if constexpr(MASK&0x10)best_init_one<4>(jj,p,r,b,l,c,d);if constexpr(MASK&0x20)best_init_one<5>(jj,p,r,b,l,c,d);
    if constexpr(MASK&0x40)best_init_one<6>(jj,p,r,b,l,c,d);if constexpr(MASK&0x80)best_init_one<7>(jj,p,r,b,l,c,d);
}
template<int MASK> __device__ __forceinline__ void best_update_mask(int jj,int*p,int*r,int*b,int*l,bool*d){
    if constexpr(MASK&0x01)best_update_one<0>(jj,p,r,b,l,d);if constexpr(MASK&0x02)best_update_one<1>(jj,p,r,b,l,d);
    if constexpr(MASK&0x04)best_update_one<2>(jj,p,r,b,l,d);if constexpr(MASK&0x08)best_update_one<3>(jj,p,r,b,l,d);
    if constexpr(MASK&0x10)best_update_one<4>(jj,p,r,b,l,d);if constexpr(MASK&0x20)best_update_one<5>(jj,p,r,b,l,d);
    if constexpr(MASK&0x40)best_update_one<6>(jj,p,r,b,l,d);if constexpr(MASK&0x80)best_update_one<7>(jj,p,r,b,l,d);
}
template<int MASK> __global__ void k_scan_char_best(u32 p,u32 ninv,u32 R2,u32 one_m,u32 e,int m,
        const u32* __restrict__ gval,const u32* __restrict__ gj,u32 n,u32 nseg,Summ* __restrict__ out){
    extern __shared__ u32 smem[];u32*sval=smem,*sj=smem+m;
    for(int i=threadIdx.x;i<m;i+=blockDim.x){sval[i]=gval[i];sj[i]=gj[i];}__syncthreads();
    u32 seg=blockIdx.x*(u32)blockDim.x+threadIdx.x;if(seg>=nseg)return;
    u32 s=seg*(u32)SEG,en=s+(u32)SEG;if(en>n)en=n;
    int prev[NR],run[NR],best[NR],pl[NR],pc[NR];bool done[NR];
    u32 xm=montmul(s+1u,R2,p,ninv);bool first=true;
    for(u32 pos=s;pos<en;++pos){
        u32 y=mont_pow(xm,e,p,ninv,one_m); // y reste en Montgomery
        int lo=0,hi=m-1,idx=0;while(lo<=hi){int mid=(lo+hi)>>1;u32 v=sval[mid];
            if(v==y){idx=mid;break;}if(v<y)lo=mid+1;else hi=mid-1;}int jj=sj[idx];
        if(first){best_init_mask<MASK>(jj,prev,run,best,pl,pc,done);first=false;}
        else best_update_mask<MASK>(jj,prev,run,best,pl,done);
        xm=addmod32(xm,one_m,p);
    }
    int len=(int)(en-s);
    #pragma unroll
    for(int t=0;t<NR;t++){Summ z{};switch(t){
        case 0:if constexpr(MASK&0x01){z.pL=pl[0];z.sL=run[0];z.best=best[0];z.meta=(u32)pc[0]|((u32)prev[0]<<4)|((u32)(pl[0]==len)<<8);}break;
        case 1:if constexpr(MASK&0x02){z.pL=pl[1];z.sL=run[1];z.best=best[1];z.meta=(u32)pc[1]|((u32)prev[1]<<4)|((u32)(pl[1]==len)<<8);}break;
        case 2:if constexpr(MASK&0x04){z.pL=pl[2];z.sL=run[2];z.best=best[2];z.meta=(u32)pc[2]|((u32)prev[2]<<4)|((u32)(pl[2]==len)<<8);}break;
        case 3:if constexpr(MASK&0x08){z.pL=pl[3];z.sL=run[3];z.best=best[3];z.meta=(u32)pc[3]|((u32)prev[3]<<4)|((u32)(pl[3]==len)<<8);}break;
        case 4:if constexpr(MASK&0x10){z.pL=pl[4];z.sL=run[4];z.best=best[4];z.meta=(u32)pc[4]|((u32)prev[4]<<4)|((u32)(pl[4]==len)<<8);}break;
        case 5:if constexpr(MASK&0x20){z.pL=pl[5];z.sL=run[5];z.best=best[5];z.meta=(u32)pc[5]|((u32)prev[5]<<4)|((u32)(pl[5]==len)<<8);}break;
        case 6:if constexpr(MASK&0x40){z.pL=pl[6];z.sL=run[6];z.best=best[6];z.meta=(u32)pc[6]|((u32)prev[6]<<4)|((u32)(pl[6]==len)<<8);}break;
        case 7:if constexpr(MASK&0x80){z.pL=pl[7];z.sL=run[7];z.best=best[7];z.meta=(u32)pc[7]|((u32)prev[7]<<4)|((u32)(pl[7]==len)<<8);}break;}
        out[(u32)t*nseg+seg]=z;
    }
}
#define BEST_MASK_CASES(X) X(0x01) X(0x05) X(0x09) X(0x0d) X(0x13) X(0x17) X(0x1b) X(0x1f) X(0x21) X(0x25) X(0x29) X(0x2d) X(0x33) X(0x37) X(0x3b) X(0x3f) X(0x45) X(0x4d) X(0x57) X(0x5f) X(0x65) X(0x6d) X(0x77) X(0x7f) X(0x93) X(0x97) X(0x9b) X(0x9f) X(0xb3) X(0xb7) X(0xbb) X(0xbf) X(0xd7) X(0xdf) X(0xf7) X(0xff)
static void launch_best(u32 mask,u32 p,u32 ninv,u32 R2,u32 one,u32 e,int m,const u32*dv,const u32*dj,u32 n,u32 nseg,Summ*out){
    dim3 grid((nseg+127u)/128u),block(128);size_t sh=2*(size_t)m*4;
    switch(mask){
#define BEST_LAUNCH(x) case x:k_scan_char_best<x><<<grid,block,sh>>>(p,ninv,R2,one,e,m,dv,dj,n,nseg,out);break;
        BEST_MASK_CASES(BEST_LAUNCH)
#undef BEST_LAUNCH
        default:fprintf(stderr,"masque actif impossible: 0x%02x\n",mask);exit(3);
    }
}
static void ordered_reduce_active(Buffers&b,u32 nseg,u32 mask){SummOp op;
    for(int t=0;t<NR;t++)if(mask&(1u<<t))cub::DeviceScan::InclusiveScan(b.cub_scan,b.cub_scan_bytes,b.summ+(size_t)t*nseg,b.summ+(size_t)t*nseg,op,(int)nseg);
    k_lastgather<<<1,NR>>>(b.summ,nseg,NR,b.d_sout);
}
// =================== V2a : scan DEMI-intervalle miroir (×~1,9) ===============
// La coloration est miroir : col(p-x)=col(x)+col(-1) mod r, col(-1)=((p-1)/2) mod r.
// La 2e moitie = reverse(1re moitie) + col(-1) -> memes longueurs de run.
// On ne scanne que x=1..(p-1)/2 (moitie des mulmods). Recollement central :
//   shift_r = ((p-1)/2) mod r ; palindrome (shift_r==0) -> run central = 2*suffixe(FH) ;
//   sinon (anti) -> frontiere, maxrun_full = maxrun(FH). Zero nouvelle memoire.
// mulmods/element derives de e (parcours LTR : bits+popcount-2 multiplications) — deterministe.
static void process_prime_char_v2a(Buffers& b,u32 p,u32 g,int* out_maxrun,int* active,double* mm_per_elem){
    const u32 nh=(p-1)/2; u32 m=1,mask=0;
    for(int r=RMIN;r<=RMAX;++r){active[r]=((p-1)%r==0);if(active[r]){mask|=1u<<(r-RMIN);m=h_lcm(m,(u32)r);}}
    assert((int)m<=MMAX&&(p-1)%m==0);
    const u32 e=(p-1)/m,nseg=(nh+SEG-1)/SEG;
    assert(nh<=0x7fffffffu&&nseg<=2097152u&&NR*nseg<=16777216u&&nseg<=(u32)b.nseg_max);
    const u32 ninv=mont_ninv(p),R2=mont_r2(p),one_m=(u32)((1ull<<32)%p);
    // Les racines et la clé de recherche restent en Montgomery. Le tri doit être
    // refait après conversion car x -> xR mod p ne préserve pas l'ordre normal.
    u32 base=h_powmod(g,e,p),cur=1;std::vector<std::pair<u32,u32>> tab(m);
    for(u32 j=0;j<m;j++){tab[j]={montmul(cur,R2,p,ninv),j};cur=h_mulmod(cur,base,p);}
    std::sort(tab.begin(),tab.end());std::vector<u32>sval(m),sj(m);
    for(u32 j=0;j<m;j++){sval[j]=tab[j].first;sj[j]=tab[j].second;}
    CK(cudaMemcpy(b.d_sval,sval.data(),m*4,cudaMemcpyHostToDevice));
    CK(cudaMemcpy(b.d_sj,sj.data(),m*4,cudaMemcpyHostToDevice));
    launch_best(mask,p,ninv,R2,one_m,e,(int)m,b.d_sval,b.d_sj,nh,nseg,b.summ);
    ordered_reduce_active(b,nseg,mask);
    CK(cudaMemcpy(b.h_sout,b.d_sout,NR*sizeof(Summ),cudaMemcpyDeviceToHost));
    for(int t=0;t<NR;t++)if(mask&(1u<<t)){int r=RMIN+t,shift=(int)(nh%(u32)r);
        int fhb=b.h_sout[t].best,fhs=b.h_sout[t].sL;
        out_maxrun[r]=(shift==0&&2*fhs>fhb)?2*fhs:fhb;}
    if(mm_per_elem){int bits=0,pc=0;for(u32 ee=e;ee;ee>>=1){bits++;pc+=ee&1u;}*mm_per_elem=bits+pc-2;}
}

// =================== V2b : parité 2-adique (×~2 sur V2a) =====================
// Passe A : modpow SEULEMENT pour u IMPAIR <=(p-1)/2 -> val16[u-1]=ind(u) mod m.
// Passe B : niveaux 2-adiques j(2^a·u)=j(u)+a·j(2) (chaque impair remplit sa chaîne,
//   kernels indép, aucune course). Passe C : k_scan_fused sur val16 (réutilisé).
// -> modpows = (p-1)/4 (moitié de V2a). j2=ind(2) mod m (1 char-eval, hôte).
__global__ void k_v2b_odd(u32 p,u32 ninv,u32 R2,u32 one_m,u64 e,int m,
        const u32* __restrict__ sval,const u32* __restrict__ sj,long nh,u16* __restrict__ val16){
    long tid=blockIdx.x*(long)blockDim.x+threadIdx.x; u32 u=(u32)(2*tid+1); if(u>nh) return;
    u32 xm=montmul(u,R2,p,ninv); u32 ym=mont_pow(xm,e,p,ninv,one_m); u32 y=montmul(ym,1u,p,ninv);
    int lo=0,hi=m-1,idx=0; while(lo<=hi){int mid=(lo+hi)>>1;u32 v=sval[mid];
        if(v==y){idx=mid;break;} if(v<y)lo=mid+1; else hi=mid-1;}
    val16[u-1]=(u16)sj[idx];
}
__global__ void k_v2b_even(long nh,int m,u32 j2,u16* __restrict__ val16){
    long tid=blockIdx.x*(long)blockDim.x+threadIdx.x; u32 u=(u32)(2*tid+1); if(u>nh) return;
    int ju=val16[u-1]; int a=1;
    for(u64 x=2ull*u; x<=(u64)nh; x<<=1, ++a) val16[x-1]=(u16)((ju + (long)a*j2)%m);
}
static void process_prime_char_v2b(Buffers& b,u32 p,u32 g,int* out_maxrun,int* active,double* mm_per_elem){
    long nh=(p-1)/2;
    u32 m=1; for(int r=RMIN;r<=RMAX;++r){ active[r]=((p-1)%r==0)?1:0; if(active[r]) m=h_lcm(m,(u32)r); }
    assert((int)m<=MMAX && (p-1)%m==0);
    u32 e=(u32)((p-1)/m);
    u32 base=h_powmod(g,(p-1)/m,p);
    std::vector<std::pair<u32,u32>> tab(m); u32 cur=1;
    for(u32 j=0;j<m;j++){ tab[j]={cur,j}; cur=h_mulmod(cur,base,p);} std::sort(tab.begin(),tab.end());
    std::vector<u32> sval(m),sj(m); for(u32 j=0;j<m;j++){ sval[j]=tab[j].first; sj[j]=tab[j].second; }
    // j2 = ind(2) mod m : y2 = 2^((p-1)/m), recherche dans la table triée
    u32 y2=h_powmod(2u,(p-1)/m,p), j2=0;
    { int lo=0,hi=(int)m-1; while(lo<=hi){int mid=(lo+hi)>>1; if(sval[mid]==y2){j2=sj[mid];break;} if(sval[mid]<y2)lo=mid+1; else hi=mid-1;} }
    CK(cudaMemcpy(b.d_sval,sval.data(),m*4,cudaMemcpyHostToDevice));
    CK(cudaMemcpy(b.d_sj,sj.data(),m*4,cudaMemcpyHostToDevice));
    u32 ninv=mont_ninv(p),R2=mont_r2(p),one_m=(u32)((1ull<<32)%p);
    int th=128; long nodd=(nh+1)/2, bo=(nodd+th-1)/th;
    k_v2b_odd<<<bo,th>>>(p,ninv,R2,one_m,(u64)e,(int)m,b.d_sval,b.d_sj,nh,b.d_val16);   // passe A
    k_v2b_even<<<bo,th>>>(nh,(int)m,j2,b.d_val16);                                        // passe B
    long nseg=(nh+SEG-1)/SEG, bs=(nseg+th-1)/th;                                          // passe C
    k_scan_fused<<<bs,th>>>(b.d_val16,nh,nseg,b.summ);
    ordered_reduce(b,nseg);   // réduction ORDONNÉE (scan) — SummOp non commutatif
    CK(cudaMemcpy(b.h_sout,b.d_sout,NR*sizeof(Summ),cudaMemcpyDeviceToHost));
    for(int t=0;t<NR;t++){ int r=RMIN+t; int shift=(int)(((u64)(p-1)/2)%r);
        int fhb=b.h_sout[t].best, fhs=b.h_sout[t].sL;
        out_maxrun[r] = (shift==0) ? (fhb>2*fhs?fhb:2*fhs) : fhb; }
    if(mm_per_elem){ int bits=0,pc=0; u32 ee=e; while(ee){bits++;pc+=(ee&1);ee>>=1;} *mm_per_elem=bits+pc+2; } // par impair traité
}

// --- B7 rapide r=2(+3), ZÉRO table (directive) : z=x^((p-1)/6) si 6|p-1 ---
// z³=x^((p-1)/2)→classe quad (col2) ; z²=x^((p-1)/3)→classe cubique (col3 via ζ).
// 2 états de run en registres → occupancy élevée. do3=0 ⇒ r=2 seul, e=(p-1)/2.
static const int NRF=2;
__global__ void k_scan_char23(u32 p,u32 ninv,u32 R2,u32 one_m,u64 e,int do3,
        u32 zeta_m,u32 zeta2_m,long n,long nseg,Summ* __restrict__ out){
    long seg=blockIdx.x*(long)blockDim.x+threadIdx.x; if(seg>=nseg) return;
    long s=seg*SEG, en=s+SEG; if(en>n)en=n;
    if(s>=n){ for(int t=0;t<NRF;t++){Summ z{};out[(long)t*nseg+seg]=z;} return; }
    int prevc[NRF],runlen[NRF],best[NRF],pL[NRF],pC[NRF]; bool pdone[NRF];
    for(long jpos=s;jpos<en;++jpos){
        u32 x=(u32)(jpos+1);
        u32 xm=montmul(x,R2,p,ninv);
        u32 z=mont_pow(xm,e,p,ninv,one_m);
        u32 z3= do3 ? montmul(montmul(z,z,p,ninv),z,p,ninv) : z;   // x^((p-1)/2)
        int c0=(z3==one_m)?0:1;                                    // col2
        int c1=0; if(do3){ u32 z2=montmul(z,z,p,ninv); c1=(z2==one_m)?0:((z2==zeta_m)?1:2); }
        int col[NRF]={c0,c1};
        if(jpos==s){ for(int t=0;t<NRF;t++){prevc[t]=col[t];runlen[t]=1;best[t]=1;pL[t]=1;pC[t]=col[t];pdone[t]=false;} }
        else{ for(int t=0;t<NRF;t++){ int c=col[t];
            if(c==prevc[t]){runlen[t]++;if(!pdone[t])pL[t]++;}
            else{prevc[t]=c;runlen[t]=1;pdone[t]=true;}
            if(runlen[t]>best[t])best[t]=runlen[t]; } }
    }
    long len=en-s;
    for(int t=0;t<NRF;t++){Summ z;z.pL=pL[t];z.sL=runlen[t];z.best=best[t];
        z.meta=(u32)(pC[t]&15)|((u32)(prevc[t]&15)<<4)|((u32)(pL[t]==(int)len)<<8);
        out[(long)t*nseg+seg]=z;}
}
// renvoie maxrun r=2 (out[2]) et r=3 (out[3] si 6|p-1). do3 renseigné.
static void process_prime_char23(Buffers& b,u32 p,u32 g,int* out_maxrun,int* do3out){
    long n=p-1; int do3=((p-1)%3==0)?1:0; *do3out=do3;
    u64 e = do3 ? (p-1)/6 : (p-1)/2;
    u32 ninv=mont_ninv(p),R2=mont_r2(p),one_m=(u32)((1ull<<32)%p);
    u32 zeta_m=0,zeta2_m=0;
    if(do3){ u32 zt=h_powmod(g,(p-1)/3,p); u32 zt2=h_mulmod(zt,zt,p);
             zeta_m=montmul(zt,R2,p,ninv); zeta2_m=montmul(zt2,R2,p,ninv); }
    long nseg=(n+SEG-1)/SEG; int th=256; long bl=(nseg+th-1)/th;
    k_scan_char23<<<bl,th>>>(p,ninv,R2,one_m,e,do3,zeta_m,zeta2_m,n,nseg,b.summ);
    int nrf=do3?2:1;
    ordered_reduce_active(b,(u32)nseg,(1u<<nrf)-1u);
    CK(cudaMemcpy(b.h_sout,b.d_sout,nrf*sizeof(Summ),cudaMemcpyDeviceToHost));
    out_maxrun[2]=b.h_sout[0].best; if(do3) out_maxrun[3]=b.h_sout[1].best;
}
// active[r]=1 si r|(p-1). Renvoie maxrun[r] pour r actifs (ordre additif, coloring).
static void process_prime_char(Buffers& b,u32 p,u32 g,int* out_maxrun,int* active){
    long n=p-1;
    u32 m=1; for(int r=RMIN;r<=RMAX;++r){ active[r]=((p-1)%r==0)?1:0; if(active[r]) m=h_lcm(m,(u32)r); }
    assert((int)m<=MMAX && (p-1)%m==0);
    u32 e=(u32)((p-1)/m);
    u32 base=h_powmod(g,(p-1)/m,p);
    std::vector<std::pair<u32,u32>> tab(m);
    u32 cur=1; for(u32 j=0;j<m;j++){ tab[j]={cur,j}; cur=h_mulmod(cur,base,p); }
    std::sort(tab.begin(),tab.end());
    std::vector<u32> sval(m),sj(m);
    for(u32 j=0;j<m;j++){ sval[j]=tab[j].first; sj[j]=tab[j].second; }
    CK(cudaMemcpy(b.d_sval,sval.data(),m*4,cudaMemcpyHostToDevice));
    CK(cudaMemcpy(b.d_sj,sj.data(),m*4,cudaMemcpyHostToDevice));
    u32 ninv=mont_ninv(p),R2=mont_r2(p),one_m=(u32)((1ull<<32)%p);
    long nseg=(n+SEG-1)/SEG; int th=128; long bl=(nseg+th-1)/th;
    size_t shbytes=2*(size_t)m*4;
    k_scan_char<<<bl,th,shbytes>>>(p,ninv,R2,one_m,(u64)e,(int)m,b.d_sval,b.d_sj,n,nseg,b.summ);
    ordered_reduce(b,nseg);   // réduction ORDONNÉE (scan) — SummOp non commutatif
    CK(cudaMemcpy(b.h_sout,b.d_sout,NR*sizeof(Summ),cudaMemcpyDeviceToHost));
    for(int t=0;t<NR;t++) out_maxrun[RMIN+t]=b.h_sout[t].best;
}

// ---------------- flux canonique de premiers (CPU uniquement) ---------------
// BEGIN VDW_PRIME_STREAM_CPU
static bool parse_u64_decimal(const char* text,u64* out){
    if(!text||!*text)return false;
    for(const char* p=text;*p;++p)if(*p<'0'||*p>'9')return false;
    errno=0;char* end=nullptr;unsigned long long value=strtoull(text,&end,10);
    if(errno==ERANGE||!end||*end!='\0')return false;
    *out=(u64)value;return true;
}
static std::vector<u32> sieve_primes(u64 lo,u64 hi){
    std::vector<u32>pr;if(hi<lo||hi<3)return pr;lo=std::max<u64>(lo,3);
    u32 lim=1;while((u64)(lim+1)*(lim+1)<=hi)lim++;
    std::vector<char>small((size_t)lim+1),comp((size_t)(hi-lo+1));std::vector<u32>base;
    for(u32 i=2;i<=lim;i++)if(!small[i]){base.push_back(i);if((u64)i*i<=lim)for(u64 j=(u64)i*i;j<=lim;j+=i)small[(size_t)j]=1;}
    for(u32 q:base){u64 s=std::max<u64>((u64)q*q,((lo+q-1)/q)*q);for(u64 j=s;j<=hi;j+=q)comp[(size_t)(j-lo)]=1;}
    for(u64 x=lo;x<=hi;x++)if(!comp[(size_t)(x-lo)])pr.push_back((u32)x);return pr;
}
static bool make_prime_sample(const char* mode,const std::vector<u32>& all,long nsample,std::vector<u32>* samp){
    if(!samp)return false;samp->clear();
    if(nsample<=0||all.empty()){
        fprintf(stderr,"SAMPLE_INPUT_REJECT mode=%s nsample=%ld available=%zu\n",mode?mode:"unknown",nsample,all.size());
        return false;
    }
    long step=(long)all.size()/nsample;if(step<1)step=1;
    for(long i=0;i<(long)all.size()&&(long)samp->size()<nsample;i+=step)samp->push_back(all[i]);
    if(samp->empty()){
        fprintf(stderr,"SAMPLE_INPUT_REJECT mode=%s nsample=%ld available=%zu\n",mode?mode:"unknown",nsample,all.size());
        return false;
    }
    return true;
}
static int dump_prime_stream(u64 lo,u64 hi){
    std::vector<u32> primes;
    if(lo<hi&&hi>3)primes=sieve_primes(std::max<u64>(lo,3),hi-1);
    printf("VDW-PRIMES-v1\n%llu\n%llu\n",(unsigned long long)lo,(unsigned long long)hi);
    if(lo<=2&&2<hi)printf("2\n");
    for(u32 p:primes)printf("%u\n",p);
    if(ferror(stdout)){fprintf(stderr,"--dump-primes: write failure\n");return 1;}
    return 0;
}
// END VDW_PRIME_STREAM_CPU

// Validation ciblée du domaine Montgomery haut, sans scanner des milliards de
// Jacobi CPU: mêmes primitives que V2a, comparées échantillon par échantillon à
// h_powmod; le chemin Euler (p-1)/2 est en plus comparé au Jacobi binaire.
__global__ void k_mont_samples(u32 p,u32 ninv,u32 R2,u32 one,const u32*base,const u32*exp,const u32*steps,u32*out,u32*rec,u32 n){
    u32 i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=n)return;u32 xm=montmul(base[i],R2,p,ninv);
    u32 ym=mont_pow(xm,exp[i],p,ninv,one);out[i]=montmul(ym,1u,p,ninv);
    for(u32 j=0;j<steps[i];j++)xm=addmod32(xm,one,p);rec[i]=xm;
}
static bool h_is_prime(u32 n){if(n<2)return false;if(!(n&1))return n==2;for(u32 d=3;(u64)d*d<=n;d+=2)if(n%d==0)return false;return true;}
static int run_montcheck(int argc,char**argv){
    u32 ns=(argc>2)?(u32)strtoul(argv[2],0,10):20000u;std::vector<u32>mods;
    for(int i=3;i<argc;i++)mods.push_back((u32)strtoull(argv[i],0,10));
    if(mods.empty())mods={3459826103u,3476732783u,4294967197u,4294967231u,4294967279u,4294967291u};
    u32 *db,*de,*ds,*doo,*dro;CK(cudaMalloc(&db,(size_t)ns*4));CK(cudaMalloc(&de,(size_t)ns*4));CK(cudaMalloc(&ds,(size_t)ns*4));
    CK(cudaMalloc(&doo,(size_t)ns*4));CK(cudaMalloc(&dro,(size_t)ns*4));int rc=0;
    std::vector<u32>b(ns),expv(ns),st(ns),got(ns),rg(ns);u64 state=0x6a09e667f3bcc909ull;
    for(u32 p:mods){if(!(p&1)||p<3){printf("MONTCHECK modulus=%u verdict=SKIP_NOT_ODD\n",p);rc=1;continue;}
        u32 m=1;for(int r=RMIN;r<=RMAX;r++)if((p-1)%r==0)m=h_lcm(m,(u32)r);u32 ve=(p-1)/m;
        for(u32 i=0;i<ns;i++){state=state*6364136223846793005ull+1442695040888963407ull;b[i]=1u+(u32)(state%(p-1ull));
            state=state*6364136223846793005ull+1442695040888963407ull;expv[i]=(i%4==0)?(p-1)/2:((i%4==1)?ve:(u32)state);st[i]=(u32)(state>>48)&2047u;}
        CK(cudaMemcpy(db,b.data(),(size_t)ns*4,cudaMemcpyHostToDevice));CK(cudaMemcpy(de,expv.data(),(size_t)ns*4,cudaMemcpyHostToDevice));CK(cudaMemcpy(ds,st.data(),(size_t)ns*4,cudaMemcpyHostToDevice));
        u32 ni=mont_ninv(p),r2=mont_r2(p),one=(u32)((1ull<<32)%p);k_mont_samples<<<(ns+255)/256,256>>>(p,ni,r2,one,db,de,ds,doo,dro,ns);
        CK(cudaMemcpy(got.data(),doo,(size_t)ns*4,cudaMemcpyDeviceToHost));CK(cudaMemcpy(rg.data(),dro,(size_t)ns*4,cudaMemcpyDeviceToHost));
        u64 bad=0,jbad=0,rbad=0,jcmp=0,cs=1469598103934665603ull;bool prime=h_is_prime(p);
        for(u32 i=0;i<ns;i++){u32 want=h_powmod(b[i],expv[i],p);if(got[i]!=want)bad++;
            u32 x=(u32)(((u64)b[i]+st[i])%p),rw=montmul(x,r2,p,ni);if(rg[i]!=rw)rbad++;
            if(prime&&expv[i]==(p-1)/2){jcmp++;int j=h_jacobi(b[i],p);u32 jw=(j<0)?p-1u:(u32)j;if(got[i]!=jw)jbad++;}
            cs^=((u64)got[i]<<32)^rg[i];cs*=1099511628211ull;}
        printf("MONTCHECK modulus=%u prime=%d samples=%u pow_mismatch=%llu recur_mismatch=%llu jacobi_cmp=%llu jacobi_mismatch=%llu checksum=%llu verdict=%s\n",
            p,(int)prime,ns,(unsigned long long)bad,(unsigned long long)rbad,(unsigned long long)jcmp,(unsigned long long)jbad,(unsigned long long)cs,(bad||rbad||jbad)?"FAIL":"PASS");
        if(bad||rbad||jbad)rc=1;
    }
    return rc;
}

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: %s --dump-primes lo hi | --validate Pmax | --montcheck [N [mod...]] | --v2a lo hi n | --scan lo hi\n",argv[0]); return 1; }
    if(!strcmp(argv[1],"--dump-primes")){
        u64 lo=0,hi=0;
        if(argc!=4||!parse_u64_decimal(argv[2],&lo)||!parse_u64_decimal(argv[3],&hi)||lo>hi||hi>(1ull<<32)){
            fprintf(stderr,"usage: %s --dump-primes lo hi  (0 <= lo <= hi <= 2^32; interval [lo,hi))\n",argv[0]);return 2;
        }
        return dump_prime_stream(lo,hi);
    }
    cudaDeviceProp prop; CK(cudaGetDeviceProperties(&prop,0));
    fprintf(stderr,"[scan_gpu] %s sm_%d%d, %.1f Go\n",prop.name,prop.major,prop.minor,prop.totalGlobalMem/1e9);

    if(!strcmp(argv[1],"--montcheck"))return run_montcheck(argc,argv);

    if(!strcmp(argv[1],"--validate")){
        u64 Pmax=(argc>2)?strtoull(argv[2],0,10):100000ull;
        assert(Pmax < (1ull<<32));
        auto primes=sieve_primes(3,Pmax);
        Buffers b; alloc_buffers(b, (long)Pmax);
        // 3 voies : SORT (process_prime, ind%r tous r) ; CHAR B7 (r|p-1) ; CPU (ind%r).
        long nchk=0,nf_sc=0,nf_cc=0,nf_va=0,nf_vb=0,nbstar=0,nf_bstar=0;
        long nchk_char=0;
        auto t0=std::chrono::steady_clock::now();
        for(u32 p: primes){
            if(p<=RMAX) continue;
            u32 g=primitive_root(p);
            int gpu[RMAX+1]={0}, cpu[RMAX+1]={0}, chr[RMAX+1]={0}, act[RMAX+1]={0}, v2a[RMAX+1]={0}, av[RMAX+1]={0}, v2b[RMAX+1]={0}, bv[RMAX+1]={0};
            process_prime(b,p,g,gpu);
            process_prime_char(b,p,g,chr,act);
            process_prime_char_v2a(b,p,g,v2a,av,nullptr);
            process_prime_char_v2b(b,p,g,v2b,bv,nullptr);
            std::vector<u16> logtab;cpu_maxrun(p,g,cpu,&logtab);
            for(int r=RMIN;r<=RMAX;++r){
                nchk++; if(gpu[r]!=cpu[r]){ nf_sc++; if(nf_sc<=10) printf("SORT!=CPU p=%u r=%d : %d/%d\n",p,r,gpu[r],cpu[r]); }
                if(act[r]){ nchk_char++; if(chr[r]!=cpu[r]){ nf_cc++; if(nf_cc<=10) printf("CHAR!=CPU p=%u r=%d : %d/%d\n",p,r,chr[r],cpu[r]); }
                    if(v2a[r]!=cpu[r]){ nf_va++; if(nf_va<=10) printf("V2a!=CPU p=%u(mod4=%u) r=%d : %d/%d\n",p,p&3,r,v2a[r],cpu[r]); }
                    if(v2b[r]!=cpu[r]){ nf_vb++; if(nf_vb<=10) printf("V2b!=CPU p=%u(mod4=%u) r=%d : %d/%d\n",p,p&3,r,v2b[r],cpu[r]); }
                    for(int k=3;k<=28&&k<(int)p;k++){nbstar++;bool a=boundary_ok_pow(p,g,r,k),w=boundary_ok_walk(p,r,k,logtab);
                        if(a!=w){nf_bstar++;if(nf_bstar<=10)printf("BSTAR pow!=walk p=%u r=%d k=%d : %d/%d\n",p,r,k,(int)a,(int)w);}}
                }
            }
        }
        auto t1=std::chrono::steady_clock::now();
        double s=std::chrono::duration<double>(t1-t0).count();
        printf("\n=== VALIDATION DIFFERENTIELLE (3 voies) ===\n");
        printf("premiers testes : %zu (p<%llu)\n",primes.size(),(unsigned long long)Pmax);
        printf("SORT vs CPU : %ld comparaisons, %ld desaccords\n",nchk,nf_sc);
        printf("CHAR(B7) vs CPU : %ld comparaisons (r|p-1), %ld desaccords\n",nchk_char,nf_cc);
        printf("V2a(miroir) vs CPU : %ld comparaisons (r|p-1), %ld desaccords\n",nchk_char,nf_va);
        printf("V2b(parite 2-adique) vs CPU : %ld comparaisons (r|p-1), %ld desaccords\n",nchk_char,nf_vb);
        printf("B*(powmod) vs B*(walk) : %ld comparaisons, %ld desaccords\n",nbstar,nf_bstar);
        bool ok=(nf_sc==0 && nf_cc==0 && nf_va==0 && nf_vb==0 && nf_bstar==0);
        printf("VERDICT : %s  (%.1fs)\n", ok?"ACCORD 100% (V2a/V2b + B7 + tri + CPU concordants)":"ECHEC",s);
        return ok?0:1;
    }
    if(!strcmp(argv[1],"--b7")){
        u64 lo=strtoull(argv[2],0,10),hi=strtoull(argv[3],0,10); long nsample=atol(argv[4]);
        assert(hi < (1ull<<32));
        auto all=sieve_primes(lo,hi);
        std::vector<u32> samp;if(!make_prime_sample("--b7",all,nsample,&samp))return 2;
        Buffers b; alloc_buffers_b7(b,(long)hi);
        { int m[RMAX+1],a[RMAX+1]; process_prime_char(b,samp[0],primitive_root(samp[0]),m,a); CK(cudaDeviceSynchronize()); }
        auto t0=std::chrono::steady_clock::now(); u64 elems=0;
        for(u32 p: samp){ u32 g=primitive_root(p); int m[RMAX+1],a[RMAX+1]; process_prime_char(b,p,g,m,a); elems+=(p-1); }
        CK(cudaDeviceSynchronize());
        auto t1=std::chrono::steady_clock::now(); double s=std::chrono::duration<double>(t1-t0).count();
        double rate=(double)elems/s;
        printf("\n=== B7 débit éval-caractère fusionnée (SANS tri, SANS val16) ===\n");
        printf("premiers traites : %zu dans [%llu,%llu] ; elements : %.3e\n",samp.size(),(unsigned long long)lo,(unsigned long long)hi,(double)elems);
        printf("debit soutenu : %.3f x10^10 el/s  (%.2fs)\n",rate/1e10,s);
        printf("vs plafond tri S2 2,76x10^10 : %.2fx  |  adopter si >=2x : %s\n",rate/2.76e10, rate>=2*2.76e10?"OUI":"NON (mais compare aussi au tri reel B6)");
        return 0;
    }
    if(!strcmp(argv[1],"--v2a")){   // débit V2a (demi-intervalle miroir)
        u64 lo=strtoull(argv[2],0,10),hi=strtoull(argv[3],0,10); long nsample=atol(argv[4]);
        assert(hi < (1ull<<32));
        auto all=sieve_primes(lo,hi);std::vector<u32> samp;if(!make_prime_sample("--v2a",all,nsample,&samp))return 2;
        Buffers b; alloc_buffers_b7(b,(long)hi/2+64);
        { int m[RMAX+1],a[RMAX+1]; double mm; process_prime_char_v2a(b,samp[0],primitive_root(samp[0]),m,a,&mm); CK(cudaDeviceSynchronize()); }
        auto t0=std::chrono::steady_clock::now(); u64 elems=0; double mmsum=0;
        for(u32 p: samp){ u32 g=primitive_root(p); int m[RMAX+1],a[RMAX+1]; double mm; process_prime_char_v2a(b,p,g,m,a,&mm); elems+=(p-1); mmsum+=mm; }
        CK(cudaDeviceSynchronize());
        auto t1=std::chrono::steady_clock::now(); double s=std::chrono::duration<double>(t1-t0).count();
        double rate=(double)elems/s;                       // el/s (elements PLEINS reconstruits)
        double mm_half=mmsum/samp.size();                  // mulmods par element PROCESSE (demi)
        double mm_full=mm_half/2.0;                         // mulmods par element plein
        double mmrate=rate*mm_full;                         // mulmod/s effectif
        printf("\n=== V2a débit (demi-intervalle miroir, multi-r r<=%d) ===\n",RMAX);
        printf("premiers : %zu dans [%llu,%llu] ; elements pleins : %.3e\n",samp.size(),(unsigned long long)lo,(unsigned long long)hi,(double)elems);
        printf("debit : %.3f x10^10 el/s (pleins)  (%.2fs)\n",rate/1e10,s);
        printf("mulmods/element : %.1f (procede) = %.1f (plein) ; mulmod/s eff = %.2f x10^12\n",mm_half,mm_full,mmrate/1e12);
        printf("efficacite vs B1 (3401 Gmulmod/s) : %.1f%% | vs tri 2,76e10 : %.2fx\n",100*mmrate/3.401e12,rate/2.76e10);
        return 0;
    }
    if(!strcmp(argv[1],"--v2b")){   // débit V2b (parité 2-adique)
        u64 lo=strtoull(argv[2],0,10),hi=strtoull(argv[3],0,10); long nsample=atol(argv[4]);
        assert(hi < (1ull<<32));
        auto all=sieve_primes(lo,hi);std::vector<u32> samp;if(!make_prime_sample("--v2b",all,nsample,&samp))return 2;
        Buffers b; alloc_buffers_b7(b,(long)hi);
        { int m[RMAX+1],a[RMAX+1]; double mm; process_prime_char_v2b(b,samp[0],primitive_root(samp[0]),m,a,&mm); CK(cudaDeviceSynchronize()); }
        auto t0=std::chrono::steady_clock::now(); u64 elems=0; double mmsum=0;
        for(u32 p: samp){ u32 g=primitive_root(p); int m[RMAX+1],a[RMAX+1]; double mm; process_prime_char_v2b(b,p,g,m,a,&mm); elems+=(p-1); mmsum+=mm; }
        CK(cudaDeviceSynchronize());
        auto t1=std::chrono::steady_clock::now(); double s=std::chrono::duration<double>(t1-t0).count();
        double rate=(double)elems/s;
        double mm_odd=mmsum/samp.size();       // mulmods par IMPAIR traité
        double mm_full=mm_odd/4.0;             // par element plein : seuls (p-1)/4 impairs ont un modpow
        double mmrate=rate*mm_full;
        printf("\n=== V2b débit (parité 2-adique, multi-r r<=%d) ===\n",RMAX);
        printf("premiers : %zu dans [%llu,%llu] ; elements pleins : %.3e\n",samp.size(),(unsigned long long)lo,(unsigned long long)hi,(double)elems);
        printf("debit : %.3f x10^10 el/s (pleins)  (%.2fs)\n",rate/1e10,s);
        printf("mulmods/element : %.1f (par impair) = %.1f (plein) ; mulmod/s eff = %.2f x10^12\n",mm_odd,mm_full,mmrate/1e12);
        printf("efficacite vs B1 : %.1f%% | vs V2a ~9,7e10 : %.2fx | vs tri : %.2fx\n",100*mmrate/3.401e12,rate/9.72e10,rate/2.76e10);
        return 0;
    }
    if(!strcmp(argv[1],"--b7fast")){
        u64 lo=strtoull(argv[2],0,10),hi=strtoull(argv[3],0,10); long nsample=atol(argv[4]);
        assert(hi < (1ull<<32));
        auto all=sieve_primes(lo,hi);std::vector<u32> samp;if(!make_prime_sample("--b7fast",all,nsample,&samp))return 2;
        Buffers b; alloc_buffers_b7(b,(long)std::max<u64>(hi,60000));
        // (1) validation r=2,3 vs CPU sur petits premiers
        auto small=sieve_primes(3,60000); long nf=0,nc=0;
        for(u32 p: small){ if(p<=RMAX) continue; u32 g=primitive_root(p);
            int cpu[RMAX+1]={0},f[RMAX+1]={0},do3=0; cpu_maxrun(p,g,cpu); process_prime_char23(b,p,g,f,&do3);
            nc++; if(f[2]!=cpu[2]){nf++; if(nf<=8)printf("FAST r2 p=%u %d/%d\n",p,f[2],cpu[2]);}
            if(do3){ nc++; if(f[3]!=cpu[3]){nf++; if(nf<=8)printf("FAST r3 p=%u %d/%d\n",p,f[3],cpu[3]);} }
        }
        printf("validation FAST(r=2,3) vs CPU : %ld comparaisons, %ld desaccords -> %s\n",nc,nf,nf==0?"100%":"ECHEC");
        if(nf) return 1;
        // (2) débit sur l'échantillon campagne
        { int m[RMAX+1],d3; process_prime_char23(b,samp[0],primitive_root(samp[0]),m,&d3); CK(cudaDeviceSynchronize()); }
        auto t0=std::chrono::steady_clock::now(); u64 elems=0;
        for(u32 p: samp){ u32 g=primitive_root(p); int m[RMAX+1],d3; process_prime_char23(b,p,g,m,&d3); elems+=(p-1); }
        CK(cudaDeviceSynchronize());
        auto t1=std::chrono::steady_clock::now(); double s=std::chrono::duration<double>(t1-t0).count();
        double rate=(double)elems/s;
        printf("\n=== B7 RAPIDE r=2(+3) zéro-table, débit ===\n");
        printf("premiers : %zu dans [%llu,%llu] ; elements : %.3e\n",samp.size(),(unsigned long long)lo,(unsigned long long)hi,(double)elems);
        printf("debit : %.3f x10^10 el/s  (%.2fs)\n",rate/1e10,s);
        printf("vs plafond tri 2,76e10 : %.2fx | vs B6 tri reel 1,43e10 : %.2fx | >=2x tri : %s\n",
               rate/2.76e10, rate/1.43e10, rate>=2*2.76e10?"OUI":"NON");
        return 0;
    }
    if(!strcmp(argv[1],"--b6")){
        u64 lo=strtoull(argv[2],0,10),hi=strtoull(argv[3],0,10); long nsample=atol(argv[4]);
        assert(hi < (1ull<<32));
        auto all=sieve_primes(lo,hi);
        // échantillon régulier
        std::vector<u32> samp;if(!make_prime_sample("--b6",all,nsample,&samp))return 2;
        Buffers b; alloc_buffers(b,(long)hi);
        // warmup
        { int m[RMAX+1]; process_prime(b,samp[0],primitive_root(samp[0]),m); CK(cudaDeviceSynchronize()); }
        auto t0=std::chrono::steady_clock::now(); u64 elems=0;
        for(u32 p: samp){ u32 g=primitive_root(p); int m[RMAX+1]; process_prime(b,p,g,m); elems+=(p-1); }
        CK(cudaDeviceSynchronize());
        auto t1=std::chrono::steady_clock::now(); double s=std::chrono::duration<double>(t1-t0).count();
        printf("\n=== B6 débit pipeline (étage 1, S2 SortPairs) ===\n");
        printf("premiers traites : %zu dans [%llu,%llu] ; elements : %.3e\n",samp.size(),(unsigned long long)lo,(unsigned long long)hi,(double)elems);
        printf("debit soutenu : %.3f x10^10 el/s  (%.2fs)  [inclut gen+tri+scan multi-r, SANS overlap]\n",(double)elems/s/1e10,s);
        printf("question discriminante (>=1e10) : %s\n",(double)elems/s>=1e10?"OUI":"NON");
        return 0;
    }
    if(!strcmp(argv[1],"--verify1")){ // PF1(ii) sur UN premier : triplet {V2a,B7-plein,CPU-walk} x2
        if(argc<3||argc>5){fprintf(stderr,"usage: --verify1 p [k [r]]\n");return 2;}
        u64 p=0,karg=0,rarg=2;bool classification_requested=argc>=4;
        if(!parse_u64_decimal(argv[2],&p)||p<3||p>=(1ull<<32)
           ||(classification_requested&&(!parse_u64_decimal(argv[3],&karg)||karg<2||karg>(u64)INT_MAX))
           ||(argc==5&&(!parse_u64_decimal(argv[4],&rarg)||rarg>(u64)INT_MAX))){
            fprintf(stderr,"VERIFY1_INPUT_REJECT: invalid p, k, or r\n");return 2;
        }
        int kk=classification_requested?(int)karg:0;int rr=(int)rarg;
        Buffers b; alloc_buffers_b7(b,(long)p+64); u32 g=primitive_root(p);
        int va1[RMAX+1]={0},va2[RMAX+1]={0},b71[RMAX+1]={0},b72[RMAX+1]={0},cw1[RMAX+1]={0},cw2[RMAX+1]={0},ac[RMAX+1]={0};
        process_prime_char_v2a(b,p,g,va1,ac,nullptr); process_prime_char_v2a(b,p,g,va2,ac,nullptr);   // V2a x2
        process_prime_char(b,p,g,b71,ac);             process_prime_char(b,p,g,b72,ac);               // B7-plein x2
        cpu_maxrun(p,g,cw1);                          cpu_maxrun(p,g,cw2);                             // CPU-walk x2
        printf("VERIFY1 p=%llu g=%u\n",(unsigned long long)p,g);
        printf("%-4s %-6s %-6s %-6s %-6s %-6s %-6s %s\n","r","V2a#1","V2a#2","B7#1","B7#2","CPU#1","CPU#2","accord");
        u64 csum=14695981039346656037ull;csum=fnv1a_u64_le(csum,p);bool allok=true;
        for(int r=RMIN;r<=RMAX;++r){ if((p-1)%r) continue;
            bool ok=(va1[r]==va2[r]&&va1[r]==b71[r]&&va1[r]==b72[r]&&va1[r]==cw1[r]&&va1[r]==cw2[r]);
            allok&=ok;csum=fnv1a_u64_le(csum,(u64)r);
            csum=fnv1a_u64_le(csum,(u64)va1[r]);csum=fnv1a_u64_le(csum,(u64)va2[r]);
            csum=fnv1a_u64_le(csum,(u64)b71[r]);csum=fnv1a_u64_le(csum,(u64)b72[r]);
            csum=fnv1a_u64_le(csum,(u64)cw1[r]);csum=fnv1a_u64_le(csum,(u64)cw2[r]);
            csum=fnv1a_u64_le(csum,ok?1ull:0ull);
            printf("%-4d %-6d %-6d %-6d %-6d %-6d %-6d %s\n",r,va1[r],va2[r],b71[r],b72[r],cw1[r],cw2[r],ok?"OK":"**DIFF**"); }
        printf("CHECKSUM(maxrun) %llu\n",(unsigned long long)csum);
        printf("PROFILE_DIGEST algorithm=fnv1a64-le64 value=%016llx\n",(unsigned long long)csum);
        printf("TRIPLET x2 : %s\n", allok?"ACCORD 100% (V2a=B7=CPU, double-run identique)":"ECHEC");
        bool requested=classification_requested;int claim_r=requested?rr:0;bool applicable=false,A=false,B=false;
        int claim_maxrun=-1;u64 claim_bound=0;
        if(requested){
            applicable=(claim_r>=RMIN&&claim_r<=RMAX&&(p-1)%(u64)claim_r==0&&p>(u64)kk);
            if(applicable){claim_maxrun=va1[claim_r];A=claim_maxrun<kk;B=boundary_ok_pow((u32)p,g,claim_r,kk);}
            claim_bound=(u64)(kk-1)*p+1;
            printf("CLASSIFICATION r=%d k=%d maxrun=%d A=%s Bstar=%s A_AND_B=%s\n",
                claim_r,kk,claim_maxrun,A?"PASS":"FAIL",B?"PASS":"FAIL",(A&&B)?"PASS":"FAIL");
        }
        bool claimok=!requested||(applicable&&A&&B);bool finalok=allok&&claimok;
        u64 claim_digest=14695981039346656037ull;
        claim_digest=fnv1a_u64_le(claim_digest,p);
        claim_digest=fnv1a_u64_le(claim_digest,(u64)claim_r);
        claim_digest=fnv1a_u64_le(claim_digest,(u64)kk);
        claim_digest=fnv1a_u64_le(claim_digest,claim_bound);
        claim_digest=fnv1a_u64_le(claim_digest,csum);
        claim_digest=fnv1a_u64_le(claim_digest,applicable?1ull:0ull);
        claim_digest=fnv1a_u64_le(claim_digest,A?1ull:0ull);
        claim_digest=fnv1a_u64_le(claim_digest,B?1ull:0ull);
        claim_digest=fnv1a_u64_le(claim_digest,(A&&B)?1ull:0ull);
        claim_digest=fnv1a_u64_le(claim_digest,allok?1ull:0ull);
        claim_digest=fnv1a_u64_le(claim_digest,finalok?1ull:0ull);
        const char *applicable_text=requested?(applicable?"YES":"NO"):"NA";
        const char *A_text=requested?(A?"PASS":"FAIL"):"NA";
        const char *B_text=requested?(B?"PASS":"FAIL"):"NA";
        const char *AB_text=requested?((A&&B)?"PASS":"FAIL"):"NA";
        printf("CLAIM_RESULT version=1 digest_alg=fnv1a64-le64 p=%llu r=%d k=%d bound=%llu maxrun=%d "
               "profile_digest=%016llx applicable=%s A=%s Bstar=%s A_AND_B=%s triplet=%s verdict=%s digest=%016llx\n",
            (unsigned long long)p,claim_r,kk,(unsigned long long)claim_bound,claim_maxrun,
            (unsigned long long)csum,applicable_text,A_text,B_text,AB_text,
            allok?"ACCORD":"ECHEC",finalok?"ACCEPT":"REJECT",
            (unsigned long long)claim_digest);
        return finalok?0:1;
    }
    if(!strcmp(argv[1],"--xcheck")){ // cross-check TRIPLET {V2a,B7-plein,CPU-walk} sur [lo,hi]
        u64 lo=strtoull(argv[2],0,10),hi=strtoull(argv[3],0,10); long n=(argc>4)?atol(argv[4]):20;
        assert(hi < (1ull<<32));
        auto all=sieve_primes(lo,hi);std::vector<u32> samp;if(!make_prime_sample("--xcheck",all,n,&samp))return 2;
        Buffers b; alloc_buffers_b7(b,(long)hi);
        // Fiables (PASS/FAIL) : V2a (char, moteur campagne) vs CPU-walk (log discret) + Jacobi(r=2).
        // B7-plein = diagnostic WARN (bug grand-p connu, à corriger avant emploi comme 3e impl).
        long cmp=0,dis=0,warn=0,done=0; auto tx0=std::chrono::steady_clock::now();
        for(u32 p: samp){ u32 g=primitive_root(p);
            int va[RMAX+1]={0},ch[RMAX+1]={0},cp[RMAX+1]={0},av[RMAX+1]={0},ac[RMAX+1]={0};
            process_prime_char_v2a(b,p,g,va,av,nullptr);   // V2a (char-powmod demi-miroir)
            process_prime_char(b,p,g,ch,ac);                // B7-plein (DIAGNOSTIC)
            cpu_maxrun(p,g,cp);                             // CPU-walk (log discret), O(p) ponctuel
            for(int r=RMIN;r<=RMAX;++r) if(av[r]){ cmp++;
                if(va[r]!=cp[r]){ dis++; if(dis<=10) printf("FAIL V2a!=CPU p=%u r=%d : v2a=%d cpu=%d\n",p,r,va[r],cp[r]); }
                if(ch[r]!=cp[r]){ warn++; if(warn<=6) printf("WARN B7plein!=CPU p=%u r=%d : b7=%d cpu=%d (bug grand-p connu)\n",p,r,ch[r],cp[r]); } }
            int j2=cpu_maxrun_jacobi_r2(p);                 // Jacobi r=2 (réciprocité), indépendant
            if(av[2] && j2!=cp[2]){ dis++; printf("FAIL Jacobi!=CPU p=%u r=2 : jac=%d cpu=%d\n",p,j2,cp[2]); }
            done++; double el=std::chrono::duration<double>(std::chrono::steady_clock::now()-tx0).count();
            fprintf(stderr,"\r  [xcheck] %ld/%zu premiers ; %.0fs ecoule, ETA %.0fs   ",done,samp.size(),el,el*(samp.size()-done)/done); fflush(stderr);
        }
        fprintf(stderr,"\n");
        printf("XCHECK [%llu,%llu] %zu prem. : %ld comp. ; V2a/Jacobi vs CPU desaccords=%ld -> %s ; B7plein WARN=%ld\n",
               (unsigned long long)lo,(unsigned long long)hi,samp.size(),cmp,dis, dis==0?"ACCORD (moteur campagne OK)":"ECHEC", warn);
        return dis?1:0;
    }
    if(!strcmp(argv[1],"--scan")){   // CAMPAGNE : tous les premiers de [lo,hi], cibles (r,k)
        u64 lo=strtoull(argv[2],0,10),hi=strtoull(argv[3],0,10);
        assert(hi < (1ull<<32));
        // cibles campagne (r,k) : (2,25), (3,17..25) + BONUS (2,26..28) tracking live
        // (K6/bonus_targets.md : seuils k=26,27,28 r=2 ajoutés au 1er restart propre, <=p=1.4e9).
        // maxrun[2] déjà calculé exact -> tally générique (m[2]<k). Champions dans la queue p>1e9.
        struct Tgt{int r,k;}; std::vector<Tgt> T={{2,25},{3,17},{3,18},{3,19},{3,20},{3,21},{3,22},{3,23},{3,24},{3,25},{2,26},{2,27},{2,28}};
        std::vector<u32> primes;
        if(lo<hi)primes=sieve_primes(lo,hi-1); // campaign intervals are half-open [lo,hi)
        Buffers b; alloc_buffers_b7(b,(long)hi);
        std::vector<long> cntA(T.size(),0),cntAB(T.size(),0);std::vector<u32> maxA(T.size(),0),maxAB(T.size(),0);
        std::vector<std::vector<u32>> candA(T.size()),candAB(T.size());
        // O1/mélange : compteurs AGRÉGÉS col_r(q)=0 (q r-ième résidu) chez les valides, par cible.
        // Stockage négligeable (pas de listes). Baseline Chebotarev = 1/r. col=0 <=> q^((p-1)/r)==1.
        static const u32 QSET[6]={2,3,5,7,11,13}; const int NQ=6;
        std::vector<std::vector<long>> colq0(T.size(), std::vector<long>(NQ,0));
        u64 checksumA=1469598103934665603ull,checksumAB=1469598103934665603ull;
        // R0 : histogrammes maxrun (64 bins) + top-20 premiers, par r=RMIN..RMAX (r|p-1). ADDITIF.
        static long histo[RMAX+1][64]={};
        struct TopE{int mr; u32 p;}; std::vector<std::vector<TopE>> top(RMAX+1);
        for(u32 p: primes){ if(p<=RMAX) continue; u32 g=primitive_root(p);
            int m[RMAX+1],a[RMAX+1]; process_prime_char_v2a(b,p,g,m,a,nullptr);   // V2a (voie campagne)
            int col2[6],col3[6],done2=0,done3=0;   // cache col_r(q) : calculé 1× par r par premier valide
            for(int r=RMIN;r<=RMAX;++r) if(a[r]){ int mr=m[r]; histo[r][mr<0?0:(mr>63?63:mr)]++;
                auto&tv=top[r];                                  // top-20 par r (maxrun decroissant)
                if((int)tv.size()<20 || mr>tv.back().mr){ tv.push_back({mr,p});
                    for(int i=(int)tv.size()-1;i>0&&tv[i].mr>tv[i-1].mr;--i) std::swap(tv[i],tv[i-1]);
                    if(tv.size()>20) tv.pop_back(); } }
            for(size_t t=0;t<T.size();++t){int r=T[t].r,k=T[t].k;
                if((p-1)%r==0&&m[r]<k){cntA[t]++;if(p>maxA[t])maxA[t]=p;checksumA^=p;checksumA*=1099511628211ull;
                    bool bok=boundary_ok_pow(p,g,r,k);if((r==2&&k==25)||(r==3&&k==17))candA[t].push_back(p);
                    if(!bok)continue;cntAB[t]++;if(p>maxAB[t])maxAB[t]=p;checksumAB^=p;checksumAB*=1099511628211ull;
                    if((r==2&&k==25)||(r==3&&k==17))candAB[t].push_back(p);
                    int* cv=nullptr;
                    if(r==2){ if(!done2){ for(int j=0;j<NQ;j++) col2[j]=(h_powmod(QSET[j],(p-1)/2,p)==1); done2=1; } cv=col2; }
                    else if(r==3){ if(!done3){ for(int j=0;j<NQ;j++) col3[j]=(h_powmod(QSET[j],(p-1)/3,p)==1); done3=1; } cv=col3; }
                    if(cv) for(int j=0;j<NQ;j++) if(cv[j]) colq0[t][j]++; } }
        }
        printf("# SCAN [%llu,%llu] : %zu premiers\n",(unsigned long long)lo,(unsigned long long)hi,primes.size());
        for(size_t t=0;t<T.size();++t)printf("TARGET r=%d k=%d A_count=%ld A_max_p=%u A_bound=%llu AB_count=%ld AB_max_p=%u AB_bound=%llu Bstar_reject=%ld\n",
            T[t].r,T[t].k,cntA[t],maxA[t],(unsigned long long)(maxA[t]?(u64)(T[t].k-1)*maxA[t]+1:0),cntAB[t],maxAB[t],(unsigned long long)(maxAB[t]?(u64)(T[t].k-1)*maxAB[t]+1:0),cntA[t]-cntAB[t]);
        printf("CHECKSUM_A %llu\nCHECKSUM_AB %llu\n",(unsigned long long)checksumA,(unsigned long long)checksumAB);
        for(size_t t=0;t<T.size();++t){if(!candA[t].empty()){printf("CANDIDATS_A r=%d k=%d :",T[t].r,T[t].k);for(u32 q:candA[t])printf(" %u",q);printf("\n");}
            if(!candAB[t].empty()){printf("CANDIDATS_AB r=%d k=%d :",T[t].r,T[t].k);for(u32 q:candAB[t])printf(" %u",q);printf("\n");}}
        // COLQ (O1/mélange) : cnt valides + #(col_r(q)=0) par q∈{2,3,5,7,11,13}. Baseline=1/r.
        for(size_t t=0;t<T.size();++t){
            printf("COLQ r=%d k=%d cnt_AB=%ld :",T[t].r,T[t].k,cntAB[t]);
            for(int j=0;j<NQ;j++) printf(" %ld",colq0[t][j]); printf("\n"); }
        // R0 : histogrammes + top-20 (ADDITIF, hors checksum ; sink Q1/localisation).
        for(int r=RMIN;r<=RMAX;++r){
            printf("HISTO r=%d :",r); for(int b2=0;b2<64;++b2) printf(" %ld",histo[r][b2]); printf("\n"); }
        for(int r=RMIN;r<=RMAX;++r){
            printf("TOP r=%d :",r); for(auto&e:top[r]) printf(" %u:%d",e.p,e.mr); printf("\n"); }
        return 0;
    }
    if(!strcmp(argv[1],"--b7db")){   // multi-r double-buffered (2 streams)
        u64 lo=strtoull(argv[2],0,10),hi=strtoull(argv[3],0,10); long nsample=atol(argv[4]);
        assert(hi < (1ull<<32));
        auto all=sieve_primes(lo,hi);std::vector<u32> samp;if(!make_prime_sample("--b7db",all,nsample,&samp))return 2;
        long ns=samp.size();
        // pré-calcul (hors boucle chronométrée) : g,ninv,R2,one_m,e,m + tables
        std::vector<u32> P(ns),NINV(ns),R2A(ns),ONE(ns),M(ns); std::vector<u64> E(ns);
        u32 *hval,*hj; CK(cudaHostAlloc(&hval,(size_t)ns*MMAX*4,cudaHostAllocDefault));
        CK(cudaHostAlloc(&hj,(size_t)ns*MMAX*4,cudaHostAllocDefault));
        for(long i=0;i<ns;i++){ u32 p=samp[i]; u32 g=primitive_root(p);
            u32 m=1; for(int r=RMIN;r<=RMAX;++r) if((p-1)%r==0) m=h_lcm(m,(u32)r);
            u32 base=h_powmod(g,(p-1)/m,p);
            std::vector<std::pair<u32,u32>> tab(m); u32 cur=1;
            for(u32 j=0;j<m;j++){tab[j]={cur,j};cur=h_mulmod(cur,base,p);} std::sort(tab.begin(),tab.end());
            for(u32 j=0;j<m;j++){hval[(size_t)i*MMAX+j]=tab[j].first; hj[(size_t)i*MMAX+j]=tab[j].second;}
            P[i]=p;NINV[i]=mont_ninv(p);R2A[i]=mont_r2(p);ONE[i]=(u32)((1ull<<32)%p);M[i]=m;E[i]=(p-1)/m;
        }
        // 2 contextes de stream
        long cap=hi, nseg_max=(cap+SEG-1)/SEG+1;
        struct SC{Summ*summ;Summ*dso;u32*dv;u32*dj;void*scan;size_t scanb;cudaStream_t st;} c[2];
        for(int s=0;s<2;s++){ CK(cudaMalloc(&c[s].summ,(size_t)NR*nseg_max*sizeof(Summ)));
            CK(cudaMalloc(&c[s].dso,NR*sizeof(Summ))); CK(cudaMalloc(&c[s].dv,MMAX*4)); CK(cudaMalloc(&c[s].dj,MMAX*4));
            c[s].scan=nullptr;c[s].scanb=0; SummOp op;
            cub::DeviceScan::InclusiveScan(c[s].scan,c[s].scanb,c[s].summ,c[s].summ,op,nseg_max); CK(cudaMalloc(&c[s].scan,c[s].scanb));
            CK(cudaStreamCreate(&c[s].st)); }
        Summ* hres; CK(cudaHostAlloc(&hres,(size_t)ns*NR*sizeof(Summ),cudaHostAllocDefault));
        auto launch=[&](long i){ int s=i&1; u32 p=P[i]; long n=p-1; long nseg=(n+SEG-1)/SEG; int th=128; long bl=(nseg+th-1)/th;
            CK(cudaMemcpyAsync(c[s].dv,hval+(size_t)i*MMAX,M[i]*4,cudaMemcpyHostToDevice,c[s].st));
            CK(cudaMemcpyAsync(c[s].dj,hj+(size_t)i*MMAX,M[i]*4,cudaMemcpyHostToDevice,c[s].st));
            k_scan_char<<<bl,th,2*(size_t)M[i]*4,c[s].st>>>(p,NINV[i],R2A[i],ONE[i],E[i],(int)M[i],c[s].dv,c[s].dj,n,nseg,c[s].summ);
            SummOp op;
            for(int t=0;t<NR;t++) cub::DeviceScan::InclusiveScan(c[s].scan,c[s].scanb,c[s].summ+(long)t*nseg,c[s].summ+(long)t*nseg,op,nseg,c[s].st);
            k_lastgather<<<1,NR,0,c[s].st>>>(c[s].summ,nseg,NR,c[s].dso);
            CK(cudaMemcpyAsync(hres+i*NR,c[s].dso,NR*sizeof(Summ),cudaMemcpyDeviceToHost,c[s].st)); };
        launch(0); CK(cudaStreamSynchronize(c[0].st));   // warmup
        auto t0=std::chrono::steady_clock::now(); u64 elems=0;
        for(long i=0;i<ns;i++){ launch(i); elems+=(P[i]-1); }
        CK(cudaStreamSynchronize(c[0].st)); CK(cudaStreamSynchronize(c[1].st));
        auto t1=std::chrono::steady_clock::now(); double s=std::chrono::duration<double>(t1-t0).count();
        double rate=(double)elems/s;
        printf("\n=== B7 multi-r DOUBLE-BUFFERED (2 streams), r<=%d ===\n",RMAX);
        printf("premiers : %ld dans [%llu,%llu] ; elements : %.3e\n",ns,(unsigned long long)lo,(unsigned long long)hi,(double)elems);
        printf("debit : %.3f x10^10 el/s  (%.2fs)\n",rate/1e10,s);
        printf("vs tri 2,76e10 : %.2fx | >=2x tri : %s\n",rate/2.76e10, rate>=2*2.76e10?"OUI":"NON");
        return 0;
    }
    fprintf(stderr,"mode inconnu\n"); return 1;
}
