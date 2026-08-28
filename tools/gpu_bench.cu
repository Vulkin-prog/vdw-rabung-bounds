// ============================================================================
// tools/gpu_bench.cu — T2 microbenchmarks GPU (RTX 5090, sm_120).
// Ordre de priorité (couche de vérification) : B1 -> B2/B3 (tables 2–4 Go) -> B5.
//   B1 : mulmod Montgomery 32b en CHAÎNE DÉPENDANTE (latence, = parcours segmenté).
//   B2 : S1 scatter 2 octets aléatoire dans table 2 Go et 4 Go : Go/s utiles.
//   B3 : S2 tri radix 32 bits (CUB) : GKeys/s.
//   B5 : scan de runs fusionné multi-r (r=2..10) streaming : éléments/s.
// p < 2^32 (p ≤ ~3×10⁹) -> arithmétique 32 bits, Montgomery R=2^32.
//
// Build : nvcc -O3 -gencode arch=compute_120,code=sm_120 \
//              -gencode arch=compute_120,code=compute_120 -o gpu_bench gpu_bench.cu
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cuda_runtime.h>
#include <cub/cub.cuh>

#define CK(x) do{ cudaError_t e=(x); if(e!=cudaSuccess){ \
  fprintf(stderr,"CUDA err %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(e)); exit(1);} }while(0)

// ---- Montgomery 32 bits (modulo n impair < 2^32) ---------------------------
__host__ __device__ __forceinline__ uint32_t montmul(uint32_t a,uint32_t b,uint32_t n,uint32_t ninv){
    uint64_t t=(uint64_t)a*b;
    uint32_t m=(uint32_t)t*ninv;            // mod 2^32
    uint64_t u=(t+(uint64_t)m*n)>>32;
    return (u>=n)?(uint32_t)(u-n):(uint32_t)u;
}
// ninv = -n^{-1} mod 2^32 (Newton)
static uint32_t mont_ninv(uint32_t n){
    uint32_t x=1; for(int i=0;i<5;i++) x*= (2u - n*x); return (uint32_t)(0u - x);
}

// ===================== B1 : chaîne mulmod DÉPENDANTE ========================
__global__ void k_b1(uint32_t n,uint32_t ninv,uint32_t g_mont,uint32_t* out,long iters){
    long tid=blockIdx.x*(long)blockDim.x+threadIdx.x;
    uint32_t x=(uint32_t)(tid% n)+1;
    #pragma unroll 4
    for(long i=0;i<iters;i++) x=montmul(x,g_mont,n,ninv);   // dépendance portée
    out[tid]=x;
}
static void B1(){
    uint32_t n=4294967291u;             // premier impair <2^32 (n impair = seule exigence Montgomery)
    uint32_t ninv=mont_ninv(n);
    // g en domaine Montgomery : g*R mod n ; on prend g=3, R=2^32
    uint32_t R2=(uint32_t)((( (unsigned __int128)1<<64)%n)); // R^2 mod n (32b: (2^64 mod n))
    uint32_t three_mont=montmul(3u,R2,n,ninv);
    int threads=256; long blocks=4096*4;   // ~4.2M threads pour saturer
    long N=blocks*threads; long iters=20000;
    uint32_t* d_out; CK(cudaMalloc(&d_out,N*sizeof(uint32_t)));
    k_b1<<<blocks,threads>>>(n,ninv,three_mont,d_out,200);  // warmup
    CK(cudaDeviceSynchronize());
    cudaEvent_t a,b; cudaEventCreate(&a); cudaEventCreate(&b);
    cudaEventRecord(a);
    k_b1<<<blocks,threads>>>(n,ninv,three_mont,d_out,iters);
    cudaEventRecord(b); CK(cudaEventSynchronize(b));
    float ms=0; cudaEventElapsedTime(&ms,a,b);
    double ops=(double)N*iters; double rate=ops/(ms/1e3);
    printf("B1 mulmod Montgomery 32b (chaine DEPENDANTE) : %.2f Gops/s  (%ld threads x %ld iters, %.1f ms)\n",
           rate/1e9,N,iters,ms);
    printf("   -> plafond du parcours segmente ~ %.2f x10^10 elements generes/s\n",rate/1e10);
    cudaFree(d_out);
}

// ===================== B2 : S1 scatter 2 octets =============================
__global__ void k_b2(uint16_t* tab,uint32_t P,uint32_t a,uint32_t bb,long N){
    long i=blockIdx.x*(long)blockDim.x+threadIdx.x;
    if(i>=N) return;
    uint32_t pos=(uint32_t)(((uint64_t)a*(uint32_t)i+bb)%P);  // permutation ~ aleatoire
    tab[pos]=(uint16_t)(i&0xFFFF);
}
static void B2_one(uint32_t P){
    size_t bytes=(size_t)P*sizeof(uint16_t);
    uint16_t* d_tab; CK(cudaMalloc(&d_tab,bytes));
    CK(cudaMemset(d_tab,0,bytes));
    long N=P; uint32_t a=1000000007u%P|1, bb=12345;
    int threads=256; long blocks=(N+threads-1)/threads;
    k_b2<<<blocks,threads>>>(d_tab,P,a,bb,N);  CK(cudaDeviceSynchronize()); // warmup
    cudaEvent_t e0,e1; cudaEventCreate(&e0); cudaEventCreate(&e1);
    cudaEventRecord(e0);
    for(int it=0;it<5;it++) k_b2<<<blocks,threads>>>(d_tab,P,a,bb,N);
    cudaEventRecord(e1); CK(cudaEventSynchronize(e1));
    float ms=0; cudaEventElapsedTime(&ms,e0,e1); ms/=5;
    double useful=(double)N*2.0/(ms/1e3);     // octets utiles/s (2 o/ecriture)
    double elem=(double)N/(ms/1e3);
    printf("B2 scatter 2o table %.1f Go : %.1f Go/s utiles, %.2f x10^10 el/s  (%.1f ms)\n",
           bytes/1e9, useful/1e9, elem/1e10, ms);
    cudaFree(d_tab);
}
static void B2(){ B2_one(1000000000u); B2_one(2000000000u); }  // 2 Go et 4 Go

// ===================== B3 : tri radix 32 bits (CUB) =========================
__global__ void k_fill(uint32_t* k,long N,uint32_t a,uint32_t b,uint32_t P){
    long i=blockIdx.x*(long)blockDim.x+threadIdx.x; if(i>=N)return;
    k[i]=(uint32_t)(((uint64_t)a*(uint32_t)i+b)%P);
}
static void B3(){
    long N=500000000;                  // 5e8 cles (2 Go cles + 2 Go out + temp)
    uint32_t *d_in,*d_out; CK(cudaMalloc(&d_in,N*4)); CK(cudaMalloc(&d_out,N*4));
    int threads=256; long blocks=(N+threads-1)/threads;
    k_fill<<<blocks,threads>>>(d_in,N,1000000007u,777u,4000000007u); CK(cudaDeviceSynchronize());
    void* d_tmp=nullptr; size_t tmp=0;
    cub::DeviceRadixSort::SortKeys(d_tmp,tmp,d_in,d_out,N);
    CK(cudaMalloc(&d_tmp,tmp));
    cub::DeviceRadixSort::SortKeys(d_tmp,tmp,d_in,d_out,N); CK(cudaDeviceSynchronize()); //warmup
    cudaEvent_t e0,e1; cudaEventCreate(&e0); cudaEventCreate(&e1);
    cudaEventRecord(e0);
    cub::DeviceRadixSort::SortKeys(d_tmp,tmp,d_in,d_out,N);
    cudaEventRecord(e1); CK(cudaEventSynchronize(e1));
    float ms=0; cudaEventElapsedTime(&ms,e0,e1);
    printf("B3 tri radix 32b CUB : %.1f GKeys/s  (N=%.1e, tmp=%.2f Go, %.1f ms)\n",
           (double)N/(ms/1e3)/1e9, (double)N, tmp/1e9, ms);
    cudaFree(d_in); cudaFree(d_out); cudaFree(d_tmp);
}

// ===================== B5 : scan de runs fusionné multi-r ====================
// val16 = ind mod 2520 ; color_r = val16 % r ; compte les frontieres de run
// (color[i]!=color[i-1]) pour r=2..10 en UNE passe streaming. Mesure el/s.
__global__ void k_fillval(uint16_t* v,long N){ long i=blockIdx.x*(long)blockDim.x+threadIdx.x; if(i<N) v[i]=(uint16_t)(i%2520); }
__global__ void k_b5(const uint16_t* val,long N,unsigned long long* boundaries){
    long i=blockIdx.x*(long)blockDim.x+threadIdx.x;
    if(i<1||i>=N) return;
    uint16_t v=val[i], w=val[i-1];
    unsigned cnt=0;
    #pragma unroll
    for(int r=2;r<=10;r++) cnt += ((v%r)!=(w%r));
    if((i&1023)==0) atomicAdd(boundaries,(unsigned long long)cnt); // echantillon (eviter contention)
}
static void B5(){
    long N=1000000000;                 // 1e9 elements (2 Go val16)
    uint16_t* d_val; CK(cudaMalloc(&d_val,(size_t)N*2));
    k_fillval<<<(N+255)/256,256>>>(d_val,N);   // val16 = i mod 2520
    CK(cudaDeviceSynchronize());
    unsigned long long* d_b; CK(cudaMalloc(&d_b,8)); CK(cudaMemset(d_b,0,8));
    int threads=256; long blocks=(N+threads-1)/threads;
    k_b5<<<blocks,threads>>>(d_val,N,d_b); CK(cudaDeviceSynchronize()); //warmup
    cudaEvent_t e0,e1; cudaEventCreate(&e0); cudaEventCreate(&e1);
    cudaEventRecord(e0);
    for(int it=0;it<5;it++) k_b5<<<blocks,threads>>>(d_val,N,d_b);
    cudaEventRecord(e1); CK(cudaEventSynchronize(e1));
    float ms=0; cudaEventElapsedTime(&ms,e0,e1); ms/=5;
    printf("B5 scan runs fusionne multi-r (r=2..10) : %.2f x10^10 el/s  (N=%.1e, %.1f ms)\n",
           (double)N/(ms/1e3)/1e10,(double)N,ms);
    cudaFree(d_val); cudaFree(d_b);
}

int main(int argc,char**argv){
    int dev=0; cudaDeviceProp pr; CK(cudaGetDeviceProperties(&pr,dev));
    printf("=== T2 GPU bench : %s, sm_%d%d, %.1f Go, CUDA runtime ===\n",
           pr.name,pr.major,pr.minor,pr.totalGlobalMem/1e9);
    printf("(ordre B1 -> B2 -> B3 -> B5 ; tables B2 a 2/4 Go)\n\n");
    B1();
    printf("\n"); B2();
    printf("\n"); B3();
    printf("\n"); B5();
    printf("\n[note] B2 ~6%% d'efficacite secteur (2o/32o) attendu = normal, pas un bug.\n");
    return 0;
}
