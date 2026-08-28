#!/usr/bin/env python3
# campaign.py — orchestrateur de campagne VDW-GPU (gate 2026-07-02).
#
# Découpe [lo,hi] en chunks de premiers CROISSANTS, restartables ; par chunk :
#   scan_gpu --scan lo hi  -> count/max_p/bound par cible (r,k) + CHECKSUM + candidats.
# Checkpoint JSON atomique (chunks faits + agrégats) -> reprise après pause/crash.
# Walltime/chunk borné. Log par chunk (cmd, durée, checksum, git rev). Cross-check
# périodique (validation 3-voies). Comparaison avec la fermeture automatique des
# baselines : champions directs de Rabung et candidats records généraux sont
# distingués, puis marqués pour confirmation (règle 1/3 ; PAS annoncés ici).
#
# NB : le premier chunk de campagne attend le choix humain de X (gate). Ce script
# est prêt ; --dry teste sur un petit intervalle sans engager la campagne.
#
# Usage : campaign.py --lo 970000000 --hi 2000000000 --chunk 2000000 --out results/campaign
#         campaign.py --dry   (test [1e6,1.02e6], chunks 1e4)
import argparse, json, os, subprocess, sys, time, hashlib, math, re, shutil

HERE=os.path.dirname(os.path.abspath(__file__))
SCAN=os.path.join(HERE,"scan_gpu")
REPO_ROOT=os.path.dirname(HERE)
BOUNDS_CLOSURE_PATH=os.path.join(REPO_ROOT,"audit","generated","bounds_closure.json")

# --- L1 : garde disque bloquante (suite incident 62 Go) : PAUSE + alerte, PAS de crash ---
DISK_MIN_GB=10.0
def free_gb(path):
    try: return shutil.disk_usage(path).free/1e9
    except Exception: return 999.0
def wait_disk(path,min_gb,L,tag=""):
    """Bloque tant que l'espace libre < min_gb (alerte re-loggée toutes les ~5 min).
       Reprend automatiquement dès libération. Ne crashe jamais (règle L1)."""
    n=0
    while free_gb(path)<min_gb:
        if n%5==0: L(f"!! GARDE DISQUE {tag} : libre={free_gb(path):.1f}Go < {min_gb}Go -> PAUSE (liberer ; reprise auto)")
        n+=1; time.sleep(60)
    if n: L(f"   garde disque {tag} : espace OK ({free_gb(path):.1f}Go) -> reprise")
# --- baselines fermees (C4) ---
def load_closed_baselines(path=BOUNDS_CLOSURE_PATH):
    """Charge les meilleures bornes ordinaires et leur graphe de provenance.

    La fermeture est produite par l'outil d'audit ; la campagne refuse un fichier
    incoherent au lieu de retomber sur une table codee en dur et potentiellement
    perimee. Les bornes directes de Rabung sont indexees separement pour ne jamais
    confondre champion de methode et record general.
    """
    with open(path,"rb") as f: raw=f.read()
    data=json.loads(raw)
    if data.get("notation")!="W(colors,length) > lower_bound":
        raise ValueError(f"notation inattendue dans {path}")
    nodes={n["id"]:n for n in data.get("nodes",[]) if "id" in n}
    general={}
    for winner in data.get("winners",[]):
        node=nodes.get(winner.get("node_id"))
        if node is None or node.get("kind")!="ordinary":
            raise ValueError(f"winner sans noeud ordinaire valide dans {path}: {winner}")
        if int(node["lower_bound"])!=int(winner["lower_bound"]):
            raise ValueError(f"winner incoherent avec son noeud dans {path}: {winner}")
        key=(int(winner["colors"]),int(winner["length"]))
        general[key]={
            "lower_bound":int(winner["lower_bound"]),
            "method":winner["method"],
            "node_id":winner["node_id"],
            "source":node.get("source"),
        }
    direct={}
    for node in nodes.values():
        if node.get("kind")!="ordinary" or node.get("method")!="direct_rabung": continue
        key=(int(node["colors"]),int(node["length"]))
        entry={"lower_bound":int(node["lower_bound"]),"method":"direct_rabung",
               "node_id":node["id"],"source":node.get("source")}
        if key not in direct or entry["lower_bound"]>direct[key]["lower_bound"]: direct[key]=entry
    if not general:
        raise ValueError(f"aucune baseline generale dans {path}")
    return {"general":general,"direct_rabung":direct,
            "schema_version":data.get("schema_version"),
            "sha256":hashlib.sha256(raw).hexdigest(),"path":os.path.abspath(path)}

def classify_bound(baselines,r,k,bound):
    """Classe une borne directe relativement aux baselines fermees."""
    key=(r,k)
    general=baselines["general"].get(key)
    direct=baselines["direct_rabung"].get(key)
    if general is None or direct is None:
        missing=[]
        if general is None: missing.append("general")
        if direct is None: missing.append("direct_rabung")
        raise KeyError(f"baseline {','.join(missing)} absente pour (r={r},k={k})")
    return {
        "direct_rabung_family_champion":bound>direct["lower_bound"],
        "general_record_candidate":bound>general["lower_bound"],
        "direct_rabung_baseline":direct,
        "general_closed_baseline":general,
    }

def candidate_record(baselines,r,k,p,bound,chunk):
    classification=classify_bound(baselines,r,k,bound)
    if not (classification["direct_rabung_family_champion"] or
            classification["general_record_candidate"]):
        return None
    return {"r":r,"k":k,"p":p,"bound":bound,"chunk":chunk,
            "status":"A_CONFIRMER_PF1ii",**classification}
# --- LOI NUE (U2, remplace le Gumbel §5bis perime) : P(valide)=exp(-Lam),
#     Lam=p(r-1)/(2 r^k) = #runs mono de longueur k attendus (n_eff=(p-1)/2, miroir). ---
PHI={2:1,3:2}
def v_model(p,r,k):
    return math.exp(-p*(r-1)/(2.0*r**k))
def lambda_chunk(r,k,lo,hi,steps=40):
    if r not in PHI: return 0.0
    s=0.0; dp=(hi-lo)/steps
    for i in range(steps):
        p=lo+(i+0.5)*dp; s+=v_model(p,r,k)/(PHI[r]*math.log(p))*dp
    return s
def sump(a,b):  # Sigma_{p in [a,b]} p ~ (b^2-a^2)/(2 ln b)  (travail, C2)
    return max(0.0,(b*b-a*a)/(2*math.log(max(b,3))))
_VALIDATE_PASS_RE=re.compile(
    r"^VERDICT\s*:\s*ACCORD 100% \(V2a/V2b \+ B7 \+ tri \+ CPU concordants\)"
    r"\s+\([0-9]+(?:\.[0-9]+)?s\)\s*$"
)
_XCHECK_PASS_RE=re.compile(
    r"^XCHECK \[[0-9]+,[0-9]+\] [0-9]+ prem\. : [0-9]+ comp\. ; "
    r"V2a/Jacobi vs CPU desaccords=0 -> ACCORD ; "
    r"B7plein desaccords=0 -> ACCORD\s*$"
)
_NEGATIVE_VERDICT_RE=re.compile(r"\b(?:DIFF|FAIL|ECHEC|WARN)\b",re.IGNORECASE)
CAMPAIGN_TARGETS={
    (2,25),(2,26),(2,27),(2,28),
    (3,17),(3,18),(3,19),(3,20),(3,21),(3,22),(3,23),(3,24),(3,25),
}
_SCAN_HEADER_RE=re.compile(r"^# SCAN \[([0-9]+),([0-9]+)\] : ([0-9]+) premiers$")
_TARGET_RE=re.compile(
    r"^TARGET r=([0-9]+) k=([0-9]+) "
    r"A_count=([0-9]+) A_max_p=([0-9]+) A_bound=([0-9]+) "
    r"AB_count=([0-9]+) AB_max_p=([0-9]+) AB_bound=([0-9]+) "
    r"Bstar_reject=([0-9]+)$"
)
_CHECKSUM_RE=re.compile(r"^CHECKSUM_(A|AB) ([0-9]+)$")
_CANDIDATES_RE=re.compile(r"^CANDIDATS_(A|AB) r=([0-9]+) k=([0-9]+) :(.*)$")
_COLQ_RE=re.compile(r"^COLQ r=([0-9]+) k=([0-9]+) cnt_AB=([0-9]+) :(.*)$")
_HISTO_RE=re.compile(r"^HISTO r=([0-9]+) :(.*)$")
_TOP_RE=re.compile(r"^TOP r=([0-9]+) :(.*)$")

def crosscheck_pass(process,mode):
    """Exige rc=0 et une unique ligne de succes structuree, sans verdict negatif."""
    stdout=process.stdout or ""; stderr=process.stderr or ""
    if process.returncode!=0: return False,f"returncode={process.returncode}"
    if _NEGATIVE_VERDICT_RE.search(stdout+"\n"+stderr): return False,"verdict negatif dans la sortie"
    matcher={"validate":_VALIDATE_PASS_RE,"xcheck":_XCHECK_PASS_RE}.get(mode)
    if matcher is None: raise ValueError(f"mode de cross-check inconnu: {mode}")
    matches=[line for line in stdout.splitlines() if matcher.fullmatch(line.strip())]
    if len(matches)!=1: return False,f"lignes de succes structurees={len(matches)}"
    return True,"ok"

def _strict_uint_list(text,label):
    tokens=text.split()
    if any(not token.isdecimal() for token in tokens):
        raise RuntimeError(f"{label}: liste entiere mal formee")
    return [int(token) for token in tokens]

def parse_scan_output(stdout,stderr,lo,hi):
    """Parse une sortie --scan complete; toute omission ou ambiguite est fatale."""
    stdout=stdout or ""; stderr=stderr or ""
    if _NEGATIVE_VERDICT_RE.search(stdout+"\n"+stderr):
        raise RuntimeError("sortie --scan contenant un verdict negatif")
    headers=[]; targets={}; checksums={}; candidates={"A":{},"AB":{}}
    histo={}; top={}; colq={}
    for line in stdout.splitlines():
        line=line.strip()
        if not line: continue
        match=_SCAN_HEADER_RE.fullmatch(line)
        if match:
            headers.append(tuple(map(int,match.groups())))
            continue
        match=_TARGET_RE.fullmatch(line)
        if match:
            values=list(map(int,match.groups())); key=(values[0],values[1])
            if key in targets: raise RuntimeError(f"TARGET duplique {key}")
            targets[key]={
                "count_a":values[2],"max_p_a":values[3],"bound_a":values[4],
                "count":values[5],"max_p":values[6],"bound":values[7],
                "bstar_reject":values[8],"criterion":"AB",
            }
            continue
        match=_CHECKSUM_RE.fullmatch(line)
        if match:
            name,value=match.group(1),int(match.group(2))
            if name in checksums or value >= 1<<64:
                raise RuntimeError(f"CHECKSUM_{name} duplique ou hors u64")
            checksums[name]=value
            continue
        match=_CANDIDATES_RE.fullmatch(line)
        if match:
            family=match.group(1); key=(int(match.group(2)),int(match.group(3)))
            if key in candidates[family]:
                raise RuntimeError(f"CANDIDATS_{family} duplique {key}")
            candidates[family][key]=_strict_uint_list(match.group(4),f"CANDIDATS_{family} {key}")
            continue
        match=_COLQ_RE.fullmatch(line)
        if match:
            key=(int(match.group(1)),int(match.group(2)))
            if key in colq: raise RuntimeError(f"COLQ duplique {key}")
            colq[key]=(int(match.group(3)),_strict_uint_list(match.group(4),f"COLQ {key}"))
            continue
        match=_HISTO_RE.fullmatch(line)
        if match:
            r=int(match.group(1))
            if r in histo: raise RuntimeError(f"HISTO duplique r={r}")
            histo[r]=_strict_uint_list(match.group(2),f"HISTO r={r}")
            if len(histo[r])!=64: raise RuntimeError(f"HISTO r={r}: 64 bins requis")
            continue
        match=_TOP_RE.fullmatch(line)
        if match:
            r=int(match.group(1)); entries=match.group(2).split()
            if r in top or any(not re.fullmatch(r"[0-9]+:[0-9]+",item) for item in entries):
                raise RuntimeError(f"TOP mal forme ou duplique r={r}")
            top[r]=[tuple(map(int,item.split(":"))) for item in entries]
            continue
        raise RuntimeError(f"ligne --scan inconnue: {line[:160]}")

    if len(headers)!=1 or headers[0][:2]!=(lo,hi):
        raise RuntimeError(f"en-tete --scan absent, duplique ou hors plage: {headers}")
    prime_count=headers[0][2]
    if set(targets)!=CAMPAIGN_TARGETS:
        raise RuntimeError(
            f"ensemble TARGET incorrect: missing={sorted(CAMPAIGN_TARGETS-set(targets))}, "
            f"extra={sorted(set(targets)-CAMPAIGN_TARGETS)}"
        )
    if set(checksums)!={"A","AB"}:
        raise RuntimeError(f"checksums incomplets: {sorted(checksums)}")

    for (r,k),values in targets.items():
        if values["count"]>values["count_a"] or values["count_a"]>prime_count:
            raise RuntimeError(f"TARGET {(r,k)}: comptes impossibles")
        if values["bstar_reject"]!=values["count_a"]-values["count"]:
            raise RuntimeError(f"TARGET {(r,k)}: Bstar_reject incoherent")
        for suffix in ("_a",""):
            count=values["count"+suffix]; max_p=values["max_p"+suffix]
            bound=values["bound"+suffix]
            if count==0:
                if max_p!=0 or bound!=0:
                    raise RuntimeError(f"TARGET {(r,k)}: zero avec maximum/borne non nuls")
            elif not (lo<=max_p<hi) or bound!=(k-1)*max_p+1:
                raise RuntimeError(f"TARGET {(r,k)}: maximum ou borne incoherent")

    listed_targets={(2,25),(3,17)}
    for family,count_key,max_key in (("A","count_a","max_p_a"),("AB","count","max_p")):
        if set(candidates[family])-listed_targets:
            raise RuntimeError(f"CANDIDATS_{family}: cible inattendue")
        for key in listed_targets:
            values=candidates[family].get(key,[]); target=targets[key]
            if len(values)!=target[count_key]:
                raise RuntimeError(f"CANDIDATS_{family} {key}: compte incoherent")
            if values!=sorted(set(values)) or any(not lo<=p<hi for p in values):
                raise RuntimeError(f"CANDIDATS_{family} {key}: liste non canonique")
            if values and values[-1]!=target[max_key]:
                raise RuntimeError(f"CANDIDATS_{family} {key}: maximum incoherent")
    for key in listed_targets:
        if not set(candidates["AB"].get(key,[])).issubset(candidates["A"].get(key,[])):
            raise RuntimeError(f"CANDIDATS_AB {key}: pas un sous-ensemble de A")

    if set(colq)!=CAMPAIGN_TARGETS:
        raise RuntimeError("ensemble COLQ incomplet ou inattendu")
    for key,(reported_count,values) in colq.items():
        if reported_count!=targets[key]["count"] or len(values)!=6:
            raise RuntimeError(f"COLQ {key}: denominateur ou largeur incoherent")
        if any(value>reported_count for value in values):
            raise RuntimeError(f"COLQ {key}: compteur superieur au denominateur")

    expected_diagnostics=set(range(2,10))
    if set(histo)!=expected_diagnostics or set(top)!=expected_diagnostics:
        raise RuntimeError(
            "diagnostics HISTO/TOP incomplets: "
            f"histo={sorted(histo)}, top={sorted(top)}"
        )
    for r in sorted(expected_diagnostics):
        total=sum(histo[r]); entries=top[r]
        if total>prime_count:
            raise RuntimeError(f"HISTO r={r}: total {total} > nombre de premiers {prime_count}")
        if len(entries)!=min(20,total):
            raise RuntimeError(
                f"TOP r={r}: {len(entries)} entrees pour un histogramme de total {total}"
            )
        primes=[p for p,_ in entries]
        if len(primes)!=len(set(primes)) or any(not lo<=p<hi for p in primes):
            raise RuntimeError(f"TOP r={r}: premiers dupliques ou hors plage")
        if entries!=sorted(entries,key=lambda item:(-item[1],item[0])):
            raise RuntimeError(f"TOP r={r}: ordre non canonique")
        top_bins=[0]*64
        for _,maxrun in entries:
            if maxrun<1:
                raise RuntimeError(f"TOP r={r}: maxrun invalide")
            top_bins[min(maxrun,63)]+=1
        if any(top_bins[index]>histo[r][index] for index in range(64)):
            raise RuntimeError(f"TOP r={r}: profils absents de HISTO")
        remaining=min(20,total); expected_top_bins=[]
        for index in range(63,-1,-1):
            take=min(histo[r][index],remaining)
            expected_top_bins.extend([index]*take); remaining-=take
            if not remaining: break
        actual_top_bins=[min(maxrun,63) for _,maxrun in entries]
        if actual_top_bins!=expected_top_bins:
            raise RuntimeError(f"TOP r={r}: ne correspond pas aux plus grands bins de HISTO")
    for (r,k),values in targets.items():
        expected_count_a=sum(histo[r][:min(k,64)])
        if values["count_a"]!=expected_count_a:
            raise RuntimeError(
                f"TARGET {(r,k)}: A_count={values['count_a']} mais HISTO implique "
                f"{expected_count_a}"
            )

    return (
        targets,checksums["A"],checksums["AB"],
        {f"{r},{k}":v for (r,k),v in candidates["A"].items()},
        {f"{r},{k}":v for (r,k),v in candidates["AB"].items()},
        histo,{r:[f"{p}:{maxrun}" for p,maxrun in entries] for r,entries in top.items()},
        {f"{r},{k}":v for (r,k),(n,v) in colq.items()},
    )

def git_rev():
    try: return subprocess.check_output(["git","-C",HERE,"rev-parse","--short","HEAD"],stderr=subprocess.DEVNULL).decode().strip()
    except Exception: return "N/A"

def gpu_status():
    try:
        o=subprocess.check_output(["nvidia-smi","--query-gpu=temperature.gpu,power.draw,clocks.sm,memory.used",
            "--format=csv,noheader,nounits"],stderr=subprocess.DEVNULL,timeout=30).decode().strip().split(",")
        return f"GPU {o[0].strip()}C {float(o[1]):.0f}W SM {o[2].strip()}MHz VRAM {o[3].strip()}MiB"
    except Exception as e: return f"GPU n/a ({e})"

def run_scan(lo,hi,walltime):
    t0=time.time()
    p=subprocess.run([SCAN,"--scan",str(lo),str(hi)],capture_output=True,timeout=walltime)
    dt=time.time()-t0
    try:
        stdout=p.stdout.decode("utf-8")
        stderr=p.stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"sortie --scan non UTF-8: {exc}") from exc
    if p.returncode!=0: raise RuntimeError(f"scan_gpu rc={p.returncode}\n{stderr[-500:]}")
    parsed=parse_scan_output(stdout,stderr,lo,hi)
    targets,checksum,checksum_ab,cands,cands_ab,histo,top,colq=parsed
    return targets,checksum,checksum_ab,cands,cands_ab,dt,histo,top,colq,p.stdout,p.stderr

def load_ckpt(path):
    # GARDE (audit 2026-07-06) : checkpoint corrompu (coupure courant, erreur disque) ->
    # fallback sur la copie .bak (ecrite a chaque save) au lieu de crash au redemarrage.
    for cand in (path, path+".bak"):
        if os.path.exists(cand):
            try:
                with open(cand) as f: ck=json.load(f)
                if cand!=path: print(f"[ckpt] ATTENTION: {path} illisible, repris depuis {cand}")
                return ck
            except (json.JSONDecodeError,OSError) as e:
                print(f"[ckpt] {cand} illisible ({e}) -> essai suivant")
    return {"done":{}, "agg":{}, "records":[]}

def canonical_campaign_config(lo,hi,chunk,out):
    """Identite stable de la campagne a laquelle un checkpoint appartient."""
    if not isinstance(lo,int) or not isinstance(hi,int) or not isinstance(chunk,int):
        raise ValueError("geometrie de campagne non entiere")
    if lo<0 or hi<=lo or chunk<=0:
        raise ValueError(f"geometrie de campagne invalide: lo={lo}, hi={hi}, chunk={chunk}")
    absolute=os.path.realpath(os.path.abspath(out))
    relative=os.path.relpath(absolute,REPO_ROOT)
    logical_out=relative if relative != ".." and not relative.startswith(".."+os.sep) else absolute
    return {
        "schema_version":1,
        "interval":"half-open",
        "lo":lo,"hi":hi,"chunk":chunk,
        "out":logical_out.replace(os.sep,"/"),
        "criterion":"AB",
        "targets":[f"{r},{k}" for r,k in sorted(CAMPAIGN_TARGETS)],
    }

def campaign_chunk_keys(config):
    return [f"{lo}-{min(lo+config['chunk'],config['hi'])}"
            for lo in range(config["lo"],config["hi"],config["chunk"])]

def resolve_output_path(out,dry,lo,hi,chunk):
    if out: return out
    smoke=(lo,hi,chunk)==(1_000_000,1_020_000,10_000)
    return "results/campaign-dry" if dry or smoke else "results/campaign"

def validate_resume_checkpoint(ck,expected_config):
    """Refuse toute reprise dont la geometrie, les chunks ou le critere divergent."""
    if not isinstance(ck.get("done",{}),dict) or not isinstance(ck.get("agg",{}),dict):
        raise RuntimeError("checkpoint mal forme")
    existing_config=ck.get("campaign_config")
    if existing_config is not None and existing_config!=expected_config:
        raise RuntimeError(
            "checkpoint lie a une autre campagne; utiliser un autre --out "
            f"(attendu={expected_config}, trouve={existing_config})"
        )
    if not ck["done"] and not ck["agg"]:
        if existing_config not in (None,expected_config):
            raise RuntimeError("checkpoint vide mais configuration incompatible")
        return
    if existing_config is None:
        raise RuntimeError(
            "checkpoint non vide sans campaign_config: reprise refusee; "
            "reconstruire depuis les sorties brutes dans un nouveau --out"
        )
    legacy_done=[key for key,value in ck["done"].items()
                 if not isinstance(value,dict) or value.get("criterion")!="AB"
                 or value.get("checksum_ab") is None]
    legacy_agg=[key for key,value in ck["agg"].items()
                if not isinstance(value,dict) or value.get("criterion")!="AB"
                or "count_a" not in value]
    if legacy_done or legacy_agg:
        raise RuntimeError(
            "checkpoint historique A-only incompatible avec une reprise AB; "
            "une migration est impossible sans les sorties brutes "
            f"(done={legacy_done[:3]}, agg={legacy_agg[:3]})"
        )
    canonical=campaign_chunk_keys(expected_config)
    done_keys=set(ck["done"])
    expected_prefix=set(canonical[:len(done_keys)])
    if done_keys!=expected_prefix:
        raise RuntimeError(
            "chunks checkpointes hors geometrie ou non prefixiels: "
            f"trouve={sorted(done_keys)[:3]}, prefixe_attendu={canonical[:len(done_keys)][:3]}"
        )
    allowed_targets=set(expected_config["targets"])
    aggregate_targets=set(ck["agg"])
    if not done_keys and aggregate_targets:
        raise RuntimeError("checkpoint sans chunk termine mais avec agregats")
    if done_keys and aggregate_targets!=allowed_targets:
        raise RuntimeError(
            "ensemble d'agregats incomplet ou inattendu: "
            f"missing={sorted(allowed_targets-aggregate_targets)}, "
            f"extra={sorted(aggregate_targets-allowed_targets)}"
        )

def write_raw_artifact(path,data):
    os.makedirs(os.path.dirname(path),exist_ok=True)
    tmp=path+".tmp"
    with open(tmp,"wb") as handle:
        handle.write(data); handle.flush(); os.fsync(handle.fileno())
    os.replace(tmp,path)
    return {"path":path,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}

def save_ckpt(path,ck):
    tmp=path+".tmp"
    with open(tmp,"w") as f:
        json.dump(ck,f,indent=1)
        f.flush(); os.fsync(f.fileno())   # GARDE : flush disque avant rename (coupure courant)
    if os.path.exists(path):
        try: os.replace(path,path+".bak")  # generation precedente = copie de secours
        except OSError: pass
    os.replace(tmp,path)   # atomique

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--lo",type=int,default=1000000); ap.add_argument("--hi",type=int,default=1020000)
    ap.add_argument("--chunk",type=int,default=10000); ap.add_argument("--out",default=None)
    ap.add_argument("--walltime",type=int,default=7200); ap.add_argument("--xcheck-every",type=int,default=50)
    ap.add_argument("--backup",default="",help="PF4 : dir de sauvegarde hors-machine (rsync checkpoints au hook de chunk)")
    ap.add_argument("--dry",action="store_true")
    a=ap.parse_args()
    if a.dry: a.lo,a.hi,a.chunk=1000000,1020000,10000
    a.out=resolve_output_path(a.out,a.dry,a.lo,a.hi,a.chunk)
    baselines=load_closed_baselines()
    os.makedirs(a.out,exist_ok=True)
    ckpath=os.path.join(a.out,"checkpoint.json"); logpath=os.path.join(a.out,"campaign.log")
    campaign_config=canonical_campaign_config(a.lo,a.hi,a.chunk,a.out)
    ck=load_ckpt(ckpath); validate_resume_checkpoint(ck,campaign_config); rev=git_rev()
    ck["campaign_config"]=campaign_config
    # Migration/reprise : reconstruire les classifications depuis les agrégats. Cela
    # élimine notamment les anciens faux "records" qui ne battaient qu'un tally direct.
    rb0={}
    for k,ag in ck.get("agg",{}).items():
        r,kk=int(k.split(",")[0]),int(k.split(",")[1])
        if ag.get("max_p",0)>0:
            rec=candidate_record(baselines,r,kk,ag["max_p"],ag.get("bound",0),"(reprise agg)")
            if rec: rb0[k]=rec
    ck["record_best"]=rb0
    ck["baseline_closure"]={"path":os.path.relpath(baselines["path"],REPO_ROOT),
                            "sha256":baselines["sha256"],
                            "schema_version":baselines["schema_version"]}
    ck["_sess"]={"n":0,"sum":0.0,"work":0.0}   # reset debit/ETA a la session courante (robuste restart)
    # Lie le repertoire a cette geometrie avant le premier calcul. Une autre
    # invocation (dry run compris) echouera donc avant de melanger ses agregats.
    save_ckpt(ckpath,ck)
    log=open(logpath,"a")
    def L(m): print(m); log.write(m+"\n"); log.flush()
    L(f"# campagne git={rev} range=[{a.lo},{a.hi}] chunk={a.chunk} demarrage/{'reprise' if ck['done'] else 'neuf'} @{int(time.time())}")
    L(f"# baselines fermees={ck['baseline_closure']['path']} sha256={baselines['sha256']}")
    nchunks=(a.hi-a.lo+a.chunk-1)//a.chunk; ci=0
    for lo in range(a.lo,a.hi,a.chunk):
        hi=min(lo+a.chunk,a.hi); key=f"{lo}-{hi}"; ci+=1
        if key in ck["done"]: continue
        wait_disk(a.out,DISK_MIN_GB,L,tag=f"@chunk {ci}")   # L1 : garde avant chaque chunk
        try:
            tg,cs,cs_ab,cands,cands_ab,dt,histo,top,colq,raw_stdout,raw_stderr=run_scan(lo,hi,a.walltime)
        except Exception as e:
            L(f"!! ECHEC chunk {key}: {e}  -> FREEZE (pas de checkpoint de ce chunk)"); sys.exit(1)
        chunk_dir=os.path.join(a.out,"chunks",key)
        raw_meta={
            "stdout":write_raw_artifact(os.path.join(chunk_dir,"scan.stdout"),raw_stdout),
            "stderr":write_raw_artifact(os.path.join(chunk_dir,"scan.stderr"),raw_stderr),
        }
        # Artefacts derives par chunk. Chaque fichier est remplace atomiquement au
        # rejeu du meme chunk: aucune fenetre append/checkpoint ne peut creer de doublon.
        if histo:
            payload="".join(f"r={r} "+" ".join(map(str,histo[r]))+"\n" for r in sorted(histo))
            write_raw_artifact(os.path.join(chunk_dir,"histo.txt"),payload.encode("utf-8"))
        for r in sorted(top):
            payload=f"# chunk {lo}-{hi}\n"+"\n".join(str(entry) for entry in top[r])+"\n"
            write_raw_artifact(os.path.join(chunk_dir,f"tail_r{r}.txt"),payload.encode("utf-8"))
        crit=next(iter(tg.values())).get("criterion","A") if tg else "A"
        rb=ck.setdefault("record_best",{})
        chunk_counts={}; chunk_counts_a={}
        for rk,v in tg.items():
            k=f"{rk[0]},{rk[1]}"; ag=ck["agg"].get(k,{"count":0,"max_p":0,"bound":0})
            # count/max_p/bound = critere COMPLET (a)^(b) si le scanner le fournit ; les champs
            # _a preservent la statistique A-only, seule comparable aux agregats d'avant 07-25.
            ag["count"]+=v["count"]; chunk_counts[k]=v["count"]
            ag["count_a"]=ag.get("count_a",0)+v["count_a"]; chunk_counts_a[k]=v["count_a"]
            ag["bstar_reject"]=ag.get("bstar_reject",0)+v["bstar_reject"]
            ag["criterion"]=v.get("criterion","A")
            if v["max_p_a"]>ag.get("max_p_a",0): ag["max_p_a"]=v["max_p_a"]
            if v["max_p"]>ag["max_p"]: ag["max_p"]=v["max_p"]; ag["bound"]=v["bound"]
            cq=colq.get(k)                    # O1/mélange : agrège col_r(q)=0 (6 val.) + dénominateur apparié
            if cq:
                ag["colq0"]=[x+y for x,y in zip(ag.get("colq0",[0]*len(cq)),cq)]
                ag["colq_n"]=ag.get("colq_n",0)+v["count"]   # count SUR les chunks colq -> f_q=colq0/colq_n
            ck["agg"][k]=ag
            # C4 : un champion direct peut rester domine par une recurrence. Les deux
            # statuts sont calcules et publies explicitement depuis la meme fermeture.
            if v["max_p"]>0:
                rec=candidate_record(baselines,rk[0],rk[1],v["max_p"],v["bound"],key)
                if rec and v["bound"]>rb.get(k,{}).get("bound",0):
                    rb[k]=rec
                    if rec["direct_rabung_family_champion"]:
                        b=rec["direct_rabung_baseline"]
                        L(f"** direct_rabung_family_champion (r={rk[0]},k={rk[1]}) bound={v['bound']} > {b['lower_bound']} [{b['node_id']}] p={v['max_p']} -> PF1(ii) requise")
                    if rec["general_record_candidate"]:
                        b=rec["general_closed_baseline"]
                        L(f"** general_record_candidate (r={rk[0]},k={rk[1]}) bound={v['bound']} > {b['lower_bound']} [{b['method']}:{b['node_id']}] p={v['max_p']} -> PF1(ii) requise")
        # Listes par chunk: A-only et critere complet AB restent separees. Une
        # aggregation ulterieure doit lire ces fichiers dans l'ordre des chunks.
        for name,values in (("valid_3_17_a.txt",cands.get("3,17",[])),
                            ("valid_3_17_ab.txt",cands_ab.get("3,17",[]))):
            payload=("\n".join(str(x) for x in values)+("\n" if values else "")).encode("utf-8")
            write_raw_artifact(os.path.join(chunk_dir,name),payload)
        # C4 : sanity emboitement (3,17)<=(3,18)<=...<=(3,25). L'invariant n'est PROUVE que
        # pour (a) seule (maxrun<k est monotone en k) ; (b) depend aussi de k, donc le test
        # reste porte par les comptes A-only, sinon il produirait de fausses alertes.
        nest=[chunk_counts_a.get(f"3,{k}",0) for k in range(17,26)]
        nest_ok=all(nest[i]<=nest[i+1] for i in range(len(nest)-1))
        if not nest_ok:
            L(f"!! SANITY emboitement (3,17..25) VIOLE @chunk {ci} : {nest} -> FREEZE")
            sys.exit(2)

        # Cross-check avant de rendre le chunk visible dans le checkpoint. Toute
        # exception, expiration ou divergence bloque la campagne et force le rejeu.
        if a.xcheck_every and ci % a.xcheck_every == 0:
            try:
                if lo <= 1_700_000_000:
                    r=subprocess.run([SCAN,"--validate","60000"],capture_output=True,text=True,timeout=900)
                    okx,xreason=crosscheck_pass(r,"validate")
                else:
                    r=subprocess.run([SCAN,"--xcheck",str(lo),str(hi),"6"],capture_output=True,text=True,timeout=1200)
                    okx,xreason=crosscheck_pass(r,"xcheck")
            except Exception as exc:
                L(f"!! xcheck ERREUR @chunk {ci} ({type(exc).__name__}) -> FREEZE; chunk non checkpointé")
                sys.exit(2)
            if not okx:
                L(f"!! CROSS-CHECK ECHEC @chunk {ci} ({xreason}) -> FREEZE; chunk non checkpointé\nSTDOUT:\n{(r.stdout or '')[-400:]}\nSTDERR:\n{(r.stderr or '')[-400:]}")
                sys.exit(2)
            ck["_xcheck_n"]=ck.get("_xcheck_n",0)+1
            ck["_xcheck"]=f"pass {ck['_xcheck_n']}"
            L(f"cross-check OK @chunk {ci} (#{ck['_xcheck_n']})")

        ck["done"][key]={
            "checksum":cs,"checksum_ab":cs_ab,"criterion":crit,
            "dt":round(dt,1),"rev":rev,
            "raw":{
                stream:{**meta,"path":os.path.relpath(meta["path"],a.out)}
                for stream,meta in raw_meta.items()
            },
        }
        save_ckpt(ckpath,ck)
        # C2 : ETA par TRAVAIL restant (Sigma p), pas par compte de chunks.
        sess=ck.setdefault("_sess",{})
        for _kk in ("n","sum","work"): sess.setdefault(_kk,0.0)   # robuste au restart (ancien _sess sans 'work')
        sess["n"]+=1; sess["sum"]+=dt; sess["work"]+=sump(lo,hi); rate=sess["work"]/sess["sum"] if sess["sum"] else 1
        eta_w=sump(hi,a.hi)/rate if rate else 0                       # travail restant / debit
        eta_c=(sess["sum"]/sess["n"])*(nchunks-len(ck["done"]))       # ancienne (compte de chunks)
        L(f"chunk {ci}/{nchunks} {key} ok ({dt:.1f}s, cs={cs}) ; ETA_travail {eta_w/86400:.1f}j (ETA_chunks {eta_c/86400:.1f}j)")
        # C5 : test Poisson sequentiel (observe cumule vs predit, bande 95%) pour cibles cles.
        # lambda cumule = integrale du modele sur TOUTE la plage faite [a.lo, hi] (restart-proof,
        # pas d'accumulation par chunk qui se perdrait au redemarrage).
        pois=[]; nst=max(60,int((hi-a.lo)/1_000_000))
        for kk in ["3,17","2,25"]:
            r_,k_=int(kk.split(",")[0]),int(kk.split(",")[1])
            # COMPARAISON APPARIEE : v_model = exp(-Lambda) = P(aucun run mono de longueur k)
            # = la condition (a) SEULE. On la confronte donc au compte A-only, sinon le test
            # herite d'un biais systematique (~1 % a 1e9, jusqu'a 2 % selon (r,k)). Le compte
            # certifie (a)^(b) est affiche a cote, sans etre oppose a un modele qui ne le decrit pas.
            ent=ck["agg"].get(kk,{})
            Lp=lambda_chunk(r_,k_,a.lo,hi,steps=nst); obs=ent.get("count_a",ent.get("count",0))
            obs_ab=ent.get("count",0)
            band=1.96*math.sqrt(Lp) if Lp>0 else 0
            flag="" if abs(obs-Lp)<=band or Lp==0 else (" HORS-BANDE(+)" if obs>Lp else " HORS-BANDE(-)")
            pois.append(f"{kk}: obs_A={obs} pred_A={Lp:.0f}±{band:.0f}{flag} (certifies AB={obs_ab})")
        # ligne quotidienne (C3 : counts par chunk ; C5 : Poisson)
        agg_s=" ".join(f"{k}:n={v['count']},max_p={v['max_p']}" for k,v in sorted(ck["agg"].items()) if v['count'])
        cc_s=" ".join(f"{kk}:{chunk_counts.get(kk,0)}" for kk in [f"3,{k}" for k in range(17,26)]+["2,25"])
        n_direct=sum(bool(v.get("direct_rabung_family_champion")) for v in rb.values())
        n_general=sum(bool(v.get("general_record_candidate")) for v in rb.values())
        summary=(f"- chunk {ci}/{nchunks} p~{lo/1e9:.3f}e9 | faits {len(ck['done'])} ETA_travail {eta_w/86400:.2f}j | "
                 f"direct_rabung_family_champions {n_direct} | general_record_candidates {n_general} | "
                 f"nesting OK | xcheck {ck.get('_xcheck','pass 0')} | {gpu_status()}\n"
                 f"    chunk_counts: {cc_s}\n    Poisson[C5]: {' | '.join(pois)}\n    cumul: {agg_s}\n")
        write_raw_artifact(os.path.join(chunk_dir,"summary.md"),summary.encode("utf-8"))
        # Sauvegarde hors machine après le checkpoint validé. Son indisponibilité
        # ne modifie pas le verdict scientifique local, mais reste explicitement loggée.
        if a.backup:
            try: subprocess.run(["rsync","-a",ckpath,logpath,a.backup+"/"],timeout=300)
            except Exception as e: L(f"!! backup rsync ERREUR ({type(e).__name__}) — non fatal")
    L(f"# campagne terminée. agrégats : {json.dumps(ck['agg'])}")
    rb=ck.get("record_best",{})
    direct={k:v for k,v in rb.items() if v.get("direct_rabung_family_champion")}
    general={k:v for k,v in rb.items() if v.get("general_record_candidate")}
    if direct: L(f"# {len(direct)} direct_rabung_family_champion(s) -> PF1(ii) AVANT annonce : "+
                 "; ".join(f"{k}:bound={v['bound']}" for k,v in sorted(direct.items())))
    if general: L(f"# {len(general)} general_record_candidate(s) -> PF1(ii) AVANT annonce : "+
                  "; ".join(f"{k}:bound={v['bound']}" for k,v in sorted(general.items())))
    log.close()

if __name__=="__main__": main()
