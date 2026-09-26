#!/usr/bin/env python3
"""Small arithmetic and document-consistency audit; no large certificate run."""
import hashlib
import itertools
import json
import math
import subprocess
from functools import cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = '14c3a04f758310371039f41a576d0712ed4aa0bc'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(relative):
    return json.loads((ROOT / relative).read_text())


@cache
def least_factor(n):
    require(n >= 2, 'factor input')
    if n % 2 == 0:
        return 2
    for d in range(3, math.isqrt(n) + 1, 2):
        if n % d == 0:
            return d
    return n


def small_example(p, k):
    # Independent quadratic-residue definition; enumerate every joker choice
    # and every progression in the explicit interval, without project code.
    residues = {x*x % p for x in range(1, p)}
    colours = {x: int(x not in residues) for x in range(1, p)}
    sequence = [colours[x] for x in range(1, p)]
    maximum = max(len(list(group)) for _, group in itertools.groupby(sequence))
    epsilon = colours[p-1]
    interval = (k-1+1)//2 if epsilon == 0 else k-1
    boundary = len({colours[x] for x in range(1, interval+1)}) > 1
    floor_interval = (k-1)//2 if epsilon == 0 else k-1
    floor_boundary = len({colours[x] for x in range(1, floor_interval+1)}) > 1
    n = (k-1)*p+1
    aps = [tuple(a+j*d for j in range(k))
           for d in range(1, (n-1)//(k-1)+1)
           for a in range(n-(k-1)*d)]
    accepted = []
    for jokers in itertools.product(range(2), repeat=k):
        word = [jokers[x//p] if x % p == 0 else colours[x % p] for x in range(n)]
        if all(len({word[x] for x in ap}) > 1 for ap in aps):
            accepted.append(jokers)
    expected = 2**k-2 if maximum < k and boundary else 0
    require(len(accepted) == expected, (p, k, 'explicit colouring equivalence'))
    return {'p': p, 'r': 2, 'k': k, 'maxrun': maximum,
            'boundary_correct': boundary, 'boundary_floor': floor_boundary,
            'criterion_correct': maximum < k and boundary,
            'criterion_floor': maximum < k and floor_boundary,
            'joker_assignments': 2**k, 'valid_extensions': len(accepted),
            'progressions_per_assignment': len(aps)}


def check_nodes(rows, claims):
    nodes = {n['id']: n for n in rows}
    for n in rows:
        method, bound, r, k = n['method'], n['lower_bound'], n['colors'], n['length']
        parents = [nodes[x] for x in n['parents']]
        if method == 'one_color_exact':
            require(r == 1 and bound == k-1, n['id'])
        elif method == 'length_monotonicity':
            a, = parents
            require(a['colors'] == r and a['length'] < k and bound == a['lower_bound'], n['id'])
        elif method == 'bct2018':
            a, = parents
            q = n['parameters']['prime_q']
            require(least_factor(q) == q and q <= k, n['id'])
            require(a['colors'] == r-(r+q-1)//q and a['length'] == k, n['id'])
            require(bound == q*a['lower_bound'], n['id'])
        elif method == 'xu2013':
            ring, ordinary = parents
            params = n['parameters']; q, s, t = params['n'], params['s'], params['t']
            require(q >= 5 and least_factor(q) > k and q == ring['lower_bound'], n['id'])
            require(ring['kind'] == 'ring' and ordinary['kind'] == 'ordinary', n['id'])
            require(ring['colors'] == s and ordinary['colors'] == t and r == s*t, n['id'])
            require(ring['length'] == ordinary['length'] == k and bound == q*ordinary['lower_bound'], n['id'])
        elif method == 'direct_rabung':
            c = claims[n['label']]
            expected = c['prime'] if n['kind'] == 'ring' else c['lower_bound']
            require((r,k,bound) == (c['colors'],c['length'],expected), n['id'])
        else:
            require(method == 'published_seed' and not parents, n['id'])
    return nodes


def main():
    claims = {c['id']: c for c in read('audit/claims.json')['claims']}
    for c in claims.values():
        p, r, k = c['prime'], c['colors'], c['length']
        require(least_factor(p) == p and (p-1) % r == 0 and p > k, c['id'])
        require(c['lower_bound'] == (k-1)*p+1, c['id'])
    closure = read('audit/generated/bounds_closure.json')
    nodes = check_nodes(closure['nodes'], claims)
    for w in closure['winners']:
        n = nodes[w['node_id']]
        require(n['lower_bound'] == w['lower_bound'], w)
        require(w['lower_bound'] == max(v['lower_bound'] for v in nodes.values()
           if v['kind'] == 'ordinary' and (v['colors'],v['length']) == (w['colors'],w['length'])), w)
        if w['colors'] == 3:
            pending = [n]
            while pending:
                ancestor = pending.pop()
                require(ancestor['method'] != 'xu2013', 'winning three-colour row depends on Xu')
                pending.extend(nodes[parent] for parent in ancestor['parents'])
    comparison = read('audit/generated/publication_comparison.json')
    prior = check_nodes(comparison['admitted_prior_provenance_nodes'], claims)
    improved = []
    for row in comparison['rows']:
        k = row['length']; p = max(v for v in range(5, k) if least_factor(v) == v)
        lr = p*(3**p-1)
        require(lr == row['published_unresolved_bound'], row)
        require(row['prior_comparator'] == max(lr,row['admitted_prior_bound']), row)
        if row['direct_bound'] is not None and row['direct_bound'] > row['prior_comparator']:
            improved.append(k)
    require(improved == [17,18,19,20,21], improved)
    require(23*(3**23-1)//2 == 1082646556499, 'Berlekamp value')
    examples = [small_example(5,4), small_example(5,3), small_example(13,4)]
    require(examples[0]['valid_extensions'] == 14 and not examples[0]['criterion_floor'], 'floor counterexample')
    require(examples[1]['maxrun'] < 3 and not examples[1]['boundary_correct'], 'singleton counterexample')
    word = [int(c) for c in '0011000110001101']
    aps = [(a,d) for d in range(1,6) for a in range(16-3*d)]
    require(len(aps) == 35 and all(len({word[a+j*d] for j in range(4)}) > 1
            for a,d in aps), 'printed 16-position example')
    cyclic = word[:5]
    require(all(len({cyclic[(a+j*d)%5] for j in range(4)}) > 1
            for a in range(5) for d in range(1,5)), 'exact cyclic witness at modulus 5')
    product = [(cyclic[x%5],word[x//5]) for x in range(80)]
    product_aps = [(a,d) for d in range(1,27) for a in range(80-3*d)]
    require(all(len({product[a+j*d] for j in range(4)}) > 1
            for a,d in product_aps), 'exact-witness product colouring')
    baselines = read('audit/baselines.json')
    for seed in baselines['ring_seeds']:
        if 'claim_id' not in seed:
            require(seed.get('witness_modulus') == seed['lower_bound'], seed)
    old_baselines = json.loads(subprocess.check_output(
        ['git','show',BASE+':audit/baselines.json'],cwd=ROOT))
    normalized = json.loads(json.dumps(baselines))
    normalized.pop('ring_seed_convention')
    for seed in normalized['ring_seeds']:
        seed.pop('witness_modulus',None)
    require(normalized == old_baselines, 'numerical baseline inputs changed')
    old_closure = json.loads(subprocess.check_output(
        ['git','show',BASE+':audit/generated/bounds_closure.json'],cwd=ROOT))
    require(closure['nodes'] == old_closure['nodes'] and
            closure['winners'] == old_closure['winners'], 'closure values or provenance changed')
    old_comparison = json.loads(subprocess.check_output(
        ['git','show',BASE+':audit/generated/publication_comparison.json'],cwd=ROOT))
    require(comparison['rows'] == old_comparison['rows'] and
            comparison['admitted_prior_provenance_nodes'] == old_comparison['admitted_prior_provenance_nodes'],
            'priority comparison changed')
    preserved = {}
    for name in ['src/scan_gpu.cu','tools/verify_claim.cpp','tools/rabung_criterion.cpp',
                 'tools/highp_witness.c','reference/vdw_reference.cpp','audit/claims.json']:
        current=(ROOT/name).read_bytes()
        old=subprocess.check_output(['git','show',BASE+':'+name],cwd=ROOT)
        require(current == old, 'scientific source changed: '+name)
        preserved[name]=hashlib.sha256(current).hexdigest()
    changed=subprocess.check_output(['git','diff','--name-only',BASE,'--','results/claims',
        'results/campaign','results/cpu','results/release'],cwd=ROOT,text=True).strip()
    require(changed == '', 'historical evidence changed: '+changed)
    result={'schema':'vdw-editorial-consistency/v1','basis_commit':BASE,
      'large_certificate_executions_performed':0,'gpu_executions_performed':0,
      'claim_integer_identities_checked':len(claims),'distinct_claim_primes_checked':len({c['prime'] for c in claims.values()}),
      'closure_nodes_checked':len(nodes),'prior_ancestry_nodes_checked':len(prior),
      'winning_rows_checked':len(closure['winners']),'improved_lengths':improved,
      'small_explicit_cases':examples,'preserved_scientific_inputs_sha256':preserved,
      'printed_word_verified':'0011000110001101',
      'exact_witness_product_example':{'modulus':5,'block_count':16,'colours':4,
          'length':4,'positions':80,'progressions_checked':len(product_aps)},
      'baseline_numbers_closure_nodes_and_priority_rows_unchanged':True,
      'interpretation':'Arithmetic and consistency audit only; archived large runs are validated separately, not replayed. Published seed theorems are not proved by this script.'}
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__ == '__main__':
    main()
