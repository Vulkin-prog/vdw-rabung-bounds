# Oracle de référence

`vdw_reference.cpp` est l'ancre indépendante utilisée pour valider les
constructions et détecter les divergences du scanner. Il doit rester simple et
être traité comme gelé : une optimisation du GPU ne doit pas être recopiée dans
l'oracle.

Depuis la racine :

```bash
g++ -O2 -std=c++17 -o reference/vdw_ref reference/vdw_reference.cpp
./reference/vdw_ref
```

Le binaire `vdw_ref` est local et ignoré par Git.
