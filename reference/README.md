# Oracle de référence

`vdw_reference.cpp` est l'implémentation de référence écrite séparément pour
valider les constructions et détecter les divergences du scanner. Cette
séparation du code ne désigne pas une réplication administrée sur une machine
externe. L'oracle doit rester simple et être traité comme gelé : une
optimisation du GPU ne doit pas y être recopiée.

Depuis la racine :

```bash
g++ -O2 -std=c++17 -o reference/vdw_ref reference/vdw_reference.cpp
./reference/vdw_ref
```

Le binaire `vdw_ref` est local et ignoré par Git.
