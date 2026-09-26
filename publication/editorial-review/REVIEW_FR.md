# Revue de cohérence et d'exposition — 26 septembre 2026

> Historique : cette première revue décrit le candidat `14c3a04f758310371039f41a576d0712ed4aa0bc` de 26 pages. Le traitement ultérieur de l’audit fourni par l’auteur est dans `RESPONSE_AUDIT_2026-09-26_FR.md`. La sortie numérique de cette première passe est conservée dans `consistency_initial.json` ; `consistency.json` suit la passe courante.

Le noyau numérique est cohérent avec les registres et les preuves d'exécution
conservées. La relecture a toutefois trouvé des corrections utiles : un exemple
de bord ambigu, une formulation trop rapide sur la surjectivité, des mesures
historiques insuffisamment documentées pour servir de benchmarks publiés, et
une présentation encore trop centrée sur les détails d'audit. Ces points sont
corrigés. Les bornes, les sources des grands calculs et leurs journaux ne sont
pas modifiés. Aucun calcul lourd ni aucune nouvelle exécution GPU n'a été lancé.

## Référence éditoriale effectivement consultée

La comparaison directe porte sur l'édition publique du 21 septembre 2026 de
*Long runs and rare patterns of a random completely multiplicative function*,
version 3, de Brice Pouly : 67 pages, fichier `paper_c_version_3_en(2).pdf`,
SHA-256 `365dc309cc54ae7b957cff247093d2d58db9ab1333d36054b9b465473bee0db7`.
Les principaux passages étudiés sont l'ouverture, les résultats introductifs,
le schéma de méthode, l'état de l'art, le guide de lecture et la conclusion.
Il s'agit d'une comparaison d'exposition ; elle ne constitue pas une nouvelle
vérification mathématique de Long runs ni de l'ensemble du corpus publié.

| Dimension | Force de Long runs v3 | Modification du manuscrit Rabung |
| --- | --- | --- |
| Entrée dans le sujet | Un modèle simple, puis l'obstruction qui motive le travail. | L'ouverture part d'une coloration gigantesque décrite par un petit triplet ; les registres viennent ensuite. |
| Hiérarchie des résultats | Résultats principaux identifiés, suivis de leur portée. | Trois certificats primitifs, neuf inégalités et cinq améliorations sont distingués dès l'introduction. |
| Mécanisme de preuve | Une interface mathématique explicitée avant les outils détaillés. | Schéma découverte–vérification–borne–comparaison et exemple complet de petite taille. |
| Antériorité | Séparation entre principes hérités et contribution propre. | Rabung, BCT, Berlekamp, Monroe et l'énoncé Landman–Robertson gardent leurs rôles et attributions distincts. |
| Parcours de lecture | Sommaire, sections introductives et guide par intérêt. | Sommaire avant l'introduction, quatre sous-sections d'orientation, format A4 et en-tête discret. |
| Détails techniques | Le lecteur sait où se trouvent les preuves et compléments. | Les preuves restent dans le texte principal ; catalogue des sources et inventaire de campagne passent en annexe. |
| Limites | Les quantificateurs et la portée ne sont pas laissés implicites. | Les comparateurs non résolus, la portée finie de la recherche et le statut empirique de la densité restent visibles. |

L'objectif est une qualité de lecture comparable, adaptée à un article de
calculs certifiés. Il ne s'agit pas d'assimiler la portée scientifique du
résultat à celle d'un article théorique beaucoup plus long. Aucun numéro de
version de travail n'est ajouté au manuscrit. La déclaration d'assistance IA
et de responsabilité demeure distincte et conserve son contenu.

## Contrôle scientifique et numérique

Le programme `check_consistency.py`, sans importer les fonctions du générateur
des bornes, a effectué les vérifications suivantes. Sa sortie complète figure
dans `consistency.json`.

- Les treize identités strictes `B = (k−1)p + 1` sont exactes. Les sept nombres
  premiers distincts sont revérifiés par division d'essai ; les congruences et
  les conditions `p > k` concordent.
- Les 309 nœuds de la fermeture, les 48 lignes gagnantes et les 18 nœuds
  d'ascendance des comparateurs antérieurs sont contrôlés. Les opérations BCT,
  Xu et de monotonie respectent leurs paramètres et l'arithmétique entière.
  Cela vérifie les applications des formules, pas les théorèmes publiés servant
  de bases.
- Les spécialisations du comparateur Landman–Robertson sont recalculées avec
  des entiers exacts. Les cinq améliorations subsistent exactement pour
  `k = 17, 18, 19, 20, 21`. Aucune ascendance gagnante à trois couleurs ne
  dépend de Xu.
- Les sources du scanner, des vérificateurs et de l'oracle, les registres de
  certificats et de bases, et les résultats de fermeture sont identiques à
  ceux du candidat précédent `d2759d745647d53a2bb6d99ca0a9e9b3effb517b`.
  Les archives de grandes exécutions, de campagne, de CPU et de qualification
  CUDA sont inchangées.

La preuve de l'équivalence du critère de bord a aussi été relue : réduction
des progressions sans joker, unicité de la progression de pas `p`, au plus un
joker pour un pas inférieur à `p`, relèvement au même joker pour toutes les
classes du pas, puis distinction des deux valeurs possibles de `c(−1)`.
La monotonie à nombre premier fixé utilise bien l'inclusion de chaque chaîne
de bord dans une chaîne de longueur supérieure. La convention stricte des
bornes est cohérente avec les `+1` des constructions.

## Corrections précises

1. **Exemple plafond/plancher.** Au triplet `(13,2,4)`, la condition de bord
   distingue les deux arrondis, mais la condition de longueur de plage échoue
   déjà : cet exemple ne distingue donc pas les verdicts complets. Le texte
   emploie maintenant `(5,2,4)`, qui les distingue effectivement. Une
   énumération indépendante des 16 colorations des jokers et des 35
   progressions par coloration confirme les 14 extensions non constantes
   valides. Pour `(5,2,3)`, les huit affectations échouent, ce qui confirme le
   rôle du singleton. Ces calculs sont minuscules.
2. **Hypothèses et surjectivité.** La proposition rappelle explicitement que
   `p` est premier et `3 ≤ k < p`. La divisibilité de `p−1` par `r` fournit
   un homomorphisme surjectif ; le texte n'attribue plus cette équivalence à
   la seule surjectivité d'une liste d'indices.
3. **Chiffres de performance et anciens échantillons.** Les anciennes vitesses
   de noyau GPU, le tableau de temps/mémoire et les totaux de prévalidation
   dépourvus ici d'un protocole complet ne sont plus présentés comme mesures
   publiées. Le chiffre historique de 200 survivants échantillonnés n'est plus
   utilisé comme validation chiffrée en l'absence de sa liste et de sa sortie
   complète. Ces informations historiques restent dans les versions et
   archives existantes ; aucune donnée n'est inventée pour les compléter.
4. **Relecture éditoriale.** Les instructions de préparation encore formulées
   au futur sont retirées ou remplacées par l'état réellement documenté.
   Les DOI ne sont plus imprimés deux fois sous forme de DOI et d’URL
   identique. Une faute grammaticale dans la conclusion est corrigée ; les graphies
   anglaises sont harmonisées. Les limites de la comparaison empirique
   restent dans les annexes et sont annoncées dans le texte principal.
5. **Licences.** L'accord explicite du 26 septembre est appliqué : MIT pour le
   code original, CC BY 4.0 pour le manuscrit et les données originales. Les
   textes, la carte des composants et les métadonnées logicielles concordent.

## Portée de l'assurance apportée

Les contrôles automatiques du dépôt acceptent les treize manifestes et les
67 exécutions archivées. Ils vérifient identités, sources, fichiers et verdicts ;
ils ne refont pas les grands calculs. La suite CPU et la construction
déterministe du candidat éditorial sont consignées avec leurs sorties et
l'identité du commit dans le dossier de vérification livré.

Cette revue n'est ni une preuve formelle intégrale ni une expertise humaine
indépendante. Aucun défaut invalidant les cinq améliorations n'a été identifié
dans le périmètre examiné. « Parfait » serait une assurance excessive : une
erreur encore non détectée reste possible, comme dans tout article
computationnel non intégralement formalisé.

Les limites restantes sont précises : statut de preuve de l'énoncé
Landman–Robertson non résolu dans l'audit ; accès au texte original de Xu
incomplet, avec absence de dépendance des gagnants à trois couleurs ; recherche
d'antériorité limitée au corpus daté ; absence de réplication extérieure
indépendamment administrée. Ces limites sont déclarées, sans être transformées
en promesse de nouveaux grands calculs.

Le dossier est préparé pour la diffusion. Restent les identifiants réels du
dépôt, la version de l'archive, son gel et la publication du DOI. Aucun DOI,
tag public, dépôt effectué ou acceptation par une revue n'est annoncé avant
sa réalisation.

Le PDF révisé compte 26 pages au format A4. Deux constructions propres ont
donné les mêmes octets ; les pages ont été contrôlées visuellement, avec
revérification des références après leur mise en forme finale. SHA-256 :
`17e7f67056cb66d3f3c085b3588d33232031d0db5aa9873844a5a655259378e3`.
