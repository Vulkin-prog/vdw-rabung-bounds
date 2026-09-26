# Traitement de l’audit d’exposition et de cohérence — 26 septembre 2026

Le point logique signalé sur Xu est fondé et corrigé. La révision emploie un
témoin cyclique au module exact, explicite son produit avec une coloration
ordinaire et renforce le contrat des entrées du programme. Les bornes et les
cinq améliorations principales sont inchangées. Aucun calcul lourd, balayage
GPU ou grand certificat n’a été relancé ; le PC de l’auteur n’a pas été utilisé.

Le document traité est `AUDIT_RABUNG_EXPOSITION_ET_CORPUS_2026-09-26_FR.md`,
SHA-256 `ed643f714925afb7627dfe83b08f4e0a58d7f14de9d6473db6c8a2fbec06078e`. Il examine le candidat
`14c3a04f758310371039f41a576d0712ed4aa0bc` et le PDF de 26 pages d’empreinte
`17e7f67056cb66d3f3c085b3588d33232031d0db5aa9873844a5a655259378e3`.
L’ancien espace de travail ayant disparu, ce candidat et son historique ont
été restaurés à partir du paquet conservé et des objets GitHub ; sa
reconstruction a retrouvé exactement les octets du PDF examiné.

| Remarque de l’audit | Traitement |
| --- | --- |
| Le seuil cyclique ne fournit pas un témoin au module choisi. | La section 2.1 suppose directement une coloration de Z/RZ au module exact R, avec les conditions de taille et de facteurs premiers. La formule reste W(st,k) > RB. |
| Aligner la convention du code. | Les entrées publiées de `ring_seeds` portent désormais `witness_modulus`. Les entrées liées à une revendication utilisent son premier. Deux tests de régression refusent une simple borne de seuil ou un module contradictoire. |
| Rendre le mécanisme de Xu vérifiable. | Le texte donne l’argument par paire de couleurs : résidu modulo R et indice du bloc. Un pas non divisible par R contredit le témoin cyclique ; un pas divisible par R contredit la coloration des blocs. |
| Résumé trop tôt occupé par le dossier bibliographique. | Résumé réécrit autour des trois certificats, neuf conséquences, cinq améliorations dans le catalogue daté, de la borne emblématique et du mécanisme. Les deux comparaisons Landman–Robertson restent aux lieux d’utilisation. |
| Montrer le petit certificat. | Ajout du mot `0011000110001101` sur les positions 0 à 15. Les 35 progressions de longueur 4 sont revérifiées. |
| Expliquer trois certificats / neuf bornes. | La transition vers le lemme précise que le même premier donne un intervalle plus long, au-delà de la simple monotonie numérique. |
| Distinguer témoin bref et coût de vérification. | Le guide de lecture distingue réévaluation des résidus et contrôle léger de l’archive ; la section 3 distingue le balayage O(p) du calcul des couleurs O(p log p). |
| Donner une conséquence BCT lisible. | Ajout du produit 19 × 2 582 037 634 = 49 058 715 046, qui dépasse la borne directe à la longueur 22. |
| Actualiser Kozik–Shabanov. | Publication de 2016, volume 116, pages 312–332 et DOI ajoutés ; le numéro de théorème reste explicitement celui d’arXiv v1. |
| Réduire les répétitions administratives. | Preuve du théorème 2.1 recentrée sur les hypothèses finies ; plusieurs répétitions sur les manifestes, la source de référence et la réplication retirées du récit de campagne. La traçabilité et les limites restent dans leurs sections dédiées. |
| Ne pas refaire la structure ou ajouter des liens artificiels au corpus. | Titre, figure, preuves, sommaire initial et périmètre statistique conservés. Aucune citation artificielle des autres articles, aucune scission, aucun benchmark ou travail Lean ajouté. |
| Synchroniser le paquet et l’accès public. | Les sources et la documentation sont synchronisées à cette révision. Le dépôt privé est qualifié comme tel ; aucun DOI ou accès public inexistant n’est annoncé. L’adresse d’archive définitive reste une étape du dépôt public. |

## Vérifications et portée

Le contrôle arithmétique séparé retrouve les treize identités de bornes, les
sept nombres premiers distincts, les 309 nœuds de fermeture, les 48 lignes
gagnantes, les 18 nœuds d’ascendance des comparateurs et les cinq améliorations
pour k = 17, 18, 19, 20 et 21. Il compare les entrées numériques et les chemins
de calcul au candidat initial : ils sont identiques, hormis les nouvelles
déclarations explicites de module dans les métadonnées.

L’exemple du produit de colorations est aussi contrôlé à petite échelle : un
témoin cyclique à R = 5 et la coloration sur 16 positions donnent 80 positions
à quatre couleurs ; les 1 027 progressions de longueur 4 sont toutes examinées.
Cela illustre l’argument général sans prétendre le remplacer.

Les programmes des grands calculs, les treize revendications et les archives
d’exécution de certificats, de campagne et de qualification CUDA sont conservés
sans modification. Les changements du générateur concernent le contrat des
entrées et son explication, pas les valeurs numériques des récurrences.
La sortie détaillée est `publication/editorial-review/consistency.json`.
Les contrôles CPU et PDF sur le prochain candidat propre seront consignés dans
`results/publication-finalization/2026-09-26-audit/` avant la livraison finale.

La mise en page de cette révision a été inspectée sur les 27 pages A4. Le PDF
est obtenu par deux constructions propres donnant les mêmes octets :
SHA-256 `b5499f954245b52bff215ab24a6d019a5900d4bdaea9ae896fa67f5dc1e314ff`.

## Bibliographie vérifiée dans cette passe

La notice publiée Kozik–Shabanov a été recoupée avec la page de l’éditeur et
la notice de l’Université Jagellonne :

- https://www.sciencedirect.com/science/article/pii/S0095895615001112
- https://apacz.matinf.uj.edu.pl/publikacje/7679-improved_algorithms_for_colorings_of_simple_hypergraphs_and_applications
- https://arxiv.org/abs/1409.6921v1

Le texte intégral original de Xu n’a pas été obtenu dans cette passe. La
concaténation effectivement utilisée est maintenant exposée directement à
partir du témoin exact. Aucun gagnant à trois couleurs ne dépend de Xu.
Les limites de l’audit Landman–Robertson, de la recherche d’antériorité et
l’absence de réplication extérieure indépendamment administrée restent visibles.

## Reste pour le dépôt public

Les licences sont acquises : MIT pour le code original, CC BY 4.0 pour le
manuscrit et les données originales. Il reste à attribuer les identifiants
réels de l’archive publique, à les insérer dans les métadonnées et à effectuer
le gel avec une dernière reconstruction légère et le contrôle des fichiers
déposés. Le dossier remis à l’auteur est une préparation vérifiée, pas la
preuve qu’un DOI, une release publique ou une acceptation éditoriale existe.
