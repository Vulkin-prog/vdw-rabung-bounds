# Finalisation pour publication — 26 septembre 2026

Le manuscrit a été finalisé à partir de la PR 5, commit
`62e4149bfdd29256080462cd4339e972e58e4aee`, en intégrant la revue bibliographique
du 26 septembre. Aucune campagne GPU et aucune exécution de grand certificat
n'ont été relancées. Les calculs historiques, leurs sources et leurs journaux
restent conservés sans modification.

## Portée scientifique retenue

- Trois certificats primitifs à trois couleurs, donnant neuf bornes directes.
- Cinq améliorations sur les comparateurs antérieurs identifiés, pour
  `k = 17, 18, 19, 20, 21`, y compris en tenant compte de l'énoncé publié
  Landman–Robertson au statut de preuve non résolu dans notre revue.
- Quatre certificats à deux couleurs attribués à Monroe et aux contributeurs
  de son projet : la contribution actuelle est une revérification.
- Les conséquences BCT/Berlekamp sont présentées comme telles ; le tableau
  n'est pas une revendication de records mondiaux sur toute la littérature.

Le résumé est recentré sur les résultats. Les mentions de document privé en
préparation ont été retirées du papier. Les longues identités d'exécution ont
été déplacées en annexe pour que les résultats scientifiques viennent d'abord.
La déclaration détaillée d'assistance par IA est conservée.

## Bibliographie et vérifications

Kozik–Shabanov a été ajouté. L'heure de soumission de Monroe v1 a été corrigée.
Les accès refaits le 26 septembre sont distingués des vérifications historiques
du 29 août. L'accès incomplet au texte original de Xu reste explicite ; aucune
borne gagnante à trois couleurs ne dépend de cette récurrence.

`audit/published-unresolved.json` conserve les spécialisations Landman–Robertson.
`tools/publication_comparison.py` recalcule la comparaison antérieure après
retrait des nouvelles entrées à trois couleurs. Les tableaux du papier sont
générés par ces registres, avec des entiers exacts.

Les contrôles CPU, la validation des 13 manifestes/67 exécutions archivées,
la couverture des 515 portions de campagne, l'identité des flux de premiers,
la construction déterministe et les résultats de contrôle du candidat sont
conservés dans le dossier de vérification livré avec le paquet. Ces contrôles
ne constituent pas une nouvelle réplication externe des grands calculs.

## Ce qui reste une décision de diffusion

Le dépôt reste privé et aucune release publique ni aucun DOI ne sont inventés.
`RIGHTS-STATUS.md` demande une décision de l'auteur. La proposition concrète est
MIT pour le code original, CC BY 4.0 pour le manuscrit et les données originales,
avec exclusion des éléments tiers. Elle est détaillée dans
`release/PROPOSED-LICENSING.md` et n'est pas encore une autorisation accordée.

Après ce choix, réserver le DOI de l'archive, reporter les identifiants réels
dans les métadonnées, puis exécuter le gel tag–archive et le contrôle des fichiers
déposés selon `REPRODUCIBILITY.md`. Ce sont des opérations légères de diffusion,
pas une nouvelle campagne de calcul sur le PC. Une archive de préparation
munie d'empreintes n'est pas présentée comme une release déjà déposée.

Le fichier `publication/zenodo-abstract.txt` fournit le résumé anglais avec
formules LaTeX en ligne, prêt à copier dans la description de dépôt.
