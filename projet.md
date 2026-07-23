# Framework d’analyse de vulnérabilités web

## Objectif

Créer un outil capable d’analyser un site web autorisé afin d’identifier des faiblesses techniques, sans les corriger ni les exploiter au-delà de ce qui est nécessaire pour les confirmer.

La plateforme OWASP Juice Shop servira d’environnement de test.

## Fonctionnement

Le projet reposera sur deux parties :

- **Bash** : lancement et orchestration des outils Kali.
- **Python** : analyse des résultats, comparaison des réponses HTTP et génération du rapport.

## Outils utilisés

- **WhatWeb** : identification des technologies.
- **Nmap** : détection des ports et services exposés.
- **Gobuster** : découverte de fichiers et routes cachées.
- **Nikto** : détection de mauvaises configurations web.
- **OWASP ZAP** : crawl et analyse active de l’application.
- **sqlmap** : vérification ciblée des injections SQL.
- **Burp Suite** : validation manuelle des requêtes et vulnérabilités.

## Plan du projet

1. Valider la cible et le périmètre autorisé.
2. Lancer les outils Kali depuis un script Bash.
3. Collecter les résultats dans un dossier dédié.
4. Analyser les fichiers produits avec Python.
5. Classer les faiblesses par catégorie, gravité et niveau de confiance.
6. Générer un rapport JSON et HTML.

## Tests visés

- mauvaises configurations HTTP ;
- fichiers et routes exposés ;
- composants vulnérables ;
- injections SQL ;
- XSS ;
- défauts d’authentification et d’autorisation ;
- tokens et cookies mal sécurisés ;
- redirections non validées ;
- exposition de données sensibles.

## Livrables

- script `scan.sh` ;
- scripts Python d’analyse ;
- fichiers bruts des outils ;
- rapport final synthétique ;
- documentation d’utilisation.

## Limites

Le framework automatise la détection et la qualification des faiblesses. Les vulnérabilités liées à la logique métier ou aux droits utilisateurs devront souvent être confirmées manuellement.
