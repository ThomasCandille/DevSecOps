# Web Security Scanner — MVP 0.4

Scanner local destiné à OWASP Juice Shop et aux applications explicitement autorisées.

## Nouveautés

- exploration HTML limitée au même site ;
- analyse contextuelle des appels `fetch`, Axios, clients HTTP et routes SPA ;
- distinction entre routes serveur et routes navigateur `/#/...` ;
- extraction des paramètres de requête et de chemin ;
- lecture de `robots.txt`, `sitemap.xml` et des résultats Gobuster ;
- vérification de chemins sensibles courants ;
- détection des réponses génériques des SPA pour éviter les faux positifs ;
- profil OWASP Juice Shop détecté automatiquement ;
- suppression des faux paramètres issus du JavaScript minifié ;
- déduplication des alertes Nikto sur les headers.

## Utilisation

```bash
chmod +x scan.sh
./scan.sh http://127.0.0.1:3000
```

Avec les tests actifs limités :

```bash
./scan.sh http://127.0.0.1:3000 --active
```

Forcer le profil Juice Shop :

```bash
./scan.sh http://127.0.0.1:3000 --active --profile juice-shop
```

Désactiver les profils spécifiques :

```bash
./scan.sh http://127.0.0.1:3000 --profile none
```

## Fonctionnement

1. Bash lance WhatWeb, Nmap, Gobuster, Nikto et Curl.
2. Python explore les pages HTML du même site.
3. Les fichiers JavaScript sont téléchargés et analysés.
4. Les routes trouvées sont fusionnées avec Gobuster, `robots.txt` et `sitemap.xml`.
5. Les chemins sensibles de `config/sensitive-paths.txt` sont vérifiés par des requêtes GET limitées.
6. Le profil Juice Shop complète la recherche avec des routes connues du laboratoire.
7. En mode actif, seuls les paramètres GET fiables sont modifiés.

## Fichiers de sortie

Dans `results/AAAA-MM-JJ_HH-MM-SS/` :

- `report.html` : rapport principal ;
- `report.json` et `report.md` ;
- `endpoints.json` : routes consolidées ;
- `parameters.json` : paramètres liés à une route ;
- `sensitive-routes.json` : routes sensibles réellement détectées ;
- `route-probes.json` : ensemble des chemins testés, y compris les absents ;
- `crawl-pages.json` : pages explorées ;
- `active-tests.json` : résultats des mutations GET ;
- `javascript/` : fichiers JavaScript téléchargés.

## Personnalisation

Ajouter des chemins globaux dans :

```text
config/sensitive-paths.txt
```

Format :

```text
Categorie|/route
```

Créer un profil dans :

```text
config/profiles/nom-du-profil.txt
```

Puis le lancer avec `--profile nom-du-profil`.

Le profil Juice Shop s’appuie notamment sur les routes documentées dans :
https://github.com/Whyiest/Juice-Shop-Write-up/tree/main

## Limites

Le scanner ne remplace pas un navigateur exécutant le JavaScript ni une analyse avec Burp ou ZAP. Les formulaires POST, les sessions authentifiées, les contrôles d’accès et la logique métier nécessitent encore des tests dédiés.
