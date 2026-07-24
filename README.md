# DevSecOps Scanner V1.1

Framework pédagogique d’analyse dynamique de sécurité web. Il accepte directement toute URL HTTP ou HTTPS fournie en argument, sans liste blanche locale à maintenir.

> Utilise uniquement ce scanner sur un site pour lequel tu disposes d’une autorisation explicite.

## Fonctions principales

- reconnaissance avec WhatWeb, Nmap, Gobuster et Nikto ;
- analyse des headers, cookies, CORS et méthodes HTTP ;
- cartographie HTML et JavaScript contextuelle ;
- import HAR pour les paramètres GET, formulaires et JSON ;
- mutations limitées : validation des entrées, réflexion/XSS potentielle, indices SQLi et redirections ouvertes ;
- analyse passive des JWT ;
- tests configurables d’authentification, de session, d’IDOR/BOLA et de logique métier ;
- intégration ZAP passive ou active sur demande ;
- rapport final HTML, JSON et Markdown.

Le scanner signale des indices et conserve des preuves. Il ne remplace pas une validation humaine.

## Installation

```bash
chmod +x install.sh
./install.sh
```

L’installation ne lance pas `apt` et ne modifie pas automatiquement Kali. Les outils absents sont signalés puis ignorés.

## Analyser une cible

Aucune modification de configuration n’est nécessaire. Fournis directement l’URL complète :

```bash
./scan.sh https://staging.exemple.fr
./scan.sh http://127.0.0.1:3000
```

Le protocole doit être `http://` ou `https://`. Le port peut être précisé dans l’URL.

## Commandes

### Vérification du projet

```bash
./scan.sh --check
```

### Analyse passive

```bash
./scan.sh https://staging.exemple.fr
```

### Analyse active à partir d’un HAR

```bash
./scan.sh https://staging.exemple.fr \
  --active \
  --har navigation.har
```

### Inclure certains corps POST/JSON

```bash
./scan.sh https://staging.exemple.fr \
  --active \
  --active-post \
  --har navigation.har
```

### Deux comptes et scénarios avancés

```bash
cp config/auth-tests.example.json config/auth-tests.local.json
cp config/business-scenarios.example.json config/business-scenarios.local.json
```

Adapte et active uniquement les scénarios compatibles avec la cible, puis :

```bash
./scan.sh https://staging.exemple.fr \
  --active \
  --har navigation.har \
  --har-user-a user-a.har \
  --har-user-b user-b.har \
  --auth-config config/auth-tests.local.json \
  --scenario-config config/business-scenarios.local.json \
  --all-auth-tests
```

### ZAP

```bash
./scan.sh https://staging.exemple.fr --zap
./scan.sh https://staging.exemple.fr --active --zap-active
```

## Organisation des résultats

```text
results/
└── staging-exemple-fr_443/
    ├── latest
    ├── latest-report.html
    └── 20260724T083015Z_active_a1b2c3d4/
        ├── 00-meta/              paramètres, environnement, état des outils
        ├── 01-raw/               sorties brutes et réponses HTTP
        ├── 02-static/            cartographie et données statiques consolidées
        ├── 03-dynamic/           HAR, paramètres et mutations (si un HAR est fourni)
        ├── 04-authentication/    authentification et session (si demandé)
        ├── 05-access-control/    comparaisons de comptes (si demandé)
        ├── 06-business-logic/    scénarios métier (si demandé)
        ├── 07-zap/               rapports ZAP (si demandé)
        ├── 08-report/            rapport final
        └── 09-logs/              journal console et logs des modules
```

Rapport principal :

```text
08-report/security-assessment.html
```

## Interprétation

- **confirmed** : observation directement vérifiée par le scanner ;
- **probable** : comportement fortement suspect à confirmer ;
- **possible** : indice nécessitant une analyse manuelle.

Une entrée réfléchie n’est pas automatiquement une XSS. Une erreur SQL n’est pas automatiquement une injection exploitable. Une réponse similaire entre deux comptes doit être vérifiée avec la propriété réelle de la ressource.

## Sécurité et limites

- utilise uniquement des cibles autorisées ;
- privilégie une préproduction ou un laboratoire pour le mode actif ;
- emploie des comptes et données de test ;
- ne publie jamais les fichiers HAR ou `*.local.json` ;
- le test de logout peut fermer la session enregistrée ;
- certains scénarios POST peuvent modifier les données ;
- aucune analyse automatisée ne couvre entièrement la logique métier.
