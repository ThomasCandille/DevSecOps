# 67

# Web Security Scanner - MVP 0.2

Ce projet lance plusieurs outils Kali sur une instance locale autorisee, puis analyse les resultats avec Python.

## Fonctionnalites

- identification des technologies avec WhatWeb ;
- analyse du port avec Nmap ;
- decouverte de ressources avec Gobuster ;
- verification de configurations avec Nikto ;
- analyse des headers, cookies, methodes HTTP et CORS ;
- telechargement des fichiers JavaScript du meme site ;
- extraction de routes API et d'indices cote client ;
- rapports JSON, Markdown et HTML autonomes.

## Utilisation

```bash
chmod +x scan.sh
./scan.sh http://127.0.0.1:3000
```

Les resultats sont crees dans :

```text
results/AAAA-MM-JJ_HH-MM-SS/
```

Fichiers principaux :

- `report.html` : rapport lisible dans Firefox ;
- `report.md` : rapport texte ;
- `report.json` : donnees structurees ;
- `endpoints.json` : routes extraites du JavaScript ;
- `javascript/` : fichiers JavaScript telecharges.

Pour ouvrir le dernier rapport :

```bash
LATEST=$(find results -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)
firefox "$LATEST/report.html"
```

## Securite et limites

Cette version accepte uniquement `localhost`, `127.0.0.1` et `::1`. Elle effectue surtout de la reconnaissance et de l'analyse statique. Les alertes JavaScript et CORS sont des indices a confirmer, pas automatiquement des vulnerabilites.
