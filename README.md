# DevSecOps Scanner V2.0.1

- [GARNIER Quentin](https://github.com/F1N3X)
- [LETARD Pierric](https://github.com/Mrpierrouge)
- [CANDILLE Thomas](https://github.com/ThomasCandille)

Lanceur Bash, un scanner Python et un rapport HTML/JSON.

> Utiliser uniquement sur une cible autorisee. Le mode actif envoie des requetes de test.

## Fichiers

```text
DevSecOps-v2.0.1/
├── scan.sh
├── scanner.py
└── README.md
```

## Scan passif

```bash
./scan.sh http://127.0.0.1:3000
```

## Scan actif sans Nuclei

```bash
./scan.sh http://127.0.0.1:3000 --active
```

Le mode actif lance les mutations, sqlmap cible et ZAP actif lorsqu'ils sont disponibles. Nuclei est ignore par defaut afin d'eviter une attente de plusieurs minutes.

Le journal affiche alors :

```text
[INFO] Nuclei non demande : module ignore.
```

## Activer Nuclei explicitement

```bash
./scan.sh http://127.0.0.1:3000 \
  --active \
  --nuclei
```

La duree maximale par defaut est de 120 secondes :

```bash
./scan.sh http://127.0.0.1:3000 \
  --active \
  --nuclei \
  --nuclei-timeout 60
```

Nuclei utilise uniquement les severites `medium`, `high` et `critical`, avec un debit limite, un delai HTTP de 5 secondes et une seule tentative.

Mettre periodiquement les templates a jour :

```bash
nuclei -update-templates

## Resultats

```text
results/<cible>/<date>_<mode>_<id>/
├── raw/
├── console.log
├── report.json
└── report.html
```

Le rapport final reste genere meme si Nuclei est absent, desactive ou interrompu.
