# DevSecOps Scanner V2

Version simplifiée du framework : deux scripts seulement, un dossier de résultats par scan et un rapport final HTML/JSON.

> Utiliser uniquement sur une cible autorisée. Le mode actif envoie des requêtes de test.

## Pourquoi la V1 ne trouvait presque rien

Le mode actif ne disposait d'aucun paramètre GET fiable, aucun HAR n'était fourni et ZAP était absent. De plus, les fichiers `universalTouchGamepad.js` et les chaînes `Selkies` indiquent que le port 3000 analysé ne correspond probablement pas à OWASP Juice Shop.

La V2 affiche désormais clairement l'application détectée et avertit lorsque la cible ressemble à Selkies plutôt qu'à Juice Shop.

## Fichiers du projet

```text
DevSecOps-v2.0.0/
├── scan.sh
├── scanner.py
└── README.md
```

## Outils recommandés sur Kali

```bash
sudo apt update
sudo apt install zaproxy nuclei sqlmap nikto nmap gobuster whatweb seclists
```

Les outils absents sont ignorés avec un avertissement.

## Utilisation

### Scan passif

```bash
./scan.sh http://127.0.0.1:3000
```

### Scan actif générique

```bash
./scan.sh http://127.0.0.1:3000 --active
```

Le mode actif ajoute :

- sondes de routes sensibles ;
- mutations de paramètres découverts ;
- réflexion/XSS potentielle ;
- erreurs SQL ;
- redirections ouvertes ;
- Nuclei ;
- sqlmap limité, sans extraction de données ;
- ZAP actif lorsqu'il est installé.

### Forcer le profil Juice Shop

À utiliser seulement si la cible est bien une instance Juice Shop :

```bash
./scan.sh http://127.0.0.1:3000 --active --profile juice-shop
```

Le profil ajoute des contrôles sur `/ftp`, `/metrics`, `/api/Challenges`, la recherche de produits et le formulaire de connexion.

### Import HAR

Pour une application JavaScript moderne, naviguer dans le site avec Burp ou le navigateur, exporter un HAR, puis :

```bash
./scan.sh http://127.0.0.1:3000 --active --har navigation.har
```

Le HAR fournit les vraies routes et paramètres GET, POST et JSON.

## Résultats

```text
results/<cible>/<date>_<mode>_<id>/
├── raw/
├── console.log
├── report.json
└── report.html
```

Un raccourci vers le dernier rapport est créé dans :

```text
results/<cible>/latest-report.html
```

## Vérifier que le bon service écoute sur le port 3000

```bash
sudo ss -ltnp | grep ':3000'
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
curl -s http://127.0.0.1:3000 | grep -iE '<title>|juice|selkies'
```

Juice Shop est volontairement vulnérable, mais beaucoup de vulnérabilités sont liées au JavaScript, à une session ou à la logique métier. Un scanner automatisé ne les confirmera pas toutes sans HAR, navigateur dynamique et comptes de test.
