# Changelog

## 1.1.0

- suppression de la liste blanche `config/scope.txt` ;
- analyse directe de toute URL HTTP ou HTTPS fournie à `scan.sh` ;
- suppression des documents de développement redondants ;
- suppression du fichier `requirements.txt` vide ;
- renommage de `report_v1.py` en `report.py` ;
- remplacement de `report_clean.py` par `static_cleanup.py` ;
- suppression des rapports statiques HTML/Markdown intermédiaires ;
- conservation d’un seul rapport final dans `08-report/` ;
- mise à jour des logs, métadonnées, tests et documentation.

## 1.0.0

- projet autonome regroupant les versions précédentes ;
- arborescence de rapports normalisée ;
- logs horodatés et journal console complet ;
- gestion d’erreur globale avec état du scan ;
- auto-diagnostic et tests unitaires ;
- correction des URL Unicode et des domaines IDNA ;
- suppression de l’extraction globale des chaînes JavaScript ;
- import HAR et mutations GET/POST/JSON limitées ;
- réflexion/XSS potentielle, indices SQLi et redirections ouvertes ;
- analyse JWT, authentification, session, IDOR/BOLA et logique métier configurable ;
- intégration ZAP et rapport final consolidé.
