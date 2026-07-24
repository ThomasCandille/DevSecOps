# Utilisation responsable

Le scanner accepte toute URL HTTP ou HTTPS fournie en argument. Cette liberté d’utilisation ne constitue pas une autorisation de tester un système tiers.

Utilise-le uniquement sur :

- un laboratoire local ;
- une application qui t’appartient ;
- un environnement pour lequel une autorisation explicite de test a été obtenue.

Le mode actif, ZAP actif et les scénarios POST peuvent modifier l’état de l’application. Privilégie une préproduction et des comptes de test.

Les fichiers HAR, cookies, JWT et configurations locales peuvent contenir des secrets. Ils sont exclus par `.gitignore`, mais doivent aussi être protégés lors des partages et sauvegardes.
