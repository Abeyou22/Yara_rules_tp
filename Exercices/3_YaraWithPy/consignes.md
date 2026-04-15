# Python with YARA


### Table of contents
- [Python with YARA](#python-with-yara)
    - [Table of contents](#table-of-contents)
  - [Why using Python ?](#why-using-python-)
  - [Installation of YARA](#installation-of-yara)
  - [Exercice 1](#exercice-1)
  - [Exercice 2](#exercice-2)
  - [Exercice 3](#exercice-3)
  - [Exercice 4](#exercice-4)
  - [Exercice 5](#exercice-5)

## Why using Python ?

Dans cet exercice, nous allons passer par l'utilisation de YARA dans Python
Pourquoi passer par python et pas lancer directement le logiciel ?


- La possibilité d'automatiser le processus de détection de fichiers malveillants.
- Le lancement d'une règle YARA sur une arborescence complète pour appliquer nos règles sur plusieurs fichiers 
- Enrichissement de la détection avec des informations complémentaires manuelles
- Vérification directement dans le programme

### Installer Python puis yara-python avec Python Embedded (sans pip)

Un fichier `.whl` (wheel) est une simple archive ZIP.
Il est donc possible de l'extraire directement dans le répertoire de Python embedded, sans avoir à configurer pip.

Python Embedded téléchargé via ce lien, en version 3.13 [Lien]([https://www.python.org/downloads/windows/](https://www.python.org/ftp/python/3.13.13/python-3.13.13-embed-amd64.zip))

### Étapes

1. Télécharge le fichier correspondant à la version 3.12 : [Lien](https://files.pythonhosted.org/packages/cc/a0/40b0291c8b24d13daf0e26538c9f3a0d843c38c6446dd17f36335bdd5b5f/yara_python-4.5.4-cp313-cp313-win_amd64.whl)

2. Renomme le fichier en remplacant .Whl par.zip

3. Extrait le fichier

4. Copie le fichier ```yara.cp313-win_amd64.pyd``` dans le dossier ```python-3.13.12-embed-amd64```

5. Ouvrir un invité de commande dans le dossier ```python-3.13.12-embed-amd64``` et tapper ```python```

6. Tapper ensuite ```import yara```. Si aucune erreur, cela veut dire que l'import s'est bien passé

Accéder aussi à la documentation, ça va vous servir pour avancer dans le tp (https://yara.readthedocs.io/en/stable/yarapython.html)
Maintenant que tout est  prêt, on peut commencer les exercices : 


## Exercice 1 

importer la librairie yara avec ```import yara```

l'exercice se fait en 3 étapes : 
- Récupérer notre règle yara  ```rules = yara.compile("pngrules.yar")```
- Ouvrir un fichier 
- Appliquer la règle sur le fichier 


## Exercice 2 

Reprenons notre fichier python

Nous allons enrichir notre règle, notre affichage pour mieux comprendre les retours

Construisez une règle qui détecte les png, les jfif, les jpg

Enrichissez la sortie en ajoutant l'affichage de la méta donnée, du string qui a matché


## Exercice 3 

Nous savons importer yara dans python, nous savons enrichir, maintenant, il ne reste plus qu'à généraliser ce comportement avec une arborescence de fichier

Analyser tous les fichiers qui se situent dans le dossier ```myJob```

Utiliser la librairie ```os``` pour pouvoir parcourir des fichiers plus facilement 

Construisez une règle YARA qui réagit si le fichier est corrompu 
mettre un filtre 
Donnez la liste des fichiers qui ont été détectés par votre règle


## Exercice 4 
Notre règle est prête, il ne nous reste plus qu'à la sauvegarder dans la base de donnée MISP

[WIP] Utiliser l'api misp pour push des règles yara dans la BDD

## Exercice 5

Maintenant que nous avons nos règles enrichies qui tournent sur plusieurs fichiers, nous allons automatiser la tâche pour pouvoir télécharger les nouvelles règles et lancer une analyse tous les lundis matin


