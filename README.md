# Yara_rules

## Sommaire
- [Yara\_rules](#yara_rules)
  - [Sommaire](#sommaire)
  - [Introduction](#introduction)
    - [Formation](#formation)
  - [ToDo](#todo)
  - [Usage](#usage)
  - [Objectifs Septembre-Octobre](#objectifs-septembre-octobre)
  - [Sources](#sources)


<a name="Introduction"></a>
## Introduction
Ce projet Yara a pour but d'introduire les bases de Yara et de définir un moyen d'exploiter ces règles dans le cadre d'une enquête.

Nous allons tout d'abord mettre à jour la section formation et poursuivre avec un moyen de déployer et de tester les règles sur un système.
Après ces étapes, nous construirons une formation TP sur une VM pour expérimenter la reconnaissance d'un motif. 

Enfin, nous créerons un dossier avec de nombreuses règles, peut-être un moyen de les autogénérer et le modèle à respecter si vous souhaitez contribuer au projet.

### Formation
Pour commencer, vous pouvez apprendre les bases de Yara sur init.md 

Si vous préférez, la documentation complète du langage est disponible sur ce site https://yara.readthedocs.io/en/v4.3.2/index.html
**Installation Linux**

- Tout d'abord, mettez à jour votre gestionnaire de paquets en exécutant :
  
```bash
sudo apt update -y && sudo apt upgrade -y
```

- Installation de YARA sur votre ordinateur

```bash
sudo apt install yara
```

Après avoir exécuté la commande ci-dessus, vous pouvez maintenant accéder à YARA depuis votre ligne de commande.

**Installation Windows**

- Téléchargez ce [fichier zip] (https://github.com/VirusTotal/yara/releases/tag/v4.2.0) depuis la page GitHub de YARA.
- Décompressez le fichier et lancez l'exécutable `yara.exe` depuis votre invit de commande.
  

<a name="ToDo"></a>
## ToDo

| Level         | Objectif | Page |  Charge | Questionnaire |
|--------------|-----------|-----------|-----------|-----------|
| Level 1 | Saisir les bases de yara | [init](Exercices/1_ExInit/consignesInit.md)| LR |[Initiation](https://forms.office.com/e/UWZBceHr4m)|
| Level 2 | Trouver le png : faite une règle qui detecte les png (et autre) | [Exercice 2](Exercices/2_ExFindPng/consignes.md) | TBD | |
| Level 3 | YARA with python | [Exercice 3](Exercices/5_YaraWithPy/consignes.md)| PK | |
| Level X | Compléter une formation pour aborder les [wild-cards](#wild-cards), des [case-insensitive-strings](#case-insensitive-strings), des [expression régulière](#regular-expressions), ou des [opérateurs spéciaux](#special-operators) | init.md | CH |
| Level 4 | Enrichissemment| [Exercice 4](Exercices/6_Enrichment/consignes.md)| PK | |
| Level 5 | Reach Valhalla | [Exercice 5](Exercices/5_RoadToValhalla/consignes.md) | LR | [Road To Valhalla](https://forms.office.com/e/SDkC7Sk7fn) |
| Level 6 | Prise en main YarGen| [Exercice 6](Exercices/2_ExFindPng/consignes.md)| OL | |
| Level 7 | Faire un python qui tourne en boucle pour faire IDS / https://yaids.io/ | [Exercice 7](Exercices/) | PK | |
| Level 8 | Bat Malware| [Exercice 8](Exercices/8_BatMalware/consignes.md) | CH | |
| Level 9 | ExLevel Malware | [Exercice 9](Exercices/9_ExLvlMalware/consignes.md) | OL | |


Idées

| Level         | Objectif | Page |  Charge |
|--------------|-----------|-----------|-----------|
| Level X | Faire un reverse : en ayant le code d'une règle, construisez un dossier qui les déclenche toutes | init.md | TBD |
| Level X | Trouver un .exe caché dans un png (ou autre) (4/5 png et doivent en detecter un qui est exe) | init.md | TBD |
| Level X | Dans la grosse base de donnée trouver un fichier fishing/leak info/ .exe| init.md | TBD |
| Level X | Dans une extraction mail, créer une règle YARA capable d'exclure les mails perso et de trouver les mails mentionnant X | init.md | TBD |

- Voir quand on fait les règles python à créer un rapport en .md 
- Idée à creuser :  mettre en place des règles YARA génériques détectant des micro étapes de malwares et qu'on pourrait lancer pour orienter le type de règles à tester ou pour flaguer un fichier.
- 
<a name="Usage"></a>
## Usage

- Faire un IDS
- Analyser des fichiers

<a name="Objectifs Septembre-Octobre"></a>
## Objectifs Septembre-Octobre

  - Finir YarGen
  - Finir les consgines et passer au format Microsoft Form les exercices
  - Ajouter d'autre exercices ou trouver d'autre idées à explorer
  - Faire tester à Pierre et Emma pour connaitre les temps passer sur les exercices quand on ne connait pas forrcémment l'outil
  

<a name="Sources"></a>
## Sources
| Sujet         | Lien |
|--------------|-----------|
| Yara documentation | https://yara.readthedocs.io/en/v4.3.2/index.html |
| Nextron system | https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/ |
| Nextron system 2| https://www.nextron-systems.com/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/ |
| Tryhackme investigation Windows 2.0 | https://tryhackme.com/room/investigatingwindows2    | 
| Article medium yara | https://medium.com/@nidhi.trivedi/yara-cheat-sheet-585eae339e63    | 
| Formation YARA Andreas | https://www.first.org/resources/papers/conference2014/first_2014_-_schuster-_andreas_-_yara_basic_and_advanced_20140619.pdf   | 
| Formation velocyraptor| https://docs.velociraptor.app/docs/forensic/searching/    | 
| Github rules YARA | https://github.com/section-engineering-education/engineering-education/tree/master/content/articles/getting-started-with-yara-for-malware-analysis   | 
