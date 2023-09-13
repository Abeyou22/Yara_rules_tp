# Yara_rules

## Summary
- [Yara\_rules](#yara_rules)
  - [Summary](#summary)
  - [Introduction](#introduction)
    - [Formation](#formation)
  - [Planning](#planning)
  - [Installation](#installation)
  - [ToDo](#todo)
  - [Usage](#usage)
  - [Sources](#sources)


<a name="Introduction"></a>
## Introduction
This Yara project aim to introduce to the basics of Yara and to define a way to exploit those rules on investigation.

We will first update the formation section and pursue with a way to deploy and test the rules on a system.
After those step we will build a TP formation on a VM to experiment the recognition of some pattern. 

Finally we will build a folder with many rules, maybe a way to autogenerate them and the template to respect if you want to contributeto the project.

### Formation
To begin you can learn the basic of Yara on init.md 

If you prefer, the full documentation of the Language is available on this website https://yara.readthedocs.io/en/v4.3.2/index.html

<a name="Planning"></a>
## Planning


<a name="Installation"></a>
## Installation

**Linux installation**

- First, update your packet manager by running:
  
```bash
sudo apt update -y && sudo apt upgrade -y
```

- Installing YARA on your computer
  <!--  -->
```bash
sudo apt install yara
```

After running the command above, you can now access YARA from your command line.

**Windows installation**

- Download this [zip file](https://github.com/VirusTotal/yara/releases/tag/v4.2.0) from the YARAs GitHub page.
- Unzip the file and run the `yara.exe` executable.
  
For Mac users, you can use `brew` to install YARA.

<a name="ToDo"></a>
## ToDo

| Level         | Objectif | Page |  Charge |
|--------------|-----------|-----------|-----------|
| Level 1 | Saisir les bases de yara | [init](Exercices/1_ExInit/consignesInit.md)|  LR |
| Level 2 | Trouver le png : faite une règle qui detecte les png (et autre) | [Exercice 2](Exercices/2_ExFindPng/consignes.md) | TBD |
| Level 3 | YARA with python | [Exercice 3](Exercices/5_YaraWithPy/consignes.md)| PK |
| Level 4 | Enrichissemment| [Exercice 4](Exercices/6_Enrichment/consignes.md)| PK |
| Level 5 | Reach Valhalla | [Exercice 5](Exercices/5_RoadToValhalla/consignes.md) | LR |
| Level 6 | Prise en main YarGen| [Exercice 6](Exercices/2_ExFindPng/consignes.md)| OL |
| Level 7 | Faire un python qui tourne en boucle pour faire IDS / https://yaids.io/ | [Exercice 7](Exercices/) | PK |
| Level 8 | Bat Malware| [Exercice 8](Exercices/8_BatMalware/consignes.md) | CH |
| Level 9 | ExLevel Malware | [Exercice 9](Exercices/9_ExLvlMalware/consignes.md) | OL |


Idées

| Level         | Objectif | Page |  Charge |
|--------------|-----------|-----------|-----------|
| Level X | Faire un reverse : en ayant le code d'une règle, construisez un dossier qui les déclenche toutes | init.md | TBD |
| Level X | Trouver un .exe caché dans un png (ou autre) (4/5 png et doivent en detecter un qui est exe) | init.md | TBD |
| Level X | Dans la grosse base de donnée trouver un fichier fishing/leak info/ .exe| init.md | TBD |
| Level X | Dans une extraction mail, créer une règle YARA capable d'exclure les mails perso et de trouver les mails mentionnant X | init.md | TBD |

- Voir quand on fait les règles python à créer un rapport en .md 

<a name="Usage"></a>
## Usage

- Faire un IDS
- Analyser des fichiers


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