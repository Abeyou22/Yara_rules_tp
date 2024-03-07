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

- Téléchargez ce [fichier zip](https://github.com/VirusTotal/yara/releases/tag/v4.2.0) depuis la page GitHub de YARA.
- Décompressez le fichier et lancez l'exécutable `yara.exe` depuis votre invit de commande.

**Version précise**

Si vous souhaitez installer une version précise, récupérer la version sur ce [site](https://github.com/VirusTotal/yara/releases) et suivez la [procédure](changementVersion.md)

<a name="ToDo"></a>
## ToDo

| Level         | Objectif | Page |  Charge | Questionnaire |
|--------------|-----------|-----------|-----------|-----------|
| Level 1 | Saisir les bases de yara | [init](Exercices/1_ExInit/consignesInit.md)| LR |[Initiation](https://forms.office.com/e/UWZBceHr4m)|
| Level 2 | Trouver le png : faite une règle qui detecte les png (et autre) | [Exercice 2](Exercices/2_ExFindPng/consignes.md) | TBD | [Trouve le PNG](https://forms.office.com/e/4PEDdycPVZ) |
| Level 3 | YARA with python | [Exercice 3](Exercices/5_YaraWithPy/consignes.md)| PK | [Python avec Yara](https://forms.office.com/e/urw32a2Cf3) |
| Level X | Compléter une formation pour aborder les [wild-cards](#wild-cards), des [case-insensitive-strings](#case-insensitive-strings), des [expression régulière](#regular-expressions), ou des [opérateurs spéciaux](#special-operators) | init.md | CH |
| Level 4 | Enrichissemment| [Exercice 4](Exercices/6_Enrichment/consignes.md)| PK | |
| Level 5 | Reach Valhalla | [Exercice 5](Exercices/5_RoadToValhalla/consignes.md) | LR | [Road To Valhalla](https://forms.office.com/e/SDkC7Sk7fn) |
| Level 6 | Prise en main YarGen| [Exercice 6](Exercices/2_ExFindPng/consignes.md)| OL | [YarGen](https://forms.office.com/e/6ZEevy9Dc2) |
| Level 7 | Faire un python qui tourne en boucle pour faire IDS / https://yaids.io/ | [Exercice 7](Exercices/) | PK | |
| Level 8 | Bat Malware| [Exercice 8](Exercices/8_BatMalware/consignes.md) | CH | [Bat Malware](https://forms.office.com/e/kPGBmH29zZ) |
| Level 9 | ExLevel Malware | [Exercice 9](Exercices/9_ExLvlMalware/consignes.md) | OL | [Where Are You ?](https://forms.office.com/e/rfk591jjVD) |
