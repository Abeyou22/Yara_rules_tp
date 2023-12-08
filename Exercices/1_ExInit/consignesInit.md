# Intro

Cette formation porte sur YARA, un outil d'analyse de fichiers malveillants, utilisé pour détecter des patterns malveillants dans des fichiers, en utilisant des règles de detection. 

### Table des matières
- [Intro](#intro)
    - [Table des matières](#table-des-matières)
    - [Qu'est-ce que YARA ?](#quest-ce-que-yara-)
    - [Règles de synthèse de YARA](#règles-de-synthèse-de-yara)
      - [Header](#header)
      - [Metadata](#metadata)
      - [Strings](#strings)
      - [Condition](#condition)
      - [Comments](#comments)
    - [Exécution des règles de YARA](#exécution-des-règles-de-yara)
      - [A vous de jouer](#a-vous-de-jouer)
    - [Experiment](#experiment)

### Qu'est-ce que YARA ?
YARA est un outil open-source utilisé pour l'analyse des fichiers malveillants. YARA utilise des règles pour faire correller les caractéristiques des fichiers malveillants avec les fichiers analysés. Les règles contiennent généralement des chaînes, des expressions régulières et des opérateurs spéciaux qui décrivent certaines caractéristiques des familles de logiciels malveillants.

### Règles de synthèse de YARA
Voici un exemple de règle YARA :


```c
rule SectionSample{
  meta:
   author = “Descartes”
   description = “Simple YARA rule”
  strings:
    $a = "UVODFRYSIHLNWPEJXQZAKCBGMT"
  
  condition:
   any of them //checks whether a file has any of the above rules //$a or $b or $c
}
```
La règle ci-dessus indique à YARA que tout fichier contenant l'une des trois chaînes doit être signalé par la règle. Il s'agit d'un simple exemple, des règles plus complexes et plus puissantes peuvent être créées en utilisant des [wild-cards](#wild-cards), des [case-insensitive-strings](#case-insensitive-strings), des [expression régulière](#regular-expressions), ou des [opérateurs spéciaux](#special-operators) et bien d'autres fonctionnalités.

Commençons par expliquer chaque section de l'exemple.

#### Header

```c
rule SectionSample{
}
```

Chaque règle YARA comporte le mot-clé `rule`, comme le montre la première ligne de cette règle. Le mot-clé est ensuite suivi d'un nom de règle ou d'un identifiant, dans notre cas, il s'agit de `SectionSample`.

- Le premier caractère ne peut pas être un chiffre, comme dans le langage de programmation C.
- Tous les caractères alphanumériques sont autorisés
- Les [mots-clés Yara](#https://yara.readthedocs.io/en/v3.6.3/writingrules.html#id2 )ne sont pas autorisés


#### Metadata

```c
  meta :
    created = "01/06/2023 00:00:00"
    modified = "09/07/2023 11:44:00"
    author = “Descartes”
    description = “Simple YARA rule”
```

Cette ligne contient les métadonnées de la règle YARA. 

Elles peuvent être ajoutées pour aider à identifier les fichiers qui ont été pris en charge par une certaine règle. Les identificateurs de métadonnées sont toujours suivis d'un signe égal et de la valeur définie. Les valeurs attribuées peuvent être des chaînes de caractères, des nombres entiers ou une valeur booléenne. Notez que les paires identifiant/valeur définies dans la section des métadonnées ne peuvent pas être utilisées dans la section des conditions, leur seul but étant de stocker des informations supplémentaires sur la règle.

Dans cette section, vous pouvez inclure le nom de l'auteur, la date de création de la règle, une description de ce que fait la règle, etc. Ce que vous souhaitez

#### Strings

```c
  strings:
    $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
    $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
    $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
```

La section `strings` contient les valeurs que nous voulons rechercher dans les fichiers. Cette section peut contenir du texte, de l'hexadécimal ou des expressions régulières. 
`$[nomVariable]` sont les variables dans lesquelles nous allons stocker nos chaînes de caractères. Ici, nous avons 3 variables : $a $b $c


#### Condition

```c
  condition:
   any of them //checks whether a file has any of the above rules
```
Les conditions sont des expressions booléennes qui guident le moteur YARA dans la correspondance des chaînes. Il s'agit de la seule section requise pour créer une règle Yara. 

Cette section précise quand le résultat de la règle est vrai pour l'objet (fichier) qui fait l'objet de l'enquête.
Vous pouvez également inclure une autre règle dans vos conditions.

Ici, notre exemple de règle vérifiera si un fichier contient l'une des deux chaînes de caractères `a`, `b` et `c`. 

Les conditions peuvent également inclure l'[emplacement](#locationSearch) d'une chaîne de caractères dans le fichier. Cela permet notamment d'identifier le type de fichier et donc de réduire les risques que nos règles produisent des faux positifs.

Nous pouvons également inclure la taille du fichier comme condition lorsque nous voulons connaître la taille approximative d'un fichier de logiciel malveillant. Les chercheurs de logiciels malveillants partagent la taille des fichiers de logiciels malveillants et nous pouvons l'utiliser pour améliorer nos règles YARA.

#### Comments
Les règles YARA peuvent également contenir des commentaires, comme dans d'autres langages de programmation. Pour écrire des commentaires dans YARA, nous utilisons `//` pour les commentaires sur une seule ligne et `/* */` pour les commentaires sur plusieurs lignes.

Les règles YARA sont sauvegardées dans des fichiers portant l'extension `. yar`. Un seul fichier `. yar` peut contenir plus d'une règle YARA. 

### Exécution des règles de YARA

#### Premier Pas
- Ouvrez l'éditeur de code de votre choix 
- Copiez notre exemple de règle YARA et enregistrez le fichier sous le nom `sample.yar` ou tout autre nom. 
- Créez un autre fichier texte et ajoutez-y du texte.
- Ajoutez un texte aléatoire au fichier et enregistrez-le en tant que fichier texte (`.txt`). 
- Ouvrez un terminal de commande 
- Allez dans le dossier où se trouvent votre fichier et yaraRules 
- Entrez `yara sample.yar text.txt` dans le terminal 
- Dans le terminal, si votre fichier texte respecte l'une des conditions, il affichera 'SectionSample text.txt`. 
- Réessayez après avoir modifié votre fichier texte pour qu'il respecte l'une des conditions. 

Rappel dans un terminal Linux : 
  - La commande `cd NomDossier` amène dans le dossier NomDossier.  
  - La commande `cd ..` amène dans le dossier racine de celui dans lequel vous vous trouvez 
  - La commande `ls` affiche le contenu du dossier dans lequel vous vous trouvez.

Pour exécuter notre règle YARA, nous utiliserons le mot-clé `yara` pour accéder au moteur yara, pour Windows vous devez spécifier soit la version `yara32` soit la version `yara64` bit. Le nom du fichier de la règle (le fichier `. yar`) et ensuite le fichier que nous voulons tester. 

```bash 
┌──(yara@yara-virtual-machine)-[~/Documents/Yara_rules/Exercices/demo]
└─$ yara sample.yar text.txt
SectionSample test.txt
```

#### Plusieurs fichiers

Parfois, nous pouvons vouloir vérifier l'ensemble de notre système de fichiers, et nous pouvons donc utiliser `.` à la place du fichier que nous voulons tester.
Vérifier un fichier, c'est-à-dire le reste du dossier.


```bash
┌──(yara@yara-virtual-machine)-[~/Documents/Yara_rules/Exercices/demo]
└─$ yara sample.yar . 
HexSample ./falseTest.txt
SectionSample ./sample.yar
HexSample ./sample.yar
headmind ./sample.yar
SectionSample ./text.txt
```

Notez que sample.yar respecte toutes ses propres règles comme prévu.

Si vous voulez que la règle teste récursivement tous les dossiers, utilisez le paramètre `-r `/ `--recursive`. 

Si vous voulez imprimer les méta-données de la règle, utilisez le paramètre `--print-meta` / `-m`. Et pour n'afficher que les règles qui ne correspondent pas à la règle, utilisez le paramètre `--negate` / `-n`.

Trouvez les autres possibilités avec `yara --help`


### TAG

Rajouter une règle Yara dans votre fichier sample.yar et ajoutez lui un TAG.

Pour ajouter un TAG :

```c
  rule NomRule : TAG1 TAG2 {
    ...
    ...
    ...
  }
```

### Finale

Quelles commandes déclenche cette règle ? 
Modifiez votre fichier texte de test en conséquence pour que :

 1- les deux règles sans les tags détectent le fichier
 2- seule votre nouvelle règle sonne positive avec le tag

