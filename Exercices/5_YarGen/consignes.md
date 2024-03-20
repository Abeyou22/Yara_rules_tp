##Présentation de YarGen

###Cet exercice ne peut malheuresement être effectué que sur des VMs configurés en local si vous utilisez des VMs installés dans le cloud, vous pouvez passer directement à l'exercice 6.
YarGen est un outil informatique spécialisé utilisé dans le domaine de la sécurité informatique et de l'analyse de logiciels malveillants. Son rôle principal est de faciliter la création de règles YARA, un langage de détection de logiciels malveillants.
Cet outil génère automatiquement ces règles en analysant un fichier potentiellement malveillant. Il identifie les séquences de caractères (ou chaînes) qui sont uniques à ce fichier.
YarGen intègre une vaste base de données qui contient des chaînes et des opcodes (codes opérationnels) identifiés comme apparaissant également dans des fichiers qui ne sont pas malveillants. Cette base de données aide à distinguer les caractéristiques spécifiques des logiciels malveillants.

##Prérequis

Il est conseillé de diminuer la mémoire alloué à votre VM afin d'éviter certains problèmes lors de l'exécution de l'outil

##Installation de YarGen

Pour installer l'outil il suffit d'accèder à cette page Github : https://github.com/Neo23x0/yarGen.git et d'y installer l'outil via la commande suivante :

```sh
git clone https://github.com/Neo23x0/yarGen.git
```

Une fois l'outil installé vous devriez avoir un répertoire au nom de yarGen sur votre système. Pour accéder à ce répertoire un simple cd "nom du répertoire" suffit :

```sh
cd yarGen
```


Une fois dans le répertoire yarGen, vous remarquerez la présence de plusieurs fichiers et répertoires, pas de panique on va s'attarder sur l'essentiel.
Premierement installer les librairies necessaires au bon fonctionnement de l'outil grâce à la commande suivante :


```sh
pip install -r requirements.txt
```

Maintenant vous pouvez lancer l'outil et verfier qu'il se lance correctement :

```sh
python3 yarGen.py -h
```
Normalement vous devriez avoir toute les infos nécessaire pour apprendre à utiliser l'outil.


Comme vous le savez sûrement YarGen se base sur une base de données avec de multiples règles Yara. Pour mettre à jour cette base de donnée et ainsi utiliser ces règles il suffit de taper cette commande :

```sh
python3 yarGen.py --update
```

#Exercice

Vous trouverez plusieurs fichiers à analyser dans le répertoire MaybeMalicious, à l'aide de l'outil YarGen vous allez devoir génerer des règles Yara afin de détecter les fichiers présents dans le répertoire.Essayez de comprendre les règles générées par l'outil. Bon courage !
