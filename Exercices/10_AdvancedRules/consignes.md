# Consignes level 10
## Apprentissage de règles ++

Présentation des wild-cards, des case-insensitive-strings, des expression régulière, ou des opérateurs spéciaux et bien d'autres fonctionnalités.

### Strings

Il y a trois type de string dans YARA :
- les strings hexadecimal 
- les strings de texte

#### Strings Hexadécimal

Il y a quatres type de construction possible avec les strings hexadécimal qui apportent plus de fléxibilité 

- Wild card
- not operator
- jumps
- alternatives

#### Wild-Card

Une wild card, indiqué par l'opérateur **?** dans le code hexa permet d'indiquer que tous les caractères peuvent matcher à cet endroit. 

```
rule WildcarExample
{
    strings:
        $hex_strings = { 54 ?? 78 74 65 20 69 6D 70 6F 72 74 61 6E 74 20 3? 20 65 6E 20 6C 61 74 69 6E }

    condition:
        $hex_string
}

```

Exercice d'utilisation des wilds card sur pour la recehrche de fichier avec une structure similaire

#### not operator
<span style="font-size:20px;color:red">
SEULEMENT à partir de la 4.3
</span>

Le not operator représenté par ~ permet d'indiquer qu'on cherche tous sauf ce caractère. 

```
rule NotExample
{
    strings:
        $hex_string = { F4 23 ~00 62 B4 }
        $hex_string2 = { F4 23 ~?0 62 B4 }
    condition:
        $hex_string and $hex_string2
}
```
Ici $hex_string est détecté si le byte n'est pas 00 et $hex_string2 si le second le chiffre de l'hexa n'est pas 0.

Exercice d'utilisation du not operator

#### Jump

Comme les wildcard mais permet de passer des paquets variable de byte

```
rule JumpExample
{
        strings:
            $hex_string = { F4 23 [4-6] 62 B4 }

        condition:
            $hex_string
}
```

Attention le jump [X-Y] est tel que 0<=X<=Y, avec X,Y < 256 avant YARA 2.0

A partir de YARA 2.0 on peut également jump sans limite, d'un coté ou de l'autre :

```
rule JumpExample2
{
        strings:
            $hex_string = { F4 23 [-6] 62 B4 }
            $hex_string2 = { F4 23 [4-] 62 B4 }
            $hex_string3 = { F4 23 [-] 62 B4 }

        condition:
            $hex_string or $hex_string2 or $hex_string3
}
```
//METTRE DES EXERCICES

On peut également mettre des conditions 

```
rule AlternativeExample
{
    strings:
        $hex_string = { F4 23 ( 62 B4 | 56 ) 45 }
    
    codnition:
        $hex_string
}
```
(detecte ce qui contient F42362B445 or F4235645)
Et y introduire des wildcards

```
rule AlternativeExample2
{
    strings:
        $hex_string = { F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }
    
    codnition:
        $hex_string
}
```