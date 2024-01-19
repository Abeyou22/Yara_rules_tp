# Consignes level 10
## Apprentissage de règles ++

Apprentissage de règles YARA
Présentation des wild-cards, des case-insensitive-stringset de quelques opérateurs spéciaux
https://forms.office.com/e/Cc0YEMCchg

### Strings

Il y a trois type de string dans YARA :
- ASCII strings
- Wide Strings
- Hexa Strings 

#### Strings Hexadécimal

Il y a quatres type de construction possible avec les strings hexadécimal qui apportent plus de fléxibilité 

- Wild card
- not operator
- jumps
- alternatives

##### Wild-Card

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

**Ecrivez une règle YARA qui detecte les 3 fichiers text1, text2 et text3 grâce aux wildcards**
**Ecrivez une règle YARA qui detecte les fichiers text1 et text2 grâce aux wildcards**

##### not operator
<span style="font-size:20px;color:red">
SEULEMENT à partir de la version 4.3
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

**Outre leur noms les fichiers text1, text2 et text3 on des points communs lesquels ?**
**Ecrivez une règle YARA qui detecte les fichiers similaire a text1 mais qui n'est pas text1 grâce aux not operator**
**Ecrivez une règle YARA qui exclue les fichiers strictement similaire a text1 grâce aux not operator**

##### Jump

Comme les wildcard, mais permet de passer un paquets variable de byte entre deux bloc de byte.

Ici on passe 4 à 6 byte

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
##### Conditions

On peut également mettre des conditions 

```
rule AlternativeExample
{
    strings:
        $hex_string = { 69 6E 0A ( 0A | 20 20 ) 4C 6F }
    
    condition:
        $hex_string
}
```
(detecte ce qui contient 696E0A0A4C6F or 696E0A20204C6F)

On peut introduire des wildcard ou rajouter des conditions alternatives, il n'y a pas de limite sur la taille des séquences alternatives ou un nombre maximum de condition.

```
rule AlternativeExample2
{
    strings:
        $hex_string = { F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }
    
    condition:
        $hex_string
}
```

#### Strings Text
Plutôt que de rechercher des paternes sur l'écritures hexa décimale des fichiers, nous avons vu qu'il était possible de rechercher directement du texte.

Il faut noté que les textes contiennent des caractères spéciaux de mise en page ou de ponctuation:

 \\" : Double quote 
&#92; &#92; : Backslash 
\r : retour à la ligne
\t  : Tab 
\n : Nouvelle ligne 
\xdd : Un byte en hexa 

```
rule stringText{

    strings:
        $hex_string = "Je te l'avais dit :\r"
   
    condition:
        $hex_string
}
```

**Ecrivez une règle YARA, permettant de détecter un texte contenant des caractères de tabulation**

##### Casse

Les strings Yara sont sensible à la casse par default, c'est à dire qu'il différencie les lettres capitales et minuscule.

```
rule noCase{

    strings:
        $hex_string = "MorBi" nocase
   
    condition:
        $hex_string
}
```
ici la règle toutes les écritures possible de Morbi, morbi, MORBI ....

**Ecrivez une règles qui indique quel texte contient "NOn uRna At"**

#### XOR

Il est possible de detecter un strings qui a été obfusqué avec une opération xor bit à bit en ajoutant `xor` à la suite de la string recherché 
```
rule XorExample{
    strings:
        $xor_string = "Rvbmg#of#`kbw#pf#obuf/#jo#ub#sofvuljq" xor
    
    condition:
        $xor_string
}
```
Ainsi la règle ci-dessus permet de detecter tous les encodage de "La règle XorExample ci-dessous, permet de 
" 

**textXor.txt est l'un des fichier suivant text1, text2 ou text3, ayant subit une opération xor. Ecrivez une regle qui vous permet d'identifier lequel.**
