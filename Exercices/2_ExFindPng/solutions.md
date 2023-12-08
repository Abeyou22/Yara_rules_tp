# Trouve le PNG (Solutions)
## Détection d'un fichier PNG

- L'un des deux fichiers n'est pas un PNG lequel, et quel est sa véritable extension ?

Pour répondre à cette question il suffit de taper la commande "file" suivis du nom de vos fichiers dans votre terminal et il vous affichera différentes informations sur le fichier en question dont l'extension du fichier (ici le deuxième fichier est un .JFIF).

```bash
┌──(kali㉿kali)-[~/Yara_rules_tp/Exercices/2_ExFindPng/fichiers]
└─$ file yaralogo.png yara-logo.png 
yaralogo.png:  JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, progressive, precision 8, 1798x859, components 3
yara-logo.png: PNG image data, 299 x 300, 8-bit colormap, non-interlaced
```
<br></br>

- Créer 2 règles Yara, une pour chaque extension (PNG et l'autre extension)

Les 2 règles en question :

```c
rule png_file {
        strings:
                $a = {89 50 4E 47} 
        condition:
                $a
}

rule jfif_file {
        strings:
                $a = {FF D8 FF E0 ?? ?? 4A 46 49 46 00} 
        condition:
                $a
}
```