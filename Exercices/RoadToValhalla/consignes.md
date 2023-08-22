# Consignes Road To Valhalla
## Acquisition de rule sur une API en open source

[Nextron](https://www.nextron-systems.com/products/) est une entreprise qui propose des outils d'investigation gratuit.

Dans ce court exercice nous allons nous concentrer sur Valhalla une base règle YARA. 
L'objectif est d'extraire de ValhallaAPI l'ensemble des règles YARA gratuites.

Voici les différentes documentation utiles si vous voulez chercher tous seuls:
- [Valhalla Nextron](https://www.nextron-systems.com/valhalla/) 
- [Valhalla Web](https://valhalla.nextron-systems.com/) 
- [Valhalla Github](https://github.com/NextronSystems/valhallaAPI) 
- [Valhalla Host Github](https://nextronsystems.github.io/valhallaAPI/) 

Sinon voici la marche à suivre :

Installez pip
```bash
sudo apt install python3-pip
```

Installez Valhalla API
```bash
pip install valhallaAPI
```

Créez un nouveau fichier python du style "extract.py"
Rentrez le code suivant, puis exécutez le fichier

```bash
from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key="1111111111111111111111111111111111111111111111111111111111111111")
response = v.get_rules_text()

with open('valhalla-rules.yar', 'w') as fh:
    fh.write(response)
```

- "1111111111111111111111111111111111111111111111111111111111111111" est la clef API de demo pour obtenir les règles gratuites


Vous pouvez filtrer une partie des règles à importer en intégrant une condition à  la fonction get_rules_text('condition'), exemple :

```bash
response = v.get_rules_text(score=75)
response = v.get_rules_text(search="Mimikatz")
response = v.get_rules_text(product="FireEyeEX")
response = v.get_rules_json(tags=['APT'])
```

Pour chaque condition, extrayez les règles YARA correspondantes de Valhalla.

##Questions
- Combien de règle le Valhalla possède t'il pour la démo ?
- Combien de règle de type suspicious ? (Score : 60-74) ?
- Donnez 6 tags utilisés par l'API.
- Combien de règles comportent le tag 'MIDDLE-EAST' ?
- Combien de règle 

