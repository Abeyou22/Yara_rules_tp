import yara

rules = yara.compile("pngrules.yar")

file_path = "./fichiers/yara-logo.png"

with open(file_path, "rb") as file:
    content = file.read()

matches = rules.match(data=content)

if matches:
    print("Le fichier n'est pas un .png !")
    for match in matches:
        print("String Matché : {}".format(match['string']))
        print("Métadonnées : {}".format(match['meta']))
else:
    print("Rien à signaler, le fichier est bien un PNG.")

