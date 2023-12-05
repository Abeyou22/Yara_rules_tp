import yara

rules = yara.compile("pngrules.yar")

file_path = "yara-logo.png"

with open(file_path, "rb") as file:
    content = file.read()

matches = rules.match(data=content)

if matches:
    print("Rien à signaler le fichier est bien un PNG.")
    for match in matches:
        print(match)
else:
    print("Le fichier n'est pas un .png !")
