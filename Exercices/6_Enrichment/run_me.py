import yara

rules = yara.compile("pngrules.yar")

file_path = "./fichiers/yara-logo.png"

with open(file_path, "rb") as file:
    content = file.read()

matches = rules.match(data=content)

if matches:
    print(f"Le fichier '{file_path}' n'est pas un PNG ! :")
    for match in matches:
        print("Règle: ", match.rule)
        print("Métadonnées: ", match.meta)
        print("String qui a matché : " + str(match.strings[0]))
        print("-" * 40)
else:
    print("C'est un PNG.")
