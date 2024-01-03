def xor_text(input_file, output_file, key):
    try:
        # Lecture du fichier d'entrée
        with open(input_file, 'r') as file:
            content = file.read()

        # Application de XOR à chaque caractère
        encrypted_content = ''.join(chr(ord(char) ^ key) for char in content)

        # Écriture du contenu chiffré dans le fichier de sortie
        with open(output_file, 'w') as file:
            file.write(encrypted_content)

        print(f"Le fichier chiffré '{output_file}' a été créé avec succès.")
    except FileNotFoundError:
        print("Le fichier spécifié est introuvable.")
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")

# Utilisation de la fonction avec un fichier d'entrée "input.txt", un fichier de sortie "output.txt"
# et une clé de chiffrement (par exemple, 5)
xor_text("input.txt", "output.txt", 5)
