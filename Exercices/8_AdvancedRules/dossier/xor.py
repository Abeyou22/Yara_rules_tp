import os

def xor_text(input_file, output_file, key):
    try:
        # Vérification de l'existence du fichier d'entrée
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Le fichier d'entrée '{input_file}' est introuvable.")

        # Vérification de l'existence du fichier de sortie
        if not os.path.exists(output_file):
            raise FileNotFoundError(f"Le fichier de sortie '{output_file}' est introuvable.")

        # Lecture du fichier d'entrée
        with open(input_file, 'r') as file:
            content = file.read()

        # Application de XOR à chaque caractère
        encrypted_content = ''.join(chr(ord(char) ^ key) for char in content)

        # Écriture du contenu chiffré dans le fichier de sortie
        with open(output_file, 'w') as file:
            file.write(encrypted_content)

        print(f"Le fichier chiffré '{output_file}' a été créé avec succès.")
    except FileNotFoundError as e:
        print(f"Erreur : {e}")
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")

# Utilisation de la fonction avec un fichier d'entrée "input.txt", un fichier de sortie "output.txt"
# et une clé de chiffrement (par exemple, 5)
xor_text("input.txt", "output.txt", 5)
