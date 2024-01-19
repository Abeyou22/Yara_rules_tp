def xor_crypt_string(data, key):
    encrypted_text=""
    for char in data:
        encrypted_text += chr(ord(char)^key)
    return encrypted_text

#=open("dossier/text2.txt", "r")
#b=a.read()
c=int(input("La clef de dechiffrement:\n"))
#d=open("dossier/textXor.txt", 'w')
#d.write(xor_crypt_string(b,c))

print(xor_crypt_string("Quand le chat se lave, il va pleuvoir",c))