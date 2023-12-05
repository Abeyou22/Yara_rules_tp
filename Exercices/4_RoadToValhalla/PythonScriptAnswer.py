



import yara

rules = yara.compile('/home/kali/Documents/Yara_rules_tp-main/Exercices/4_RoadToValhalla/solutionlValhalla.yar')

#total de règles
nombre_regles = 0
# Compter le nombre total de règles en itérant sur chaque règle
for rule in rules:
    nombre_regles += 1

# - Combien de règle de type suspicious ? (Score : 60-74) ?
nombre_suspicious_rules = 0
for rule in rules : 
    if (60 <= rule.meta['score'] <= 74):
        nombre_suspicious_rules +=1
        
#  Donnez 6 tags utilisés par l'API.
listTag = []
for rule in rules:
    listTag.append(rule.tags)
#print (listTag[:6])
                                                                                                  
#Combien de règles comportent le tag 'MIDDLE_EAST' ?  
# C'est nul le for dans le for mais j'ai un peu la flemme de faire ça proprement 
rules_middle_east = 0
for rule in rules:
    tags =rule.tags
    for oneTag in tags:                  
        if oneTag == "MIDDLE_EAST":
            rules_middle_east +=1                               
"""
#Combien de règles sortent avec le keyword '2023_24055'
nombre = 0       
for rule in rules : 
    #print(rule.data("2023_24055"))
    if '2023_24055' in rule.strings : 
    #print(rule.get_rules_text(search="2023_24055"))
        nombre +=1 
      
"""
# Afficher les reusltat
print(f"Nombre total de règles : {nombre_regles}")
print(f"Nombre de règles de type suspicious (score : 60-74) : {nombre_suspicious_rules}")                                             
print(f"Six tags utilisés par l'API : {listTag[:6]}")
print(f"Nombre de règles comportant le tag 'MIDDLE_EAST' : {rules_middle_east}")
#print(f"Nombre de règles avec le keyword '2023_24055' : {nombre}")
