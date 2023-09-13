from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key="1111111111111111111111111111111111111111111111111111111111111111")

# - Combien de règle le Valhalla possède t'il pour la démo ?
# response = v.get_rules_text()

# - Combien de règle de type suspicious ? (Score : 60-74) ?
# response = v.get_rules_text(score=75)
# response = v.get_rules_text(score=60)
# Puis soustraire le nombre résultat 60 -75

# # - Combien de règles comportent le tag 'MIDDLE-EAST' ?
response = v.get_rules_text(tags=['MIDDLE_EAST'])

# # - Combien de règles sortent avec le keyword CVE20152545
# response = v.get_rules_text(search="CVE20152545")


with open('valhalla-rules-MIDDLE-EAST.yar', 'w') as fh:
    fh.write(response)
