from valhallaAPI.valhalla import ValhallaAPI

v = ValhallaAPI(api_key="1111111111111111111111111111111111111111111111111111111111111111")
#response = v.get_rules_text(tags=['EXE'] )

response2 = v.get_hash_info(hash="8a883a74702f83a273e6c292c672f1144fd1cce8ee126cd90c95131e870744af")

# with open('valhalla-rules-7.yar', 'w') as fh:
#     fh.write(response)

with open('valhalla-rules-hash.yar', 'w') as fh:
    fh.write(response2)