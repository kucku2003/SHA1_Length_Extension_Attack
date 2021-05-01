from sha1 import SHA1
from sha1_length_attack import SHA1_Length_Attack

print('----------------------------------------')
# Test data
key = "python"
text = "kucku2003@github"
extendedText = "sha1_length_attack"
print(f'key: "{key}"')
print(f'text: "{text}"')
print(f'extended text: "{extendedText}"')

print('----------------------------------------')
# Calculate MAC using my own SHA1 implementation "SHA1" from sha1.py
sha1 = SHA1()
original_MAC = sha1.getHash(key, text)
print(f'sha1.py MAC (key + text): {original_MAC}')

print('')
print('----------------------------------------')
print('Using text string and the original MAC value above to calculate new MAC and required added hex string')
print('Length of key is unknown, but can be brute-forced')
print('Assume, that we already know key length "len(key)"')
print('----------------------------------------')
# ----------------------------------------
sha1_attack = SHA1_Length_Attack()
addedHexString,new_MAC = sha1_attack.attackSHA1(text, original_MAC, extendedText, len(key) + len(text))
print(f'added HEX string text: "{addedHexString}"')
print('----------------------------------------')
print('new MAC: ' + new_MAC)
print('----------------------------------------')

# Re-Calculate MAC using my own SHA1 implementation "SHA1" from sha1.py, 
# (key + text + addedHexString + extendedText)
recalculated_MAC = sha1.getHash(key, text + addedHexString + extendedText)
print(f're-calculated MAC (key + text + addedHexString + extendedText): {recalculated_MAC}')

print('----------------------------------------')
if (recalculated_MAC == new_MAC):
    print('recalculated_MAC is identical to new_MAC: SUCCESSFUL!')
else:
    print('new_MAC is NOT identical to recalculated_MAC: FAILED!')
