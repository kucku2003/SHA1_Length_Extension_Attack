from sha1 import SHA1
from sha1_length_attack import SHA1_Length_Attack

print('----------------------------------------')
# Test data
KEY = "python"
TEXT = "kucku2003@github"
EXTENDED_TEXT = "sha1_length_attack"
print(f'KEY: "{KEY}"')
print(f'TEXT: "{TEXT}"')
print(f'EXTENDED_TEXT: "{EXTENDED_TEXT}"')

print('----------------------------------------')
# Calculate MAC using my own SHA1 implementation "SHA1" from sha1.py
sha1 = SHA1()
original_MAC = sha1.getHash(KEY, TEXT)
print(f'sha1.py MAC (KEY + TEXT): {original_MAC}')

print('')
print('----------------------------------------')
print('Using original TEXT (without knowing KEY) and the original MAC value above to calculate new MAC and new TEXT used for the attack')
print('Length of key is unknown, and has to be wourked out someway, mostly brute-forced')
print('Assume, that we already know key length "len(KEY)"')
print('----------------------------------------')
# ----------------------------------------
sha1_attack = SHA1_Length_Attack()
new_TEXT,new_MAC = sha1_attack.attackSHA1(TEXT, original_MAC, EXTENDED_TEXT, len(KEY) + len(TEXT))
print(f'new TEXT: "{new_TEXT}"')
print('----------------------------------------')
print(f'new MAC: "{new_MAC}"')
print('----------------------------------------')

# Re-Calculate MAC using my own SHA1 implementation "SHA1" from sha1.py, 
# (KEY + new_TEXT)
recalculated_MAC = sha1.getHash(KEY, new_TEXT)
print(f're-calculated MAC (KEY + new_TEXT) for verification purpose: {recalculated_MAC}')

print('----------------------------------------')
if (recalculated_MAC == new_MAC):
    print('re-calculated_MAC is identical to new_MAC: ATTACK SUCCESSFUL!')
else:
    print('new_MAC is NOT identical to recalculated_MAC: ATTACK FAILED!')
