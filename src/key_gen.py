import hmac
import hashlib
from ecdsa import SECP256k1
import base58
import json

# hmac sha512 isn't giving the expected output

order = SECP256k1.order

# Generate a child hardened xprv
def hardened(xprv, index):
    return

# Generate a child xprv
def CKDprv(xprv, xpub, index):
    if index >= pow(2, 31):
        return hardened(xprv, index)
    
    # Decode xprv/xpub, get depth, & trim xprv/xpub : START
    xprv = base58.b58decode_check(xprv).hex()
    xpub = base58.b58decode_check(xpub).hex()
    xprv = xprv[26:len(xprv)]
    depth = xpub[8:10]
    xpub = xpub[26:len(xpub)]
    # Decode xprv/xpub, get depth, & trim xprv/xpub : STOP

    # Get parent pub key & parent chain code : START
    pKey = xpub[(len(xpub)//2)-1:]
    pChain = xprv[:(len(xprv)//2)-1]
    # Get parent pub key & parent chain code : STOP

    # Get hmac-sha512 : START
    i = "{:08x}".format(index)
    keyMsg = pKey + i
    print(keyMsg)
    keyMsg = bytes.fromhex(keyMsg)
    print(keyMsg)
    pChain = bytes.fromhex(pChain)
    print(pChain)
    h = hmac.new(pChain, keyMsg, hashlib.sha512).hexdigest()
    print('hmac:\t\t'+h)
    # Get hmac-sha512 : STOP
    
    # Get child chain & child key & child depth : START
    cChain = h[(len(h)//2):]

    cKey = h[:(len(h)//2)]
    xprvKey = xprv[(len(xprv)//2)-1:]
    cKey = hex((int(cKey, 16) + int(xprvKey, 16)) % int(hex(order), 16))
    cKey = '00' + cKey[2:]

    cDepth = (int(depth, 16) + int("1", 16))
    cDepth = "{:02x}".format(cDepth)
    # Get child chain & child key & child depth : STOP

    # Get fingerprint : START
    pKeyHash = hashlib.new('sha256', bytes.fromhex(pKey)).digest()
    pKeyHash = hashlib.new('ripemd160', pKeyHash).hexdigest()

    fingerprint = pKeyHash[:8]
    # Get fingerprint : STOP

    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : START
    version = '0488ade4'
    #print('Chain Code:\t'+cChain)
    #print('Child Key:\t'+cKey)
    final = version + cDepth + fingerprint + i + cChain + cKey
    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : STOP

    print('Final:\t\t'+final)
    return final

# Generate a child xpub
def CKDpub(xpub, index):
    return

prv = 'xprv9uavBdbtr4h6voVJ6AqhePKNoBpVKznWgcyARSFDokaw3zB6dUH7U7ZJTUacXK4v8CMKcdabBKSXY2GwFfhR2f6YHCQ8tuhT2WL46TvHW5x'
pub = 'xpub68aGb98ngSFQ9HZmCCNi1XG7MDeyjTWN3qtmDpeqN67uvnWFB1bN1usnJjsJSHxcsBdv4z7CmShKdWrewmQNKAqmwCArbfofGbFQyNpB8kF'
expected = 'xprv9wmw7FYNj8qzTMFiCUYinypUBKEMHKy7woTyGZhPbwFN3ichLiEjWjZtHEGh7bziJYaZLheUZUfRufPAKrPRkZvoiKnhjchsv3CBJohZsEV'
expected = base58.b58decode_check(expected).hex()

if (expected == CKDprv(prv, pub, 0)):
    print('YEP')
else:
    print('NOPE')

print('Target: \t'+expected)