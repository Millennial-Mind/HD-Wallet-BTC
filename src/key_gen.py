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
    keyMsg = bytes.fromhex(pKey)
    pChain = bytes.fromhex(pChain)
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
    pKeyHash = hashlib.new('ripemd160')
    pKeyHash.update(bytes.fromhex(pKey))
    pKeyHash = pKeyHash.hexdigest()

    fingerprint = pKeyHash[:8]
    # Get fingerprint : STOP

    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : START
    print('Chain Code:\t'+cChain)
    print('Child Key:\t'+cKey)
    final = cChain + cKey
    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : STOP

    # print('Final:\t\t'+final)
    return final

# Generate a child xpub
def CKDpub(xpub, index):
    return

prv = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
pub = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
expected = 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
expected = base58.b58decode_check(expected).hex()
print(expected)
expected = expected[26:len(expected)]

if (expected == CKDprv(prv, pub, 0)):
    print('YEP')
else:
    print('NOPE')

print('Target cChain:\t'+expected[:len(expected)//2-1])
print('Target cKey:\t'+expected[len(expected)//2-1:])