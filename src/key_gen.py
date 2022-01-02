from contextlib import nullcontext
from ctypes import sizeof
import hmac
import hashlib
import ecdsa
import b58
import base58
import json

# hmac sha512 isn't giving the expected output

order = ecdsa.SECP256k1.order

# Generate a child hardened xprv
def hardened(xprv, index):
    return

# Generate a child xprv
def CKDprv(xprv, xpub, index):
    if index >= pow(2, 31):
        hardened(xprv, index)
        return
    xpub = base58.b58decode_check(xpub).hex()
    print(xpub)
    xpub = xpub[26:len(xpub)]
    key = xpub[:len(xpub)//2]
    # print('xpub key: ' + key)
    chain = xpub[len(xpub)//2:]
    # print('xpub chainkey: ' + chain)

    i = "{:08x}".format(index)
    key += i

    key = key.encode()
    # print(key)
    chain = chain.encode()
    # print(chain)
    h = hmac.new(chain, key, hashlib.sha512).digest()
    

    # h = base58.b58encode_check(h)
    # print('actual: ' + h.decode())
    print(h.hex())
    return h.hex()

# Generate a child xpub
def CKDpub(xpub, index):
    return

prv = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
pub = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
expected = 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
expected = base58.b58decode_check(expected).hex()
expected = expected[26:len(expected)]

if (expected == CKDprv(prv, pub, 0)):
    print('YEP')
else:
    print('NOPE')

print('expected: '+expected)

"""
hkey = b'2A7857631386BA23DACAC34180DD1983734E444FDBF774041578E9B6ADB37C19'
message = b'003C6CB8D0F6A264C91EA8B5030FADAA8E538B020F0A387421A12DE9319DC9336880000002'
h = hmac.new(hkey, message, hashlib.sha512).hexdigest()
print(h)
"""