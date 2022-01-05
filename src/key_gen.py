import hmac
import hashlib
import ecdsa
# import SECP256k1, SigningKey, VerifyingKey
import keys
import json

order = ecdsa.SECP256k1.order

# Generate a child hardened xprv
def hardened(xprv, index):
    # Decode xprv/xpub, get depth, & trim xprv/xpub : START
    prv = keys.xKey(xprv)
    # Decode xprv/xpub, get depth, & trim xprv/xpub : STOP

    # Get hmac-sha512 : START
    i = "{:08x}".format(int(index))
    keyMsg = prv.key + i
    keyMsg = bytes.fromhex(keyMsg)
    h = hmac.new(bytes.fromhex(prv.chain), keyMsg, hashlib.sha512).hexdigest()
    # Get hmac-sha512 : STOP
    
    # Get child chain & child key & child depth : START
    cChain = h[(len(h)//2):]

    cKey = h[:(len(h)//2)]
    cKey = hex((int(cKey, 16) + int(prv.key, 16)) % int(hex(order), 16))
    cKey = '00' + cKey[2:]

    cDepth = (int(prv.depth, 16) + int("1", 16))
    cDepth = "{:02x}".format(cDepth)
    # Get child chain & child key & child depth : STOP

    # Get fingerprint : START
    pKeyHash = hashlib.new('sha256', bytes.fromhex(prv.key)).digest()
    pKeyHash = hashlib.new('ripemd160', pKeyHash).hexdigest()

    fingerprint = pKeyHash[:8]
    # Get fingerprint : STOP

    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : START
    version = '0488ade4'
    final = version + cDepth + fingerprint + i + cChain + cKey
    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : STOP

    print('Final:\t\t'+final)
    return final

# Generate a child xprv
def CKDprv(xprv, index):
    if index >= pow(2, 31):
        return hardened(xprv, index)
    
    prv = keys.xKey(xprv)

    pKey = keys.PrvKeyToPubKey(prv.key)

    # Get hmac-sha512 : START
    i = "{:08x}".format(int(index))
    keyMsg = pKey + i
    keyMsg = bytes.fromhex(keyMsg)
    h = hmac.new(bytes.fromhex(prv.chain), keyMsg, hashlib.sha512).hexdigest()
    # Get hmac-sha512 : STOP
    
    # Get child chain & child key & child depth : START
    cChain = h[(len(h)//2):]

    cKey = h[:(len(h)//2)]
    cKey = hex((int(cKey, 16) + int(prv.key, 16)) % int(hex(order), 16)) # modulus of the order of the curve handles the overflow of the addition
    cKey = '00' + cKey[2:]

    cDepth = (int(prv.depth, 16) + int("1", 16))
    cDepth = "{:02x}".format(cDepth)
    # Get child chain & child key & child depth : STOP

    # Get fingerprint : START
    pKeyHash = hashlib.new('sha256', bytes.fromhex(pKey)).digest()
    pKeyHash = hashlib.new('ripemd160', pKeyHash).hexdigest()

    fingerprint = pKeyHash[:8]
    # Get fingerprint : STOP

    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : START
    version = '0488ade4'
    final = version + cDepth + fingerprint + i + cChain + cKey
    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : STOP

    print('Final:\t\t'+final)
    return final

# Generate a child xpub (Doesnt work right now, need to look into EC math)
# NOT OPERATIONABLE, DO NOT USE
def CKDpub(xpub, index):
    if index >= pow(2, 31):
        raise ValueError('For CKDpub, index cannot be int hardened range.')

    # Decode xprv/xpub, get depth, & trim xprv/xpub : START
    pub = keys.xKey(xpub)
    # Decode xprv/xpub, get depth, & trim xprv/xpub : STOP

    # Get hmac-sha512 : START
    i = "{:08x}".format(int(index))
    keyMsg = pub.key + i
    keyMsg = bytes.fromhex(keyMsg)
    h = hmac.new(bytes.fromhex(pub.chain), keyMsg, hashlib.sha512).hexdigest()
    # Get hmac-sha512 : STOP
    
    # Get child chain & child key & child depth : START
    cChain = h[(len(h)//2):]

    # Good til this point...
    # Multiply the tweak (first half of HMAC) by the generator point, then add the result to the parent pub key
    # Fuck with Gx & Gy, see if you can get an expected output
    cKey = keys.PrvKeyToPubKey(h[:len(h)//2])
    cKey = hex(int(cKey, 16) + int(pub.key, 16))
    if (int(cKey[-2:], 16) % 2 == 0):
        cKey = '02' + cKey[2:]
    else:
        cKey = '03' + cKey[2:]

    cDepth = (int(pub.depth, 16) + int("1", 16))
    cDepth = "{:02x}".format(cDepth)
    # Get child chain & child key & child depth : STOP

    # Get fingerprint : START
    pKeyHash = hashlib.new('sha256', bytes.fromhex(pub.key)).digest()
    pKeyHash = hashlib.new('ripemd160', pKeyHash).hexdigest()

    fingerprint = pKeyHash[:8]
    # Get fingerprint : STOP

    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : START
    final = pub.version + cDepth + fingerprint + i + cChain + cKey
    # Combine to final package (xprv + depth + fingerprint + index + cChain + cKey) : STOP

    print('Final:\t\t'+final)
    return final

'''
priv = 'xprv9vhJ3aEz7keXTpC3bUDfGrQBjgAJr9hohheGL2eSwB3LrVqJc69WFzMZWaBYQ87rAfkhip8A6AsABoNx93VnDA22oteyu8HzuhnFSbJzK2W'
pub = 'xpub69geT5msx8CpgJGWhVkfdzLvHhzoFcRf4vZs8R44VWaKjJAT9dTkong3Ms6Q5JtDC8zzq1e1EWczjwDUsxvDMkhxDwsrbPh2RQePpTu7BEZ'
expected = 'xpub6ASUhyiibqNpVQA8UHx8zUBDacwCcLWggPA2jgCsj5EgEMkr2ha65c2QrLxmgBSBkf5VW8Q9Dg1nBkzYPukV5pKT2pLGpDfBXsUqH5pyFVq'
expected = keys.xKey(expected)

if (expected.getKey() == CKDpub(pub, 0)):
    print('YEP')
else:
    print('NOPE')

print('Target: \t'+expected.getKey())
'''