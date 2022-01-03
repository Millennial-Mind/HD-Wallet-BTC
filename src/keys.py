from base58 import b58decode_check
from ecdsa import SigningKey, SECP256k1

class xKey:
    def __init__(self, payload = ''):
        if (len(payload) != 0) and (len(payload) != 111) and (len(payload) != 156):
            raise ValueError('Payload for xKey not of a recognized length.')
        if type(payload) is not str:
            raise TypeError('Payload for xKey not of a recognized type.')
        # Default values to none
        if (payload == ''):
            self.version = None
            self.depth = None
            self.fingerprint = None
            self.index = None
            self.chain = None
            self.key = None
        # If in WIF format, decode and parse
        elif 'xpub' in payload or 'xprv' in payload:
            temp = b58decode_check(payload).hex()
            self.version = temp[:8]
            self.depth = temp[8:10]
            self.fingerprint = temp[10:18]
            self.index = temp[18:26]
            self.chain = temp[26:90]
            self.key = temp[90:]
        # Otherwise, assume the payload to be in hex format
        else:
            self.version = payload[:8]
            self.depth = payload[8:10]
            self.fingerprint = payload[10:18]
            self.index = payload[18:26]
            self.chain = payload[26:90]
            self.key = payload[90:]
    def getKey(self):
        return self.version + self.depth + self.fingerprint + self.index + self.chain + self.key

# Converts a private key to a compressed public key
def PrvKeyToPubKey(prv):
    # Shave '00' prefix & convert to bytes
    if (len(prv) > 64):
        prv = bytes.fromhex(prv[2:])
    else:
        prv = bytes.fromhex(prv)

    # Calculate the uncompressed public key
    pubKey = SigningKey.from_string(prv, curve=SECP256k1).verifying_key
    pubKey = '04' + pubKey.to_string().hex()

    # Determine compressed public key prefix ('02' if even, '03' if odd)
    if (int(pubKey[-2:], 16) % 2 == 0):
        temp = '02'
    else:
        temp = '03'

    # Final compressed public key package
    pubKey = temp + pubKey[2:66]

    return pubKey

# Converts xprv to xpub (version is swapped & compressed pub key replaces private key)
def Neuter(xprv):
    if type(xprv) is not xKey:
        raise TypeError('Neuter only accepts xKey input.')
    temp = xKey(xprv.getKey())
    temp.version = '0488b21e'
    temp.key = PrvKeyToPubKey(xprv.key)
    return temp