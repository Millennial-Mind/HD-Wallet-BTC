import hashlib
import base58

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Takes type of bytes
def b58Check_Key(payload):
    version = b'\x80'

    step1 = bytes(version + payload)
    payload = hashlib.sha256(step1).hexdigest()
    payload = hashlib.sha256(payload.encode()).digest()
    payload = step1 + payload[0:8]
    temp = payload.hex()

    payload = base58.b58encode(payload)
    return payload

# Not done
def b58Check_Addr(payload):
    version = 0x00
    sb = ''
    while (payload > 0):
        r = payload % 58
        sb = sb + ALPHABET[r]
        payload = payload // 58
    return sb[::-1]