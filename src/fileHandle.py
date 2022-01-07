# Contains function for handling the wallet file. Should write keys to the file, fetch the file (and build the wallet list)
import json

def writeKey(key):
    with open('resources\wallet_keys', 'w') as wk:
        json.dump(key, wk)

def loadWallet():
    with open('resources\wallet_keys', 'r') as wk:
        t = json.load(wk)
    return t