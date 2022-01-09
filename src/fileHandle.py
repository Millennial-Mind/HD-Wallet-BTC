# Contains function for handling the wallet file. Should write keys to the file, fetch the file (and build the wallet list)
import pickle

def writeKey(key):
    with open('resources\wallet_keys.pickle', 'wb') as wk:
        wk.seek(0)
        pickle.dump(key, wk, -1)

def loadWallet():
    with open('resources\wallet_keys.pickle', 'rb') as wk:
        t = pickle.load(wk)
    return t