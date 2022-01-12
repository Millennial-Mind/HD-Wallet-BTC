# Contains function for handling the wallet file. Should write keys to the file, fetch the file (and build the wallet list)
import os
import pickle
import platform

def writeKey(key):
    os = get_OS()
    with open(os, 'wb') as wk:
        wk.seek(0)
        pickle.dump(key, wk, -1)

def loadWallet():
    os = get_OS()
    with open(os, 'rb') as wk:
        t = pickle.load(wk)
    return t

def get_OS():
    os = platform.system().lower()
    
    if(os == "darwin"): #MacOS
        return 'resources/wallet_keys.pickle'
    elif(os == "windows"):
        return 'resources\wallet_keys.pickle'
    else:
        raise RuntimeError('OS not loaded into program. Maybe later.')