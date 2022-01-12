import platform
import src
import os.path

# 1 -> create the master priv key + master chain code
wallet = list()


osys = platform.system().lower()
route = ""

if(osys == "darwin"):
    route = 'resources/wallet_keys.pickle'
elif(osys == "windows"):
    route = 'resources\wallet_keys.pickle'
else:
    print('OS not loaded into program. Maybe later.')

if not os.path.exists(route):
    wallet.append(src.in_it_wallet())
    src.writeKey(wallet)
else:
    wallet = src.loadWallet()

userIn = ''
tempDerived = None
while userIn != 'exit':
    userIn = input("Enter a key path (ex: m/0 or m/0'/0): ")
    userIn = userIn.split('/')

    # Loop through the key path
    # Each execution passes in the current key as the key in CKDprv and the next string of userIn as the index
    for i in (range(len(userIn)-1)):
        # Check if hardened range
        if userIn[i+1][-1:] == "'":
            index = int(userIn[i+1][:len(userIn[i+1])-1]) + int('80000000', 16)
        else:
            index = int(userIn[i+1])

        # If it's the initial execution, use master key, else use the previous key (tempDerived)
        if i == 0:
                tempDerived = src.CKDprv(wallet[0].getKey(), index)
        else:
            tempDerived = src.CKDprv(tempDerived.getKey(), index)
            
            # Check if the the key to be derived is in wallet already
        if tempDerived not in wallet:
            wallet.append(tempDerived)
            
    src.writeKey(wallet)
    src.buildTree(wallet)





'''
    print(wallet[0].key)
    print(wallet[1].key)
    print(wallet[2].key)
'''