# The wallet class will at minimum contain an array of xprv/xpub/address pairs, relevent functions may be developed later

# May create a node class that keeps those details. Node classes will have a key which corresponds to their parent, index, and depth ordering
# meaning they will each have an xprv

# Need to install anytree & graphviz to run

from src import keys # Change to "from src import keys" when ready for use in main
from anytree import Node, RenderTree
from anytree.exporter import DotExporter
from graphviz import render

"""
class Wallet:
    # Constructor
    def __init__(self):
        self.walVallues = dict(xprv=None, xpub = None, addr = None)
"""

# Bro looks like we might not need a wallet cuz i looked at that for like 20 minutes and don't think we need more than that 
# I'll just try to build something that'll build a tree out of a dictionary handed to it given the above data (assuming xprv and xpub are of an xKey type)
# Might then lead this into file reading so that files can simply be read from here automatically then constructed into the tree

# maybe a wallet class could be used so that each dictionary val can be handed an xprv but build the rest or be handed an xprv+xpub and generate the addr 
# (This is essentially what was done with the xKey class)

def FindParent(wallet, fingerprint):
    for x in wallet:
        parentFingerprint = keys.getFingerprint(keys.Neuter(x).key)
        if parentFingerprint == fingerprint:
            return x
    raise Exception("Error: Parent key based on fingerprint not found")

def buildTree(wallet):
    """
    wallet = [
        keys.xKey('xprv9wqXrf5G14NKZBmmk5yBbFT7zZAhu9TsEecNmaHQdpfzUEh8RFKEnqTSc2CMvtzt26JvNjN2nZFDeqveguBe6VLQFPrWZHXyyFV12J57Gn9'), # m/0/2
        keys.xKey('xprv9s21ZrQH143K3wHJVa4qJLf9U39X9E6k8EVQmco2SPRnF1C7vZeN5epn6v2JYnV9EM5D3ovVTc8rpweHh31y41ACxE2BKyjbCSc8ygcwP3U'), # m
        keys.xKey('xprv9wAMYNQjNLC5A7QQA9H7ZkNmnUcNvT2nS7Jh7vB8Erobaa2cAV2XzLVmHwpUFAT9nnqoxzf47EYR9ViHKz2GQrKmYkGYC6GRrMUpb12XCxJ'), # m/2/1
        keys.xKey('xprv9vbNpzu8fPcJHDyzEQYwnc7LxAq5hW7G9KeKXauq94tWBbsgFq5UViU2LZkBqwnqDFXUhBLMd6RVgWxrDKU5v6XAv8TyGv9aQF4eoFAefjn'), # m/0
        keys.xKey('xprv9vbNpzu8fPcJQYtLGYGYaazbi19NATB8DSFZ7oAzauFC2zkCKjLGKWs9XK5RkQ5vH8sPmD7xGkMfC8Ncz4ZQGBpbrzX9z2Pn8J8e5FL12Fh'), # m/2
        keys.xKey('xprv9wqXrf5G14NKUGRrU8DUPFanUFdddmMkJW15oXiLic2sGTW6HJrPZ5wJ5MhENrJKAvJkfbwkGU43rwCK7n17XpuydDjEbWFiHdtfJdixVc1'), # m/0/0
        keys.xKey('xprv9wqXrf5G14NKVfegjszNHkg5hUZxcLPg5odaSKCNz9NGUR9TSyby2YoWbs8RXpkUhnSYkuyGCDH7rWHG3TJthbwhiUhaS6Vjw8SPgmarwAM'), # m/0/1
        keys.xKey('xprv9vbNpzu8fPcJMdzvt3Cj6t9khG8b1ehvTb1J9R561yHvcYz4UQcJoWe6ixLDKzeRhFuFBpBU5btxTLy9sFFLEh13m8CPjwxWsgijNcgupdB'), # m/1
        keys.xKey('xprv9wAMYNQjNLC56imfSowekLAuvvMzfKmQW1XPUToAtgXCycLkAPBsi9Pw9DeXhssXgXoLdRPRzEvYWqC5enm7hAJdFfVjzjM6Fu4vc2zXmyL'), # m/2/0
        keys.xKey('xprv9vbNpzuH149GTGgnL3kjmVUX6mVTTFanegE9aeM3TLJHYKnzscPJa9yX4ayWXHkK9YUKbJKo1mzUL5ANGo1kreGdz32BKkJq9VTJRscrEup'), # m/0'
        keys.xKey('xprv9wpvXztym6r93JWXBHSgKtdkLqgnza5eAgi6qRCNFTZ3iJ7BWzRoq2pZzZ7P3o3SugynBR7th5thWJt4HaLZ8SoLWc3MzNToDEk7rod3PqF')  # m/0'/1
    ]
    """

    walletTree = list()

    # Sort by depth, index, then fingerprint
    wallet.sort(key=lambda x: (x.xDepth, x.index, x.fingerprint))

    # Create the walletTree list
    for x in wallet:
        if x.xDepth == "00":
            walletTree.append(keys.xKeyNode(x.getKey(), parent=None))
        else: 
            walletTree.append(keys.xKeyNode(x.getKey(), parent=FindParent(walletTree, x.fingerprint)))

    # Make a graph image of the tree structure
    print("Exporting wallet.dot...")
    DotExporter(walletTree[0]).to_dotfile("wallet.dot")
    print("Rendering wallet.png...")
    render('dot', 'png', 'wallet.dot')
    return walletTree