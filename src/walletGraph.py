# The wallet class will at minimum contain an array of xprv/xpub/address pairs, relevent functions may be developed later

# May create a node class that keeps those details. Node classes will have a key which corresponds to their parent, index, and depth ordering
# meaning they will each have an xprv

# Need to install anytree & graphviz to run

from src import keys # Change to "from src import keys" when ready for use in main
from anytree import Node, RenderTree
from anytree.exporter import DotExporter
from graphviz import render

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