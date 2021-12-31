import random
import hashlib

# 1 
def __binary_generator():
    # a -> generate random 128 bits (entropy)
    entropyNum = random.getrandbits(128)
    return entropyNum

# 2
def __shaHash(entropy):
    sha = hashlib.sha256(entropy)
    print(sha)
    first_char = string(sha)[0]
    print(first_char)




# guides process of initiation
#1
binEntropy = __binary_generator()
#2
__shaHash(binEntropy)
