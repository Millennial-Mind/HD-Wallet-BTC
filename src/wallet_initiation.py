import random
import hashlib

# 1 
def __entropy_generator():
    # a -> generate random 128 bits (entropy)
    entropyNum = random.getrandbits(128)
    return entropyNum  # string in decimal(Base10) format

# 2
def __shaHash(entropy):
    # encode entropy for sha parameter
    encoded = str(entropy).encode()
    sha = hashlib.sha256(encoded)
    # save (string) hexadecimal format of sha 
    first_char = sha.hexdigest()[0]
    # get binary of first char == checksum
    checksum = "{0:04b}".format(int(first_char, 16))
    return checksum




# guides process of initiation
#1 Generate 128 Bit Entropy -> result is in decimal(base10) format
entropy_Dec = __entropy_generator()
#2 Sha256 Entropy + take first 4 bits(<- == checksum)
checksum = __shaHash(binEntropy)
# 3 Add entropy + checksum == 132 bit string
binEntropy = str(binEntropy) + str(checksum)
print(binEntropy)



CREATEA BINARY GENERATOR FOR CHECKSUM AND ENTROPY DEC. CAN PASS IN AN ARRAY AND THEN LOOOP THROUGH AND CONTINOUSLY ADD 4 DIDIGT BINARIES ONTO A STRING



