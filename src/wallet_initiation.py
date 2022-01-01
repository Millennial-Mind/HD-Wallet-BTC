import random
import secrets
import hashlib

# 1 
def __entropy_generator():
    # a -> generate random/secret 32 bytes (128 bits)
    entropyNum = ""
    for i in range(32):
        random = secrets.randbelow(9)
        entropyNum = entropyNum + str(random)
    return entropyNum  # string in decimal(Base10) format

# 2
def __shaHash(entropy):
    # encode entropy for sha parameter
    encoded = str(entropy).encode()
    # hash, goal is to take first 4 bits for checksum
    sha = hashlib.sha256(encoded)
    # save (string) hexadecimal format of sha 
    first_char = sha.hexdigest()[0]
    return first_char

#3
def binary_conversion(string):
    binary_string = ""
    for i in string:
        binary_string = binary_string + "{0:04b}".format(int(i, 16))
    return binary_string


#1 Generate 128 Bit Entropy -> result is in decimal(base10) format
entropy = __entropy_generator()

#2 Get sha256 entropy string & take first 4 bits(<- == checksum)
checksum = __shaHash(entropy)

# 3 Add entropy + checksum == 132 bit string
segment_string = binary_conversion(str(entropy)) + binary_conversion(checksum)

print(segment_string)
print(len(segment_string))






