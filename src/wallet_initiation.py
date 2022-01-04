#import random
import secrets     #to generate actual random bits
import linecache   #to rid of '\n' in strings
import keys        #for prv key formatting 
import hashlib     #hashing everything below
import hmac
import os, binascii
from backports.pbkdf2 import pbkdf2_hmac
#from passlib.hash import pbkdf2_sha512



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
def binary_conversion(__string):
    binary_string = ""
    for i in __string:
        binary_string +="{0:04b}".format(int(i, 16))
    return binary_string

#4 
def split(__segment_str):
    segments = [] 
    seg_str = ""

    counter = 0 #every 11 counts, create new str
    for i in __segment_str:
        counter += 1
        seg_str += i

        if(counter == 11): # new segment / reset values
            segments.append(seg_str)
            seg_str = ""
            counter = 0

    return segments     

#5  
def get_wordList(binary_segments):
    word_segments = ""

    #convert all binary 11-bit segments into decimal
    for e in binary_segments: 
        specific_line = helper_binary2decimal(e) #need decimal value

        line_txt = linecache.getline("resources/wordlist.txt", specific_line)
        #word_segments.append(line_txt.strip()) <-- for list implementation
        word_segments += line_txt.strip() + " "

    return word_segments

def helper_binary2decimal(bin_segment):

    decimal = 0
    exp_counter = 0

    for i in bin_segment:
       int_val = int(i) * 2**exp_counter
       decimal += int_val
       exp_counter += 1 #increment
    
    if exp_counter != 11:
        raise RuntimeError("There should be 11 bits in each Segment")   

    return decimal





#==============  START  =================#
def in_it_wallet():
    #1 Generate 128 Bit Entropy -> result is in decimal(base10) format
    entropy = __entropy_generator()

    #2 Get sha256 entropy string & take first 4 bits(<- == checksum)
    checksum = __shaHash(entropy)

    #3 Add entropy + checksum == 132 bit string
    segment_string = binary_conversion(str(entropy)) + binary_conversion(checksum)

    #4 Create 12 11-bit segments
    segments = split(segment_string)

    #5 Match with corresponding mnemonic word (BIP39)
    phrase = get_wordList(segments)

    #6 Prompt user for salt phrase (optional)
    salt = input("Enter Salt phrase for Seed generation (*If no salt phrase, press enter*): ") 
    salt = "mnemonic" + salt

    #7 hmac-sha512 full phrase to get seed
    phrase = phrase.encode("utf8")
    salt = bytes(salt, 'UTF-8')
    root_seed = hashlib.pbkdf2_hmac('sha512', phrase, salt, 2048, 64)
    #print("root seed ---> ", root_seed.hex())
    #visual testing + additional contens for #7, see below

    #8 split root seed to get master private key && Master chain code
    root_str = str(root_seed.hex())
    master_privK = root_str[:len(root_str)//2]
    master_chainCode = root_str[len(root_str)//2:]
    #visual testingfor #8, see below

    #9 create key obj 
    master_key = keys.xKey() #keys obj
    master_key.key = '00' + master_privK




















# 7 Continued ->
# to test consistent outputL:
'''
tempPhrase = "army van defense carry jealous true garbage claim echo media make crunch"
tempPhrase = tempPhrase.encode("utf8")
print(tempPhrase)
tempSalt = "mnemonicSuperDuperSecret"
tempSalt = bytes(tempSalt, 'UTF-8')
print(tempSalt)
seed = hashlib.pbkdf2_hmac('sha512', tempPhrase, tempSalt, 2048, 64)
print("master seed ---> ", seed.hex())
print("size in bytes --> ", len(seed.hex()))

** output should be: b5df16df2157104cfdd22830162a5e170c0161653e3afe6c88defeefb0818c793dbb28ab3ab091897d0715861dc8a18358f80b79d49acf64142ae57037d1d54
'''
# another route for computting master seed
'''
salt2 = binascii.unhexlify(salt) <- may need to be reworked
phrase2 = phrase.encode()
key = pbkdf2_hmac('sha512', phrase2, salt2, 2048, 64)
print("Derived key:", binascii.hexlify(key).decode())
'''

# 8 Continued ->
# testing output in console
'''
root_str = str(root_seed.hex())
s1 = root_str[:len(root_str)//2]
s2 = root_str[len(root_str)//2:]
print('First Half  --> ', str(s1), '\nSecond Half --> ', str(s2))
print('First Half Size--> ', len(s1), ' :  Second Half Size--> ', len(s2))
'''