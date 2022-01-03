#import random
import secrets     #to generate actual random bits
import linecache   #to rid of '\n' in strings
import hashlib     #hashing
import hmac
from passlib.hash import pbkdf2_sha512
import os, binascii


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

#7




#==============  START  =================#

#1 Generate 128 Bit Entropy -> result is in decimal(base10) format
entropy = __entropy_generator()

#2 Get sha256 entropy string & take first 4 bits(<- == checksum)
checksum = __shaHash(entropy)

#3 Add entropy + checksum == 132 bit string
segment_string = binary_conversion(str(entropy)) + binary_conversion(checksum)

if len(segment_string) != 132:
    raise RuntimeError("Entropy + Checksum should be 132 bits. Instead length is -> ", len(segment_string))

#4 Create 12 11-bit segments
segments = split(segment_string)

#5 Match with corresponding mnemonic word (BIP39)
phrase = get_wordList(segments)

#6 Prompt user for salt phrase (optional)
salt = input("Enter Salt phrase for Seed generation (*If no salt phrase, press enter*): ")
full_phrase = phrase
if len(salt) != 0:
    full_phrase += salt

print(full_phrase)    

#7 hmac-sha512 full phrase to get seed
full_phrase_bytes = bytes(full_phrase, 'UTF-8')

pb.encode(phrase, 2048)
print(pb)

#seed = pbkdf2(phrase, salt, 2048, hashlib.sha512(), 512)
salt = binascii.unhexlify(salt)
phrase = phrase.encode("utf8")


key = pbkdf2_hmac("sha256", passwd, salt, 50000, 32)


#salt = binascii.unhexlify('aaef2d3f4d77ac66e9c5a6c3d8f921d1')
#passwd = "p@$Sw0rD~1".encode("utf8")
#key = pbkdf2_hmac("sha256", passwd, salt, 50000, 32)
#print("Derived key:", binascii.hexlify(key))