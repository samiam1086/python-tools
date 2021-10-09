import base64
import string
import binascii
from binascii import unhexlify

#base64 decode function
def base64D(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.b64decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base64"

    return strToDecode

#base32 decode function
def base32D(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.b32decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base32"
    
    return strToDecode

#base16 decode function
def base16D(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.b16decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base16"

    return strToDecode

#base85Ascii decode function
def base85AsciiD(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.a85decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base85Ascii"
    
    return strToDecode

#base85 decode function
def base85D(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.b85decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base85"
    
    return strToDecode

#rot cipher decode function
def rotCipher(text, step, alphabets):

    def shift(alphabet):
        return alphabet[step:] + alphabet[:step]

    shifted_alphabets = tuple(map(shift, alphabets))
    joined_aphabets = ''.join(alphabets)
    joined_shifted_alphabets = ''.join(shifted_alphabets)
    table = str.maketrans(joined_aphabets, joined_shifted_alphabets)
    return text.translate(table)
	
#vigenere cipher
def vigenere(text, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    input_string = ""
    dec_key = ""
    dec_string = ""
    pos_list = []

    # Takes encrpytion key from user
    dec_key = key
    dec_key = dec_key.lower()

    # Takes string from user
    input_string = text
    input_string_cpy = input_string
    input_string = input_string.lower()

    # Lengths of input_string
    string_length = len(input_string)

    # Expands the encryption key to make it longer than the inputted string
    expanded_key = dec_key
    expanded_key_length = len(expanded_key)

    while expanded_key_length < string_length:
        # Adds another repetition of the encryption key
        expanded_key = expanded_key + dec_key
        expanded_key_length = len(expanded_key)

    key_position = 0
    i = 0
    for letter in input_string:
        if letter in alphabet:
            if(ord(input_string_cpy[i]) < 96):
                pos_list.append(i)
            # cycles through each letter to find it's numeric position in the alphabet
            position = alphabet.find(letter)
            # moves along key and finds the characters value
            key_character = expanded_key[key_position]
            key_character_position = alphabet.find(key_character)
            key_position = key_position + 1
            # changes the original of the input string character
            new_position = position - key_character_position
            if new_position > 26:
                new_position = new_position + 26
            new_character = alphabet[new_position]
            dec_string = dec_string + new_character
        else:
            dec_string = dec_string + letter
        
        i += 1
    #convert the correct things to upper case
    temp_array = list(dec_string)
    for x in range(len(temp_array)):
        if x in pos_list:
            temp_array[x] = temp_array[x].upper()
        
    dec_string = "".join(temp_array)
    return(dec_string)

#atbash cipher
def atBash(inp):

    charlistUpper = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]
    charlistUpperReverse = ['Z', "Y", "X", "W", "V", "U", "T", "S", "R", "Q", "P", "O", "N", "M", "L", "K", "J", "I", "H", "G", "F", "E", "D", "C", "B", "A"]
    charlistLower = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]
    charlistLowerReverse = ['z', "y", "x", "w", "v", "u", "t", "s", "r", "q", "p", "o", "n", "m", "l", "k", "j", "i", "h", "g", "f", "e", "d", "c", "b", "a"]
    
    output = ""
    inpArray = list(inp)
    for x in range(len(inpArray)):
        # check if it is upper case 
        if((ord(inpArray[x]) >= 65) and (ord(inpArray[x]) <= 90)):
            pos = charlistUpper.index(inpArray[x])
            output += charlistUpperReverse[pos]
        elif(ord(inpArray[x]) >= 97 and ord(inpArray[x]) <= 122): #check if lowercase
            pos = charlistLower.index(inpArray[x])
            output += charlistLowerReverse[pos]
        else:
            output += inpArray[x] 
    
    return output

#xor NOT CURRENTLY FUNCTIONING PROPERLY
def xor(data, key): 
    try:
        s1 = unhexlify(data)
        s2 = unhexlify(key)
        return "".join([chr(ord(c1) ^ ord(c2)) for (c1,c2) in zip(s1,s2)])
    except:
        return "Not XOR or XOR failed"


#main running area for calling functions
inStr = input("enter your string: ")
key = input("enter a key if applicable: ")
print('')
print("Input:".ljust(15), inStr)
print("Algorithm(s)".ljust(15), "Output")
print("base64".ljust(15), base64D(inStr))
print("base32".ljust(15), base32D(inStr))
print("base16".ljust(15), base16D(inStr))
print("base85Ascii".ljust(15), base85AsciiD(inStr))
print("base85".ljust(15), base85D(inStr))
print("atbash".ljust(15), atBash(inStr))
if(key != ""):
    print("vigenere".ljust(15), vigenere(inStr, key))
    print("xor(all in hex)".ljust(15), xor(inStr, key)) # the input and key must be in hex with no spaces

alphabets = (string.ascii_lowercase, string.ascii_uppercase, string.digits)
for x in range(1,26):
    print(("Rot" + str((26-x))).ljust(15), rotCipher(inStr, x, alphabets))
print('')

pause1 = input("")
