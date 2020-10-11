import base64
import string

#global variables for cascade Cipher logic
isBase64 = False
isBase32 = False
isBase16 = False
isBase85Ascii = False
isBase85 = False

#base64 decode function
def base64D(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.b64decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base64"
    
    #logic to see if the current cipher is correct for cascade mode to run cleaner
    global isBase64
    isBase64 = True 
    return strToDecode

#base32 decode function
def base32D(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.b32decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base32"
    
    #logic to see if the current cipher is correct for cascade mode to run cleaner
    global isBase32
    isBase32 = True
    return strToDecode

#base16 decode function
def base16D(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.b16decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base16"
    
    #logic to see if the current cipher is correct for cascade mode to run cleaner
    global isBase16
    isBase16 = True
    return strToDecode

#base85Ascii decode function
def base85AsciiD(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.a85decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base85Ascii"
    
    #logic to see if the current cipher is correct for cascade mode to run cleaner
    global isBase85Ascii
    isBase85Ascii = True
    return strToDecode

#base85 decode function
def base85D(strToDecode: str):
    try:
        strToDecode = strToDecode.encode()
        strToDecode = base64.b85decode(strToDecode)
        strToDecode = strToDecode.decode()
    except:
        return "Not base85"
    
    #logic to see if the current cipher is correct for cascade mode to run cleaner
    global isBase85
    isBase85 = True
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


#main running area for calling functions
inStr = input("enter your string: ")
print('')
print("Input:".ljust(15), inStr)
print("Algorithm(s)".ljust(15), "Output")
print("base64".ljust(15), base64D(inStr))
print("base32".ljust(15), base32D(inStr))
print("base16".ljust(15), base16D(inStr))
print("base85Ascii".ljust(15), base85AsciiD(inStr))
print("base85".ljust(15), base85D(inStr))

alphabets = (string.ascii_lowercase, string.ascii_uppercase, string.digits)
for x in range(1,26):
    print(("Rot" + str((26-x))).ljust(15), rotCipher(inStr, x, alphabets))
print('')

#run the string through cascading ciphers
runCascade = input('Would you like to use cascading decrypt? (y/n): ')
runCascade = runCascade.lower()

#logic from earlier inside the functions if it returns a valid decoded string global var gets updated
#and is checked for in this if statement to make cascade decode less messy
if runCascade == 'y':
    if isBase64 == True: #if isBase64 came back as true run this if statement
        print("Algorithm(s)".ljust(20), "Output")
        print("base64(base64)".ljust(20), base64D(base64D(inStr)))
        print("base32(base64)".ljust(20), base32D(base64D(inStr)))
        print("base16(base64)".ljust(20), base16D(base64D(inStr)))
        print("base85Ascii(base64)".ljust(20), base85AsciiD(base64D(inStr)))
        print("base85(base64)".ljust(20), base85D(base64D(inStr)))

        rotString = base64D(inStr)
        for x in range(1,26):
            print(("Rot" + str((26-x)) + "(base64)").ljust(20), rotCipher(rotString, x, alphabets))

    elif isBase32 == True: #if isBase32 came back as true run this if statement
        print("Algorithm(s)".ljust(20), "Output")
        print("base64(base32)".ljust(20), base64D(base32D(inStr)))
        print("base32(base32)".ljust(20), base32D(base32D(inStr)))
        print("base16(base32)".ljust(20), base16D(base32D(inStr)))
        print("base85Ascii(base32)".ljust(20), base85AsciiD(base32D(inStr)))
        print("base85(base32)".ljust(20), base85D(base32D(inStr)))

        rotString = base32D(inStr)
        for x in range(1,26):
            print(("Rot" + str((26-x)) + "(base32)").ljust(20), rotCipher(rotString, x, alphabets))

    elif isBase16 == True: #if isBase16 came back as true run this if statement
        print("Algorithm(s)".ljust(20), "Output")
        print("base64(base16)".ljust(20), base64D(base16D(inStr)))
        print("base32(base16)".ljust(20), base32D(base16D(inStr)))
        print("base16(base16)".ljust(20), base16D(base16D(inStr)))
        print("base85Ascii(base16)".ljust(20), base85AsciiD(base16D(inStr)))
        print("base85(base16)".ljust(20), base85D(base16D(inStr)))

        rotString = base16D(inStr)
        for x in range(1,26):
            print(("Rot" + str((26-x)) + "(base16)").ljust(20), rotCipher(rotString, x, alphabets))

    elif isBase85Ascii == True: #if isBase85Ascii came back as true run this if statement
        print("Algorithm(s)".ljust(25), "Output")
        print("base64(base85Ascii)".ljust(25), base64D(base85AsciiD(inStr)))
        print("base32(base85Ascii)".ljust(25), base32D(base85AsciiD(inStr)))
        print("base16(base85Ascii)".ljust(25), base16D(base85AsciiD(inStr)))
        print("base85Ascii(base85Ascii)".ljust(25), base85AsciiD(base85AsciiD(inStr)))
        print("base85(base85Ascii)".ljust(25), base85D(base85AsciiD(inStr)))

        rotString = base85AsciiD(inStr)
        for x in range(1,26):
            print(("Rot" + str((26-x)) + "(base85Ascii)").ljust(25), rotCipher(rotString, x, alphabets))

    elif isBase85 == True: #if isBase85 came back as true run this if statement
        print("Algorithm(s)".ljust(20), "Output")
        print("base64(base85)".ljust(20), base64D(base85D(inStr)))
        print("base32(base85)".ljust(20), base32D(base85D(inStr)))
        print("base16(base85)".ljust(20), base16D(base85D(inStr)))
        print("base85Ascii(base85)".ljust(20), base85AsciiD(base85D(inStr)))
        print("base85(base85)".ljust(20), base85D(base85D(inStr)))

        rotString = base85D(inStr)
        for x in range(1,26):
            print(("Rot" + str((26-x)) + "(base85)").ljust(20), rotCipher(rotString, x, alphabets))

else: #if the input was n or something else 
    exit()