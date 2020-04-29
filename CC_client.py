import socket, subprocess, os, time, base64, ctypes, itertools, math, sys, codecs

def runClient():
    HOST = "localhost" #"192.168.1.8"
    PORT = 1337 #52
    PKT_SIZE = 1024
    KEY = "zMWYCRLd4szoBiPP"

    s = socket.socket()  # instantiate
    s.connect((HOST, PORT))  # connect to the server

    return_msg = "connected"  # take input
    while return_msg.lower().strip() != 'bye':
        s.send(return_msg.encode())  # send message
        data = s.recv(1024).decode()  # receive response

        print('Received from server: ' + data)  # show in terminal
        decrypted_data = ""
        try:
            decrypted_data = decrypt(data,KEY)
        except Exception as e:
            print('Error decrypting... ignoring packet')
            return_msg = "decryption error"
        finally:
            pass
        print('Decrypted: ' + decrypted_data)
        return_message = "ok"  # again take input

    s.shutdown(socket.SHUT_RD)
    s.close()  # close the connection


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
    runClient()