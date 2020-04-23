import socket


hdr = b'\xAA\xAA\x01\x00' #Id | Control

Cntr = 0     #QR bit is set to 0 for query
Cntr += 0 #Opcode set to ????4 bits
Cntr += 0 #Authoritative Answer 0
Cntr += 0    #Truncation flag not set since we need to use TCP
Cntr += 1    #Recursion desired?
Cntr += 0    #Recursion NOT available
Cntr += 0  #Z reserved set to 000
Cntr += 0 #RCode set to 0 since packet is a query 4 bits

hdr += b'\x00\x01\x00\x00' #questionCnt=1 | AnswerCnt=0
hdr += b'\x00\x00\x00\x00' #AuthorityCnt=0 | AdditionalCnt=0

msglen = b'\x05'
hdr += msglen

msg="hello" #this would be our custom payload??

def stringTohex(msg):
    return ''.join(r'\x{02:x}'.format(ord(c)) for c in msg)


hdr += stringTohex(msg)
hdr += b'\x00' #marks the end of the message
hdr += b'\x00\x01\x00\x01' # Qtype | Qclass


def sender(msg,address,port):
    addport = (address,port)
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

    try:
        sock.send(binascii.unhexlify(hdr),addPort)
    finally:
        sock.close()

