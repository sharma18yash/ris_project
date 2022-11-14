from elliptic import *
from diffieHellman import *
from finitefield.finitefield import FiniteField
import socket
import sys
from datetime import datetime
import threading
import _thread
F = FiniteField(3851, 1)
curve = EllipticCurve(a=F(324), b=F(1287))
basePoint = Point(curve, F(920), F(303))

SM_username_public_key = {}
SP_username_public_key = {}


def process_public_key(key):
    temp = key.split(",")
    temp1 = temp[0].split()
    temp2 = temp[1].split()
    x = temp1[0][1:]
    y = temp2[0]
    p = Point(curve, x, y)
    return p



# generate own secret key
RA_secret_key = generateSecretKey(8)
RA_public_key = sendDH(RA_secret_key, basePoint, lambda x:x)
print("My secret key: ", RA_secret_key)
print("My public key: ", RA_public_key)


def register(msg):
    global SM_username_public_key
    global SP_username_public_key
    username_recv = msg.split()[1]
    x = int(msg.split()[2])
    y = int(msg.split()[3])
    isSm = int(msg.split()[4])
    user_public_key = Point(curve, F(x), F(y))

    shared_secret1 =  receiveDH(RA_secret_key, lambda: user_public_key)
    shared_secret = shared_secret1.x.n
    print("Request recieved from username: ", username_recv)
    if(username_recv in SM_username_public_key.keys()):
        print("User already exist")
        return

    print("shared secret estabilished: ", shared_secret)
    
    if(isSm == 1):
        SM_username_public_key[username_recv] = [user_public_key, shared_secret]
    if(isSm == 0):
        SP_username_public_key[username_recv] = [user_public_key, shared_secret]

    x, y = RA_public_key.getter()
    user_public =  str(x) + " "+ str(y)
    return user_public



def authenticate(msg):
    global SM_username_public_key
    global SP_username_public_key
    print(msg)
    SM_username = msg.split()[1]
    x = int(msg.split()[2])
    y = int(msg.split()[3])
    # recv_shared_secret = int(msg.split()[4])
    SM_public_key = Point(curve, F(x), F(y))
    temp_shared_secret = receiveDH(RA_secret_key, lambda: SM_public_key)
    SM_shared_secret = temp_shared_secret.x.n
    if SM_username_public_key[SM_username][1] == SM_shared_secret :
        return "SM authenticated"
    return "SM not Authenticated"



def create_connection(c,addr,node):
    
    print ('----------------------------')
    # print('Got connection from', addr)
    # print('Node Number:',node)
    print('Connection Time:'+str(datetime.now()))
    msg=str(c.recv(1024).decode('ascii'))
    if(msg[0] == "1"):
        to_ret = register(msg)
    else:
        to_ret = authenticate(msg)
    
    c.sendall(to_ret.encode())
    print ('----------------------------')


if len(sys.argv)!=2:
    exit('Invalid arguments,Please enter Port number')


port=int(sys.argv[1])   
host=socket.gethostname()
s = socket.socket()
s.bind((host, port))
node=0
s.listen(15)
while True:
   c, addr = s.accept()
   node=node+1
   _thread.start_new_thread(create_connection,(c,addr,node))




# get key of SM/SP using socket

# generate shared key
# store shared key/username in set/dictionary