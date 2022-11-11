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

def create_connection(c,addr,node):
    global SM_username_public_key
    global SP_username_public_key
    print ('----------------------------')
    # print('Got connection from', addr)
    print('Node Number:',node)
    print('Connection Time:'+str(datetime.now()))
    msg=str(c.recv(1024).decode('ascii'))
    
    username_recv = msg.split()[0]
    x = int(msg.split()[1])
    y = int(msg.split()[2])
    isSm = int(msg.split()[3])
    user_public_key = Point(curve, F(x), F(y))

    shared_secret1 =  receiveDH(RA_secret_key, lambda: user_public_key)
    shared_secret = shared_secret1.x.n
    print("Request recieved from username: ", username_recv)
    if(username_recv in SM_username_public_key.keys()):
        print("User already exist")
        return

    print("shared secret estabilished: ", shared_secret)
    
    if(isSm == 1):
        SM_username_public_key = [user_public_key, shared_secret]
    if(isSm == 0):
        SP_username_public_key = [user_public_key, shared_secret]

    x, y = RA_public_key.getter()
    user_public =  str(x) + " "+ str(y)
    c.sendall(user_public.encode())
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