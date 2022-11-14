import socket  
import sys
from elliptic import *
from diffieHellman import *
import _thread
import threading
import time
from datetime import datetime


F = FiniteField(3851, 1)
curve = EllipticCurve(a=F(324), b=F(1287))
basePoint = Point(curve, F(920), F(303))
global username
global shared_secret
global RA_port

my_secret_key = generateSecretKey(8)
my_public_key = sendDH(my_secret_key, basePoint, lambda x:x)

print("My secret key: ", my_secret_key)
print("My public key: ", my_public_key)


def initial_registration():
    global shared_secret
    global RA_port
    print("----------------------------------")
    RA_port=int(input("Enter Regitration Authority Port: "))
    t1 = time.time()
    host=socket.gethostname()
    s = socket.socket()

    x, y = my_public_key.getter()
    user_public = "1 " + username + " " + str(x) + " "+ str(y) + " 0"
    s.connect((host, RA_port))

    s.sendall(user_public.encode())
    resp=s.recv(1024).decode()
    x, y = resp.split()[0], resp.split()[1]
    RA_public_key = Point(curve, F(x), F(y))
    shared_secret1 =  receiveDH(my_secret_key, lambda: RA_public_key)
    shared_secret = shared_secret1.x.n
    print("RA public key recieved: ", RA_public_key)
    print("shared secret estabilished: ", shared_secret)
    t2 = time.time()
    print("Time Taken for initial registration: ", t2-t1)
    print("----------------------------------")

def SM_connection(c, addr):
    print("----------------------------------")
    print('Connection Time:'+str(datetime.now()))
    msg=str(c.recv(1024).decode('ascii'))
    # recieve public key from SM and sent it to RA
    msg = "0 " + msg
    host = socket.gethostname()
    s = socket.socket()
    s.connect((host, RA_port))
    s.sendall(msg.encode())
    to_ret = s.recv(1024).decode()
    
    print(to_ret)
    if(to_ret == "SM authenticated"):
        print("Estabilishing Secure line between SM and SP")
        c.sendall(to_ret.encode())
        while(True):
            msg = str(c.recv(1024).decode("ascii"))
            if(msg == "quit"):
                break;
            print("Message Recieved: ", msg)
            response = input("Enter Response: ")
            c.sendall(response.encode())
    print("----------------------------------")

def open_connection():
    port= int(input("Enter port number: "))   
    host=socket.gethostname()
    s = socket.socket()
    s.bind((host, port))
    s.listen(15)
    while True:
        c, addr = s.accept()
        _thread.start_new_thread(SM_connection,(c,addr))
       
username = input("Enter your username: ")

print("Entering Registration phase")
initial_registration()
print("Registration phase completed")

open_connection()