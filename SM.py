import socket  
import sys
from elliptic import *
from diffieHellman import *
import time

# def process_public_key(key):
#     temp = key.split(",")
#     temp1 = temp[0].split()
#     temp2 = temp[1].split()
#     x = temp1[0][1:]
#     y = temp2[0]
#     return x, y

F = FiniteField(3851, 1)
curve = EllipticCurve(a=F(324), b=F(1287))
basePoint = Point(curve, F(920), F(303))
global username
global shared_secret

my_secret_key = generateSecretKey(8)
my_public_key = sendDH(my_secret_key, basePoint, lambda x:x)

print("My secret key: ", my_secret_key)
print("My public key: ", my_public_key)

def initial_registration():
    global shared_secret
    print("----------------------------------")
    port=int(input("Enter Regitration Authority Port: "))

    t1 = time.time()
    host=socket.gethostname()
    s = socket.socket()

    x, y = my_public_key.getter()
    user_public = "1 " + username + " " + str(x) + " "+ str(y) + " 1"
    s.connect((host, port))

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

def connect_to_service_provider():
    print("----------------------------------")
    port = int(input("Enter Port number of service provider: "))
    t1 = time.time()
    host=socket.gethostname()
    s = socket.socket()
    s.connect((host, port))
    x, y = my_public_key.getter()
    to_send = username + " " + str(x) + " "+str(y)
    s.sendall(to_send.encode())
    resp = s.recv(1024).decode()
    print(resp)
    t2 = time.time()
    print("Time for connecting to network: ", t2-t1)
    print("----------------------------------")
    print("Estabilishing Secure line between SM and SP")
    while(True):
        msg = input("Enter your message: ")
        s.sendall(msg.encode())
        response = s.recv(1024).decode()
        print("Message recieved: ", response)
        if(response == "quit"):
            break;

username = input("Enter your username: ")

print("Entering Registration phase")
initial_registration()
print("Registration phase completed")

connect_to_service_provider()

