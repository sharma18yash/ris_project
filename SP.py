import socket  
import sys
from elliptic import *
from diffieHellman import *


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
    RA_port=int(input("Enter Regitration Authority Port: "))

    host=socket.gethostname()
    s = socket.socket()

    x, y = my_public_key.getter()
    user_public = username + " " + str(x) + " "+ str(y) + " 0"
    s.connect((host, RA_port))

    s.sendall(user_public.encode())
    resp=s.recv(1024).decode()
    x, y = resp.split()[0], resp.split()[1]
    RA_public_key = Point(curve, F(x), F(y))
    shared_secret1 =  receiveDH(my_secret_key, lambda: RA_public_key)
    shared_secret = shared_secret1.x.n
    print("RA public key recieved: ", RA_public_key)
    print("shared secret estabilished: ", shared_secret)


def connect_to_SM():
    pass

username = input("Enter your username: ")

print("Entering Registration phase")
initial_registration()
print("Registration phase completed")

connect_to_SM()