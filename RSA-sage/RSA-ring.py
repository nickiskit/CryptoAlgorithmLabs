from random import getrandbits
from sage.all import *
from sage.crypto.util import ascii_to_bin, bin_to_ascii
def RandomPrime(N):
    n = getrandbits(N)
    p = next_prime(n)
    return p

def GenerateKey(N):
    
    l = []
    p = RandomPrime(N)   
    q = RandomPrime(N)
    print "p = ", p
    print "q = ", q
    n = p * q
    F = (p-1)*(q-1)
    e = randint(2,F)
    while gcd(e,F)!=1:
        e = randint(2,F)
    d = inverse_mod(e,F)
    return ((e,n),(d,n))

def encrypt(mess,public_key):
    e, n = public_key
    R = IntegerModRing(n)
    cipher_text = []
    for i in mess:
        cipher_text.append(R(i)**R(e))
    return cipher_text

def decrypt(cipher_text, private_key):
    d, n = private_key
    R = IntegerModRing(n)
    M = []
    for i in cipher_text:
        M.append(R(i)**R(d))
    return M

def i2s(list_of_blocks,block_size):
    S = ''
    for i in list_of_blocks:
        s = "{0:b}".format(int(i))
        S += '0'*(block_size-len(s)) + s
    return bin_to_ascii(S)



mess = raw_input("Input message: ")

N = input("Input size of prime numbers in bits(>8): ")
public_key, private_key = GenerateKey(N)

bin_mess = ascii_to_bin(mess)
#print bin_mess
block_size = input("Input block size in bits < N and = 0(mod 8): ")
mod = len(bin_mess)%block_size
if mod != 0:
    bin_mess = '0'*(block_size-mod) + str(bin_mess)
#print bin_mess
list_of_blocks = []

for i in range(0,len(bin_mess),block_size):
    #print (str((bin_mess[i: i + block_size])))
    list_of_blocks.append(int(str((bin_mess[i: i + block_size])), base = 2))
#print list_of_blocks
DT = ''
cipher_text =  encrypt(list_of_blocks,public_key)
#print cipher_text
M = decrypt(cipher_text, private_key)
#print M
DT = i2s(M, block_size)
print "public_key: ", public_key
print "private_key: ", private_key
print "plain text: ", mess
print  "decrypt text: ", DT



