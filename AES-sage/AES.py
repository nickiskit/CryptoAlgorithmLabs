from random import getrandbits
from sage.all import *
from sage.crypto.util import ascii_to_bin, bin_to_ascii
import AESconst
import hashlib



def SubBytes(state, mtrx):
    if mtrx == 'sBox':
        sBox = AESconst.sBox
    elif mtrx == 'InvsBox':
        sBox = AESconst.InvsBox
    for i in range(len(state)):
        for j in range(len(state[i])):
            x = (int(state[i][j])>>4)
            y = (int(state[i][j])&0xf)
            state[i][j] = sBox[x][y]
    return state

def ShiftRows(state, way):
    stateMtrx = matrix(SR,4,4,state).transpose()
    stateMtrx = [list(x) for x in stateMtrx]
    #print "after: ", stateMtrx
    if way == 'left':
        for i in range(1,len(stateMtrx)):
            stateMtrx[i] = stateMtrx[i][i:] + stateMtrx[i][:i]
    elif way == 'right':
        for i in range(1,len(stateMtrx)):
            stateMtrx[i] = stateMtrx[i][-i:] + stateMtrx[i][:-i]
    #print "before: ", stateMtrx        
    
    return [list(i) for i in zip(*stateMtrx)]


def MixColumns(state, mtrx):
    if mtrx == 'fixMtr':
        fixMtr = AESconst.fixMtr
    elif mtrx == 'InvFixMtr': 
        fixMtr = AESconst.InvFixMtr
    F = GF(2**8,'x')
    tempMtr = []
   # print "state", state
    for i in range(4):
        tempRow = []
        for j in range(4):
            result = 0
            for l in range(4):
                c = [int(k) for k in bin(fixMtr[j][l])[2:]][::-1]
                #print "state[i][l]", state[i][l]
                t = [int(k) for k in bin(state[i][l])[2:]][::-1]
                #print "row: ", c
                #print "column: ", t
                result += (F(c)*F(t))
                #print "result: ", result
            #print "int(result)= ", F(result).integer_representation() 
            tempRow.append(F(result).integer_representation())
        tempMtr.append(tempRow)
             
    return tempMtr

def SubWord(word):
    for i in range(len(word)):
        x = (word[i]>>4)
        y = (word[i]&0xf)
        word[i] = AESconst.sBox[x][y]
    return word

def RotWord(word):
    return word[1:] + word[:1]

def xor(a, b):
    temp = []
    for i in range(4):
        temp.append(int(a[i]).__xor__(int(b[i])))
    return temp


def KeyExpansion(key):
    keySchedule = []
    for i in range(AESconst.Nk):
        keySchedule.append(key[i])    
    for i in range(AESconst.Nk, 4*(AESconst.Nr+1)):
        temp = keySchedule[i-1]
        if i%AESconst.Nk==0:
            temp = xor(SubWord(RotWord(temp)), AESconst.rcon[i/AESconst.Nk-1])
        temp = xor(temp, keySchedule[i-AESconst.Nk])
        keySchedule.append(temp)

    return keySchedule

def AddRoundKey(state, key, Round):
    #print "round key: "
    for i  in range(Round*4, 4*(Round+1)):
        #print "state: ", state[i%4]
       # print "key[i]: ", key[i]
        state[i%4] = xor(state[i%4],key[i])
        
        
    #print "------------------------------------------------------"
    return state


def createKey():
    key = "kekacheburekaloh".encode("hex")
    #ey  = hashlib.md5( raw_input("input key: ") ).hexdigest()
    cipherKey = []
    block = []
    for i in range(0,len(key),2):
        block.append(int(key[i:i+2],16 ))  
    for r in range(4):
        cipherKey.append([block[r+4*c] for c in range(AESconst.Nb)])
    return KeyExpansion(cipherKey)

def textToBlocks():
    #lainText = raw_input("input plain text: ")
    plainText = "mytestbigmessage"
    block = []
    binString = str(ascii_to_bin(plainText))
    count = len(binString)/128
    if len(binString)%128:
        binString = binString+(7*'0'+'1')*((128-len(binString)%128)/8)
        count += 1
    for i in range(count):
        block.append([int(binString[j:j+8], 2) for j in range(i*128,(i+1)*128,8)])    
    return block, count

def toBlocks(text):
    count = len(text)/16
    blocks = []
    for i in range(0,len(text),16):
        blocks.append(text[i:i+16])
    return blocks, count 
    


def encrypt(block, key):
        state = []
        for r in range(4):
            state.append([0 for c in range(AESconst.Nb)])
        for r in range(4):
            for c in range(AESconst.Nb):
                state[r][c] = block[r+4*c]
        print "state: ", state
        state = AddRoundKey(state, key, 0)
        print "AddRoundKey: ", state
        for Round in range(1, AESconst.Nr):
            print "Round= ", Round
            state = SubBytes(state,'sBox')
            print "SubBytes: ", state
            state = ShiftRows(state,'left')
            print "ShiftRows: ", state
            state = MixColumns(state,'fixMtr')
            print "MixColumns: ", state
            state = AddRoundKey(state, key, Round)
            print "AddRoundKey: ", state
            print "---------------------------------------------------------------"
        print "Round= 10"
        state = SubBytes(state,'sBox')
        print "SubBytes: ", state
        state = ShiftRows(state,'left')
        print "ShiftRows: ", state
        state = AddRoundKey(state, key, AESconst.Nr)
        print "AddRoundKey: ", state
        result = [0 for i in range(4*AESconst.Nb)]
        for r in range(4):
            for c in range(AESconst.Nb):
                result[r+4*c] = state[r][c]
        #print result
        return result

def decrypt(cipher, key):
    state = []
    for r in range(4):
        state.append([0 for c in range(AESconst.Nb)])
    for r in range(4):
        for c in range(AESconst.Nb):
            state[r][c] = cipher[r+4*c]  
    state = AddRoundKey(state, key, AESconst.Nr)
    #print "AddRoundKey: ", state
    for Round in range(AESconst.Nr-1, 0, -1):
        #print "Round= ", Round
        state = ShiftRows(state,'right')
        #print "ShiftRows: ", state
        state = SubBytes(state,'InvsBox')
        #print "SubBytes: ", state
        state = AddRoundKey(state, key, Round)
        #print "AddRoundKey: ", state
        state = MixColumns(state,'InvFixMtr')
        #print "MixColumns: ", state
        
    #print "Round= 0"
    state = ShiftRows(state,'right')
    #print "ShiftRows: ", state
    state = SubBytes(state,'InvsBox')
    #print "SubBytes: ", state
    state = AddRoundKey(state, key,0)
    print "AddRoundKey: ", state
    result = [0 for i in range(4*AESconst.Nb)]
    for r in range(4):
        for c in range(AESconst.Nb):
            result[r+4*c] = state[r][c]
    
    return result
    
    
def n2text(listOfNumb):
    result = ''
    for i in listOfNumb:
        if i == 1:
            return result
        b = str(bin(i)[2:])
        b = '0'*(8 - len(b)) + b
        result += bin_to_ascii(b)
    return result

cipherKey = createKey()
#print cipherKey
block, count = textToBlocks()
cipherText = []
decryptText = []
for i in range(count):
    cipherText += encrypt(block[i], cipherKey)
print "cipher text: ", cipherText
cipherTextBlock, count2 = toBlocks(cipherText)
for i in range(count2):
    decryptText += decrypt(cipherTextBlock[i], cipherKey)

print "plain text: ", n2text(decryptText)
