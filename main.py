import codecs

# ------------------------------------------------------
# ------------------------------------------------------
class Util():

    # ------------------------------------------------------
    def rotate(self, l, n):
        return l[n:] + l[:n]

    # ------------------------------------------------------
    def bitAND(self, a, b, l):
        result = ''
        for i in range(l):
            result = result + str(int(a[i], 2) and int(b[i], 2))
        return result

    # ------------------------------------------------------
    def bitOR(self, a, b, l):
        result = ''
        for i in range(l):
            result = result + str(int(a[i], 2) or int(b[i], 2))
        return result

    # ------------------------------------------------------
    def bitXOR(self, a, b, l):
        result = ''
        for i in range(l):
            result = result + str(int(a[i], 2) ^ int(b[i], 2))
        return result

    # ------------------------------------------------------
    def bitNOT(self, a, l):
        result = ''
        for i in range(l):
            result = result + str(int(not int(a[i], 2)))
        return result

    # ------------------------------------------------------
    def bitADD(self, x, y, l):
        max_len = max(len(x), len(y))

        x = x.zfill(max_len)
        y = y.zfill(max_len)
            
        result = ''
        carry = 0

        for i in range(max_len - 1, -1, -1):
            r = carry
            r += 1 if x[i] == '1' else 0
            r += 1 if y[i] == '1' else 0
            result = ('1' if r % 2 == 1 else '0') + result
            carry = 0 if r < 2 else 1    
            
        if carry !=0 : result = '1' + result

        result.zfill(max_len)
        resultFinal = result[len(result)-l:len(result)]
        return resultFinal

    # ------------------------------------------------------
    def bitMINUS(self, x, y, l):
        max_len = max(len(x), len(y))

        x = x.zfill(max_len)
        y = y.zfill(max_len)

        result = ''
        carry = 0

        for i in range(max_len-1, -1, -1):
            r = 1 if x[i] == '1' else 0
            r -= 1 if y[i] == '1' else 0
            r -= carry
            result = ('1' if r % 2 == 1 else '0') + result
            carry = 1 if r < 0 else 0

        if carry !=0 : result = '1' + result
        resultFinal = result[len(result)-l:len(result)]
        return resultFinal


# ------------------------------------------------------
# ------------------------------------------------------
class SHA1():

    def __init__(self):
        self.util = Util();

    # ------------------------------------------------------
    def getHash(self, key, text):
        messageBinary = self.__convertMessageToBinary(key.encode("utf-8", "ignore") + text.encode("utf-8", "ignore"))
        extendedMessageBinary = self.__extendMessageBinary(messageBinary)
        return self.__generateSHA1(extendedMessageBinary)


    # ------------------------------------------------------
    def __convertMessageToBinary(self, message):
        messageInBinary = ''

        # Convert each character to 8-bit binary. 
        index = 0
        while (index < len(message)):
            # messageInBinary = messageInBinary + format(message[index], 'b').zfill(8)
            # index = index + 1
            if (chr(message[index]) != '\\'):
                messageInBinary = messageInBinary + format(message[index], 'b').zfill(8)
                index = index + 1
            else:
                messageInBinary = messageInBinary +  bin(int(message[index:index+4].decode("utf-8").replace('\\x', ''), 16))[2:].zfill(8)
                index = index + 4

        messageInBinaryLength = len(messageInBinary)

        # Padding begins with a bit "1"
        messageInBinary = messageInBinary + '1'

        # Fill padding with bit "0", until there is 64 bits left (for message length)
        while len(messageInBinary) % 512 != 448:
            messageInBinary = messageInBinary + '0'

        # Last 64 bits is for message length
        messageInBinary = messageInBinary + '{0:064b}'.format(messageInBinaryLength)

        return messageInBinary


    # ------------------------------------------------------
    def __extendMessageBinary(self, messageBinary):

        result = ''

        # Divide the whole binary message into equal chunks of 512 bits length
        for x in range(int(len(messageBinary) / 512)):
            chunk = messageBinary[(x*512):(x+1)*512]
            extendedChunkBinary = ''
            for index in range(80):
                if index < 16:
                    extendedChunkBinary = extendedChunkBinary + chunk[(index*32):(index+1)*32]
                elif index >= 16:
                    w0 = extendedChunkBinary[(index-3)*32:(index-2)*32]
                    w1 = extendedChunkBinary[(index-8)*32:(index-7)*32]
                    w2 = extendedChunkBinary[(index-14)*32:(index-13)*32]
                    w3 = extendedChunkBinary[(index-16)*32:(index-15)*32]

                    w = ''
                    x1 = self.util.bitXOR(w0,w1,32) 
                    x2 = self.util.bitXOR(x1,w2,32)
                    x3 = self.util.bitXOR(x2,w3,32)
                    w = w + x3

                    extendedChunkBinary = extendedChunkBinary + self.util.rotate(w,1)
                
            result = result + extendedChunkBinary

        return result


    # ------------------------------------------------------
    def __generateSHA1(self, extendedMessageBinary):
        h0 = '01100111010001010010001100000001' # 67452301
        h1 = '11101111110011011010101110001001' # EFCDAB89
        h2 = '10011000101110101101110011111110' # 98BADCFE
        h3 = '00010000001100100101010001110110' # 10325476
        h4 = '11000011110100101110000111110000' # C3D2E1F0
        
        for x in range(int(len(extendedMessageBinary) / 2560)):
            chunk = extendedMessageBinary[(x*2560):(x+1)*2560]

            a = h0
            b = h1
            c = h2
            d = h3
            e = h4

            for i in range(80):
                w = chunk[(i*32):(i+1)*32]
                if (i <= 19): 
                    f = self.util.bitOR((self.util.bitAND(b,c,32)),(self.util.bitAND (self.util.bitNOT(b,32),d,32)),32)
                    k = '01011010100000100111100110011001' 
                elif (i <= 39):
                    f = self.util.bitXOR((self.util.bitXOR(b,c,32)),d,32)
                    k = '01101110110110011110101110100001' 
                elif (i <= 59):
                    f = self.util.bitOR(self.util.bitOR((self.util.bitAND(b,c,32)),(self.util.bitAND(b,d,32)),32),(self.util.bitAND(c,d,32)),32)
                    k = '10001111000110111011110011011100' 
                elif (i <= 79):    
                    f = self.util.bitXOR((self.util.bitXOR(b,c,32)),d,32)
                    k = '11001010011000101100000111010110' 

                temp1 = self.util.bitADD(self.util.rotate(a,5),f,32)
                temp2 = self.util.bitADD(temp1,e,32)
                temp3 = self.util.bitADD(temp2,k,32)
                temp = self.util.bitADD(temp3,w,32)

                e = d
                d = c
                c = self.util.rotate(b, 30)
                b = a
                a = temp

            h0 = self.util.bitADD(h0,a,32)
            h1 = self.util.bitADD(h1,b,32)
            h2 = self.util.bitADD(h2,c,32)
            h3 = self.util.bitADD(h3,d,32)
            h4 = self.util.bitADD(h4,e,32)

        return format(int(h0, 2), 'x') + format(int(h1, 2), 'x') + format(int(h2, 2), 'x') + format(int(h3, 2), 'x') + format(int(h4, 2), 'x')


# ------------------------------------------------------
# ------------------------------------------------------
class SHA1_Length_Attack():

    def __init__(self):
        self.util = Util();

    # ------------------------------------------------------
    # originMessageLength is (key + text)
    def attackSHA1(self, originText, originMac, appendText, originMessageLength):

        originMacInBinary = bin(int(originMac, 16))[2:].zfill(8)
        h0 = originMacInBinary[0:32]
        h1 = originMacInBinary[32:64]
        h2 = originMacInBinary[64:96]
        h3 = originMacInBinary[96:128]
        h4 = originMacInBinary[128:160] 

        # Calculate last chunk
        totalNewLength = (int((originMessageLength * 8) / 512) + 1) * 512 + len(appendText) * 8 
        lastChunk = self.__convertMessageToBinary(appendText.encode("utf-8", "ignore"), totalNewLength)
        lastChunkExtended = self.__extendMessageBinary(lastChunk)
        
        newMac = (self.__generateLastChunkSHA1(lastChunkExtended,h0,h1,h2,h3,h4))

        # ---------------------------------------------------------
        originMessageLengthInBinary = originMessageLength * 8
        padding = '1'

        # Fill padding with bit "0", until there is 64 bits left (for message length)
        while (originMessageLengthInBinary + len(padding)) % 512 != 448:
            padding = padding + '0'

        # Last 64 bits is for message length
        paddingAndLength = padding + '{0:064b}'.format(originMessageLengthInBinary)

        paddingAndLengthInHexStringFormat = ''
        for i in range(0,len(paddingAndLength),8):
            paddingAndLengthInHexStringFormat = paddingAndLengthInHexStringFormat + ('\\x' + '{:02x}'.format(int(paddingAndLength[i:i+8], 2)))

        newMessage = paddingAndLengthInHexStringFormat
        return [newMessage,newMac]


    # ------------------------------------------------------
    def __convertMessageToBinary(self, message, newLength):
        messageInBinary = ''

        # Convert each character to 8-bit binary. 
        index = 0
        while (index < len(message)):
            if (chr(message[index]) != '\\'):
                messageInBinary = messageInBinary + format(message[index], 'b').zfill(8)
                index = index + 1
            else:
                messageInBinary = messageInBinary +  bin(int(message[index:index+4].decode("utf-8").replace('\\x', ''), 16))[2:].zfill(8)
                index = index + 4

        # Padding begins with a bit "1"
        messageInBinary = messageInBinary + '1'

        # Fill padding with bit "0", until there is 64 bits left (for message length)
        while len(messageInBinary) % 512 != 448:
            messageInBinary = messageInBinary + '0'

        # Last 64 bits is for message length
        messageInBinary = messageInBinary + '{0:064b}'.format(newLength)

        return messageInBinary

    # ------------------------------------------------------
    def __extendMessageBinary(self, messageBinary):

        result = ''

        # Divide the whole binary message into equal chunks of 512 bits length
        for x in range(int(len(messageBinary) / 512)):
            chunk = messageBinary[(x*512):(x+1)*512]
            extendedChunkBinary = ''
            for index in range(80):
                if index < 16:
                    extendedChunkBinary = extendedChunkBinary + chunk[(index*32):(index+1)*32]
                elif index >= 16:
                    w0 = extendedChunkBinary[(index-3)*32:(index-2)*32]
                    w1 = extendedChunkBinary[(index-8)*32:(index-7)*32]
                    w2 = extendedChunkBinary[(index-14)*32:(index-13)*32]
                    w3 = extendedChunkBinary[(index-16)*32:(index-15)*32]

                    w = ''
                    x1 = self.util.bitXOR(w0,w1,32) 
                    x2 = self.util.bitXOR(x1,w2,32)
                    x3 = self.util.bitXOR(x2,w3,32)
                    w = w + x3

                    extendedChunkBinary = extendedChunkBinary + self.util.rotate(w,1)
                
            result = result + extendedChunkBinary

        return result

# ------------------------------------------------------
    def __generateLastChunkSHA1(self, lastChunkOnly, last_h0, last_h1, last_h2, last_h3, last_h4):
        h0 = last_h0 
        h1 = last_h1
        h2 = last_h2
        h3 = last_h3
        h4 = last_h4

        a = last_h0
        b = last_h1
        c = last_h2
        d = last_h3
        e = last_h4

        for i in range(80):
            w = lastChunkOnly[(i*32):(i+1)*32]
            if (i <= 19): 
                f = self.util.bitOR((self.util.bitAND(b,c,32)),(self.util.bitAND (self.util.bitNOT(b,32),d,32)),32)
                k = '01011010100000100111100110011001' 
            elif (i <= 39):
                f = self.util.bitXOR((self.util.bitXOR(b,c,32)),d,32)
                k = '01101110110110011110101110100001' 
            elif (i <= 59):
                f = self.util.bitOR(self.util.bitOR((self.util.bitAND(b,c,32)),(self.util.bitAND(b,d,32)),32),(self.util.bitAND(c,d,32)),32)
                k = '10001111000110111011110011011100' 
            elif (i <= 79):    
                f = self.util.bitXOR((self.util.bitXOR(b,c,32)),d,32)
                k = '11001010011000101100000111010110' 

            temp1 = self.util.bitADD(self.util.rotate(a,5),f,32)
            temp2 = self.util.bitADD(temp1,e,32)
            temp3 = self.util.bitADD(temp2,k,32)
            temp = self.util.bitADD(temp3,w,32)

            e = d
            d = c
            c = self.util.rotate(b, 30)
            b = a
            a = temp

        h0 = self.util.bitADD(h0,a,32)
        h1 = self.util.bitADD(h1,b,32)
        h2 = self.util.bitADD(h2,c,32)
        h3 = self.util.bitADD(h3,d,32)
        h4 = self.util.bitADD(h4,e,32)

        return format(int(h0, 2), 'x') + format(int(h1, 2), 'x') + format(int(h2, 2), 'x') + format(int(h3, 2), 'x') + format(int(h4, 2), 'x')


# ------------------------------------------------------
# ------------------------------------------------------
# ------------------------------------------------------
def verifyMac(message, mac):
    key = 'secret'
    sha1 = SHA1()
    mySHA1 = sha1.getHash(key, message)
    return (mySHA1 == mac)

# ----------------------------------------
# ----------------------------------------
sha1 = SHA1()
sha1_attack = SHA1_Length_Attack()
# ----------------------------------------

print('----------------------------------------')
print('Test 1:')
originMAC1 = sha1.getHash('secret', 'a=1')
print('Origin MAC: ' + originMAC1)
# ----------------------------------------
sha1_attack_new_data = sha1_attack.attackSHA1('a=1', originMAC1, '&b=3', 9)
extendedString = sha1_attack_new_data[0]
newMac = sha1_attack_new_data[1]
print('New MAC: ' + newMac)
print('Extended text: ' + extendedString)
print('Verified result: ' + str(verifyMac('a=1' + extendedString + '&b=3', newMac)))

# ----------------------------------------
# ----------------------------------------
print('----------------------------------------')
print('Test 2:')
originMAC2 = sha1.getHash('secret', 'IAmNotAdmin')
print('Origin MAC: ' + originMAC2)
# ----------------------------------------
sha1_attack_new_data = sha1_attack.attackSHA1('IAmNotAdmin', originMAC2, 'YesIam', 17)
extendedString = sha1_attack_new_data[0]
newMac = sha1_attack_new_data[1]
print('New MAC: ' + newMac)
print('Extended text: ' + extendedString)
print('Verified result: ' + str(verifyMac('IAmNotAdmin' + extendedString + 'YesIam', newMac)))


#print(sha1.getHash('secret', 'I AmNotAdmin'))