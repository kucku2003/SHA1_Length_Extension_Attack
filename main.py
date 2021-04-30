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
        messageBinary = self.__convertMessageToBinary(str.encode(key) + str.encode(text))
        extendedMessageBinary = self.__extendMessageBinary(messageBinary)
        return self.__generateSHA1(extendedMessageBinary)


    # ------------------------------------------------------
    def __convertMessageToBinary(self, message):
        messageInBinary = ''

        # Convert each character to 8-bit binary. 
        for char in message:
            messageInBinary = messageInBinary + format(char, 'b').zfill(8)

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
    def attachSHA1(self, originText, originMac, appendText, originMessageLength):

        originMacInBinary = bin(int(originMac, 16))[2:].zfill(8)
        h0 = originMacInBinary[0:32]
        h1 = originMacInBinary[32:64]
        h2 = originMacInBinary[64:96]
        h3 = originMacInBinary[96:128]
        h4 = originMacInBinary[128:160]

        h0_init = '01100111010001010010001100000001' 
        h1_init = '11101111110011011010101110001001' 
        h2_init = '10011000101110101101110011111110' 
        h3_init = '00010000001100100101010001110110' 
        h4_init = '11000011110100101110000111110000' 

        if (int(h0, 2) <= int(h0_init, 2)):
            a = self.util.bitMINUS('1'+ h0, h0_init, 32)
        else:
            a = self.util.bitMINUS(h0, h0_init, 32)

        if (int(h1, 2) <= int(h1_init, 2)):
            b = self.util.bitMINUS('1'+ h1, h1_init, 32)
        else:
            b = self.util.bitMINUS(h1, h1_init, 32)

        if (int(h2, 2) <= int(h2_init, 2)):
            c = self.util.bitMINUS('1'+ h2, h2_init, 32)
        else:
            c = self.util.bitMINUS(h2, h2_init, 32)

        if (int(h3, 2) <= int(h3_init, 2)):
            d = self.util.bitMINUS('1'+ h3, h3_init, 32)
        else:
            d = self.util.bitMINUS(h3, h3_init, 32)

        if (int(h4, 2) <= int(h4_init, 2)):
            e = self.util.bitMINUS('1'+ h4, h4_init, 32)
        else:
            e = self.util.bitMINUS(h4, h4_init, 32)
    
        newMessage = ''
        newMac = ''
        return [newMessage,newMac]


    # ------------------------------------------------------
    def __convertMessageBinary(self, message):
        messageBinary = ''
        for char in message:
            messageBinary = messageBinary + format(char, 'b').zfill(8)

        messageBinaryLength = len(messageBinary)
        messageBinary = messageBinary + '1'
        while len(messageBinary) % 512 != 448:
            messageBinary = messageBinary + '0'

        return (messageBinary + '{0:064b}'.format(messageBinaryLength))


    # ------------------------------------------------------
    def __extendMessageBinary(self, messageBinary):
        extendedMessageBinary = ''
        for index in range(80):
            if index < 16:
                messageBinary32BitChunk = messageBinary[(index+1)*32-32:(index+1)*32]
                extendedMessageBinary = extendedMessageBinary + messageBinary32BitChunk
            elif index >= 16:
                w0 = extendedMessageBinary[(index-2)*32-32:(index-2)*32]
                w1 = extendedMessageBinary[(index-7)*32-32:(index-7)*32]
                w2 = extendedMessageBinary[(index-13)*32-32:(index-13)*32]
                w3 = extendedMessageBinary[(index-15)*32-32:(index-15)*32]

                w = ''
                x1 = self.util.bitXOR(w0,w1,32) 
                x2 = self.util.bitXOR(x1,w2,32)
                x3 = self.util.bitXOR(x2,w3,32)
                w = w + x3

                extendedMessageBinary = extendedMessageBinary + self.util.rotate(w,1)
                
        return extendedMessageBinary


    # ------------------------------------------------------
    def __generateSHA1(self, extendedMessageBinary):
        h0 = '01100111010001010010001100000001' # 67452301
        h1 = '11101111110011011010101110001001' # EFCDAB89
        h2 = '10011000101110101101110011111110' # 98BADCFE
        h3 = '00010000001100100101010001110110' # 10325476
        h4 = '11000011110100101110000111110000' # C3D2E1F0
        
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            w = extendedMessageBinary[(i+1)*32-32:(i+1)*32]
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

print(verifyMac('musterman', 'c2cb7b4ef7d5e0468a28118d59f59504fa67cd06'))


sha1 = SHA1()
mySHA1 = sha1.getHash('key', 'c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06c2cb7b4ef7d5e0468a28118d59f59504fa67cd06')
print(mySHA1)


sha1_attack = SHA1_Length_Attack()
mySHA1 = sha1_attack.attachSHA1('musterman', 'c2cb7b4ef7d5e0468a28118d59f59504fa67cd06', 'max', 15)


# key = 'secret'
# message = 'musterman'

# sha1 = SHA1()
# mySHA1 = sha1.getHash(key, message)
# print('Key: "{key}" - Message: "{message}" : {value}'.format(key = key, message = message, value = mySHA1))

