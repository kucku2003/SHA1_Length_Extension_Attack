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
    # Returns fixed bits-length l 
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
    # Returns fixed bits-length l 
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