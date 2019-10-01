class Hexdump(object):
    def __init__(self, data, base=0, size=16):
        self.data = data
        self.size = size
        self.base = base

    def getList(self):
        l = list()
        for b in self.__get_block():
            l.append(self.__new_entry(self.getHex(b), self.getAscii(b)))
        return l

    def getString(self):
        s = str()
        for i in self.getList():
            s+=("0x%08x"%i[0])+"  "+" ".join(i[1])+"  "+"".join(i[2])+"\n"
        return s

    def __get_block(self):
        for block in range(0,len(self.data), self.size):
            yield self.data[block:block+self.size]

    def __new_entry(self, hex, ascii):
        padds = self.size - len(hex)
        map(hex.append, ["  " for p in range(padds)])
        self.base += self.size
        return (self.base, hex, ascii)

    def getHex(self, bytes):
        l = list()
        for byte in bytes:
            byte = hex(ord(byte))[2:]
            if len(byte) == 1: l.append("0"+byte)
            else: l.append(byte)
        return l

    def getAscii(self, bytes):
        l = list()
        for byte in bytes:
            if ord(byte) < 32 or ord(byte) > 126: l.append(".")
            else: l.append(byte)
        return l
