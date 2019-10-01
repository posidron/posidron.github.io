#!C:\Programme\Python25\python.exe -u
# -*- coding: ISO-8859-1 -*- 

#=============================================================================
# This is NOT public software.
# It is restricted to give a copy of this source to somebody else.
#=============================================================================

__title__    = "pylf"
__version__  = "3.1"
__build__    = "23rd November 2006"
__update__   = "20th June 2007"
__author__   = "posidron"


import binascii, bz2, zlib, hashlib
import shutil, subprocess
import sys, os, random, re, time
import socket, thread, threading, Queue
import pickle, marshal
import cStringIO
import struct
import platform

from pyUniDump import pyMiniDump
DEBUG_SUPPORT = pyMiniDump.DEBUG_SUPPORT

DATA_REPLACE = 0
DATA_INSERT  = 1

COMPRESS_GZIP = 0
COMPRESS_BZ2  = 1

CRYPT_MD5 = 0

ENCODE_UUENCODE = 0
ENCODE_BASE64   = 1

REGXCHARS = ["?", "\\", "$", "^", "+", ".", "*", ",", "|", "(", ")", "[", "]"]

STATISTIC_TXT  = 0
STATISTIC_HTML = 1
STATISTIC_XML  = 2

LOG_INFO  = 0x00000001
LOG_DEBUG = 0x00000002
LOG_ERROR = 0x00000004


class pyLibFuzzError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, "*ERROR* %s " %  msg)


class pyLibFuzzWarning(Exception):
    def __init__(self, msg):
        Exception.__init__(self, "*WARNING* %s " % msg)


class Char(object):
    def __new__(self, index, codec=None):
         if codec:
             return unichr(index).encode(codec)
         return chr(index)


class String(object):
    def __init__(self, iterset, charset, *options):
        self.iterset = iterset
        self.charset = charset
        self.options = options

    def __get_random_string(self, length):
        l = []
        for min, max in self.charset:
            for char in xrange(min, max+1):
                l += unichr(char)
        s = ''
        for size in xrange(length):
            s += l[random.randint(0, len(l)-1)]
        return s.encode(self.options[1] or 'ascii')

    def __get_strict_string(self, length):
        for min, max in self.charset:
            for char in xrange(min, max+1):
                s = (unichr(char)*length)
                yield s.encode(self.options[1] or 'ascii')

    def __iter__(self):
        min, max, add = self.iterset
        for length in xrange(min, max, add):
            if self.options[0] == True:
                yield self.__get_random_string(length)
            else:
                for string in self.__get_strict_string(length):
                    yield string


class Multiyield(object):
    def __new__(self, args):
        if len(args) == 1:
            for each_next in args[0]:
                yield (each_next,)
        else:
            last_iter_result = list(self.__new__(self, args[1:]))
            for each_next_of_iter in args[0]:
                for each_item in last_iter_result:
                    yield (each_next_of_iter,) + each_item


class Replace(object):
    def __init__(self, src, patterns):
        self.src = src
        self.patterns = patterns
    
    def get_multi_yield(self, args):
        for each_next in Multiyield(args):
            yield each_next

    def __verify_patterns(self):
        for k in self.patterns.keys():
            if k not in self.src:
                self.patterns.pop(k)
    
    def __get_string_generators(self):
        l = []
        for k, v in self.patterns.items():
            l.append(String(v[0], v[1], v[2], v[3]))
        return l
    
    def __get_string_replaced(self, values):
        cp = self.src
        for s in values:
            r = self.patterns.keys()[list(values).index(s)]
            cp = cp.replace(r, s)
        return cp

    def __iter__(self):
        self.__verify_patterns()
        generators = self.__get_string_generators()
        if not generators:
            raise StopIteration
        for values in self.get_multi_yield(generators):
            yield self.__get_string_replaced(values)


class Process(pyMiniDump.MiniDump):
    def __init__(self):
        pyMiniDump.MiniDump.__init__(self)

    def __getattr__(self, name):
        if not hasattr(self, name):
            raise pyLibFuzzError("Unsupported attribute: %s" % name)
        return self.__dict__[name]
    
    def open(self, bin, args):
        return subprocess.Popen([bin, args]).pid
    
    def kill(self, pid):
        if os.name == "nt" or os.name == "ce":
            os.system("taskkill /F /PID "+str(pid))
        else:
            os.kill(pid, 9)

    def execute(self, path, args, close=False, wait=0):
        pid = self.open(path, args)
        if close:
            self.wait(wait); self.kill(pid)
        return pid

    def wait(self, interval):
        time.sleep(float(interval))


class File(Process):
    def __init__(self):
        Process.__init__(self)

    def size(self, path):
        return os.path.getsize(path)

    def remove(self, path):
        if self.isValid(path): os.remove(path)

    def move(self, dst, src):
        if self.isValid(src) and self.isValid(dst):
            shutil.move(src, dst)

    def clone(self, dst, src):
        if self.isValid(src) and self.isValid(dst):
            shutil.copy2(src, dst)
            return os.path.join(dst, os.path.split(src)[1])

    def read(self, path):
        if not self.isValid(path): return
        try:
            f = open(path, "rb")
            data = f.read()
            f.close()
        except IOError:
            return None
        return data

    def write(self, path, bytes):
        try:
            f = open(path, "wb")
            f.write(bytes)
            f.close()
        except IOError:
            pass

    def removeTree(self, path):
        if self.isValid(path): shutil.rmtree(path)

    def makeTree(self, *path):
        path = self.joinPath(*path)
        if not self.isValid(path): os.makedirs(path)
        return path

    def joinPath(self, *paths):
        return os.path.join(*paths)

    def extension(self, path):
        return os.path.splitext(path)[1][1:]

    def isValid(self, path):
        return os.access(path, os.F_OK)


class Dump(File):
    def __init__(self):
        self.__queue = 0
        self.__queue_index = 0
    
    def insert(self, content, offset, bytes):
        return content[:offset] + bytes + content[offset:]

    def replace(self, content, offset, bytes):
        return content[:offset] + bytes + content[offset+len(bytes):]

    def getTokens(self, tokens, src):
        osets = list()
        for tkn in map(str, tokens.split(",")):
            try:
                if tkn in REGXCHARS: tkn = "\\"+tkn
                map(osets.append, [p.span() for p in re.finditer(tkn, src)])
            except TypeError: continue
        return sorted(osets)

    def getOffsets(self, data, tokens):
        offsets = self.getTokens(tokens, data)
        self.setQueueIndex(len(offsets))
        for start, end in offsets:
            self.setQueueIndex(offsets.index(end))
            yield end

    def setOffsets(self, offsets, data):
        min, max, add = offsets
        if min < 0 or min > len(data): min = 0
        if max < 0 or max > len(data): max = len(data)+1
        if add < 0 or add > len(data): add = 1
        return (min, max, add)

    def setQueue(self, x): self.__queue = x

    def getQueue(self): return self.__queue

    def setQueueIndex(self, x): self.__queue_index += x

    def getQueueIndex(self): return self.__queue_index


class FileFuzz(Dump):
    def __init__(self, template, envdir="Tmp"):
        Dump.__init__(self)
        self.__setEnvironment(template, envdir)
        self.__counter  = 0

    def __setEnvironment(self, template, envdir):
        if not self.isValid(template):
            raise pyLibFuzzError("Unvailable file: %s" % template)
        self.__envdir = self.makeTree(envdir, self.extension(template))
        self.__template = self.read(self.clone(envdir, template))

    def getEnvironment(self): return self.__envdir

    def getOffsets(self, offsets, tokens=None):
        min, max, add = self.setOffsets(offsets, self.__template)
        if tokens:
            offsets = self.getTokens(tokens, self.__template[min:max])
            self.setQueue(len(offsets))
            for start, end in offsets:
                self.setQueueIndex(1)
                self.__offset = end
                yield end
        else:
            self.setQueue((max-min)/add)
            for offset in xrange(min, max, add):
                self.setQueueIndex(1)
                self.__offset = offset
                yield offset

    def getCurrentOffset(self):
        return self.__offset
    
    def setOutput(self, mode, offset, bytes):
        if mode == DATA_REPLACE: 
            self.__output = self.replace(self.__template, offset, bytes)
        elif mode == DATA_INSERT:
            self.__output = self.insert(self.__template, offset, bytes)

    def setPublishDir(self, filepath, *paths):
        self.__publishdir = self.makeTree(*paths)
        self.move(self.__publishdir, filepath)     

    def getPublishDir(self):
        return self.__publishdir
    
    def getOutput(self): return self.__output

    def getFileIndex(self): return self.__counter

    def __setFilename(self, ext=None, name=None):
        self.__counter += 1
        name = "".join((name or "", str(self.__counter), ext or ""))
        self.__filename = self.joinPath(self.__envdir, name)

    def getRelease(self): return self.__filename

    def setRelease(self, ext=None, name=None):
        self.__setFilename("."+ext, name)
        try:
            self.write(self.getRelease(), self.getOutput())
        except IOError, err: raise pyLibFuzzError(err)


class StringSettings(object):
    def crypt(self, m, *seq):
        if not hasattr(hashlib, m):
            return
        
        h = getattr(hashlib, m)()
        
        for s in seq: 
            h.update(s)
            
        return h.digest(), h.hexdigest()

    def compress(self, str, mode):
        if mode == COMPRESS_BZ2: 
            return bz2.compress(str)
        elif mode == COMPRESS_GZIP: 
            return zlib.compress(str)

    def encode(self, str, mode):
        if type(mode).__name__ == 'int':
            if mode == ENCODE_BASE64: 
                return binascii.b2a_base64(str)[:-1]
            elif mode == ENCODE_UUENCODE: 
                return binascii.b2a_uu(str)[:-1]
        elif type(mode).__name__ == 'str':
            try:
                return unicode(str).encode(mode)
            except LookupError:
                return


class Hexdump(object):
    def __init__(self, data, base=0, size=16):
        self.data = data
        self.size = size
        self.base = base

    def get_list(self):
        l = list()
        for b in self.__get_block():
            l.append(self.__new_entry(self.get_hex(b), self.get_ascii(b)))
        return l

    def get_string(self):
        s = str()
        for i in self.get_list():
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

    def get_hex(self, bytes):
        l = list()
        for byte in bytes:
            byte = hex(ord(byte))[2:]
            if len(byte) == 1: l.append("0"+byte)
            else: l.append(byte)
        return l

    def get_ascii(self, bytes):
        l = list()
        for byte in bytes:
            if ord(byte) < 32 or ord(byte) > 126: l.append(".")
            else: l.append(byte)
        return l


class TCP(socket.socket):
    
    RECEIVE_SIZE = 4096
    
    def __init__(self):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_STREAM)

    def peer(self, h, p, t=10):
        self.settimeout(t)
        self.connect((h, p))

    def read(self):
        return self.recv(self.RECEIVE_SIZE)

    def readall(self):
        return self.recvall()

    def recvall(self):
        b = []
        while 1:
            r = self.recv(self.RECEIVE_SIZE)
            if r == '':
                break
            b.append(r)
        
        return "".join(b)

    def sendline(self, s):
        return self.send(s+"\r\n")

    def is_alive(self):
        pass


class Packet(object):
    def __init__(self, content=None):
        if content != None:
            self.packet = cStringIO.StringIO(content)
        else:
            self.packet = cStringIO.StringIO()
    
    def __str__(self):
        return self.packet.getvalue()
    
    def get_bytes(self, n):
        b = self.packet.read(n)
        if len(b) < n:
            return '\x00'*n
        return b
    
    def get_boolean(self):
        b = self.get_bytes(1)
        return b!= '\x00'
    
    def get_int(self):
        return struct.unpack(">I", self.get_bytes(4))[0]
    
    def get_int64(self):
        return struct.unpack('>Q', self.get_bytes(8))[0]
    
    def get_mpint(self):
        s = self.get_string()
        acc = 0L
        unpack = struct.unpack
        length = len(s)
        if length % 4:
            extra = (4 - length % 4)
            s = '\000' * extra + s
            length = length + extra
        for i in range(0, length, 4):
            acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
        return acc

    def get_string(self):
        return self.get_bytes(self.get_int())
    
    def get_list(self):
        return self.get_string().split(',')
    
    def add_bytes(self, b):
        self.packet.write(b)
        return self
    
    def add_boolean(self, b):
        self.add_bytes(b or '\x00')
        return self
    
    def add_int(self, n):
        self.packet.write(struct.pack('>I', n))
        return self
    
    def add_int64(self, n):
        self.packet.write(struct.pack('>Q', n))
        return self
    
    def add_mpint(self, n):
        self.add_string(marshal.dumps(n))
        return self

    def add_string(self, s):
        self.add_int(len(s))
        self.packet.write(s)
        return self
    
    def add_list(self, l):
        self.add_string(','.join(l))
        return self
    
    def _add(self, i):
        if type(i) is str:
            return self.add_string(i)
        elif type(i) is int:
            return self.add_int(i)
        elif type(i) is long:
            if i > 0xffffffffL:
                return self.add_mpint(i)
            else:
                return self.add_int(i)
        elif type(i) is bool:
            return self.add_boolean(i)
        elif type(i) is list:
            return self.add_list(i)
        else:
            return self.add_bytes(i)
    
    def add(self, *seq):
        for item in seq:
            self._add(item)


class Timer(object):
    def __init__(self):
        self.idle = 0
        
    def init(self):
        self.i_time = time.clock()

    def stop(self):
        self.s_time = time.clock()

    def wait(self, n):
        time.sleep(n)
        self.idle += n
    
    def get_idle(self):
        return self.idle

    def get_busy(self):
        return self.s_time - self.i_time


class Config(object):
    def get(self, name):
        f = open(name, "r")
        settings = {}
        for ln in f.readlines():
            ln = ln.strip()
            if len(ln) == 0: 
                continue
            if ln[0] == "#": 
                continue
            k, v = ln.split("=")
            settings[k.strip()] = v.strip()
        f.close()
        return settings
        
    def set(self, name, settings):
        f = open(name, "w")
        for k, v in settings.items():
            f.write("%s = %s\r\n" % (k, v))
        f.close()


class Dump(object):
    def __init__(self, f):
        self.f = f

    def save(self, s):
        f = open(self.f, "w+b")
        pickle.dump(s, f)
        f.close()

    def load(self):
        f = open(self.f, "r+b")
        s = pickle.load(f)
        f.close()
        return s



class Log(object):
    def __init__(self, output, stdout, flags):
        self.output = output
        self.stdout = stdout
        # initialize
        self.set_verbose()
        self.set_timestamp()
        self.set_flags(flags)

    def __call__(self, *seq):
        if not self.has_info:
            return
        self._append('INFO', *seq)

    def debug(self, *seq):
        if not self.has_debug:
            return
        self._append('DEBUG', *seq)
    
    def error(self, *seq):
        if not self.has_error:
            return
        self._append('ERROR', *seq)

    def _append(self, m, *seq):
        s = ''
        if self.tmstamp:
            s += "[%s] " % time.asctime()

        s += "- [%s] - %s\n" % (m, str(seq[0]))
        
        if self.verbose:
            for i in seq[1:]:
                s += str(i)+"\n"

        if self.output:
            self._append_to_output(s)

        if self.stdout:
            self._append_to_stdout(s)

    def _append_to_output(self, s):
        f = open(self.output, 'a')
        f.write(s)
        f.close()

    def _append_to_stdout(self, s):
        sys.stdout.write(s)

    def set_flags(self, f):
        self.has_info  = f & LOG_INFO  != 0 or False
        self.has_error = f & LOG_ERROR != 0 or False
        self.has_debug = f & LOG_DEBUG != 0 or False

    def set_timestamp(self, t=True):
        self.tmstamp = t

    def set_verbose(self, v=True):
        self.verbose = v

    def delete(self):
        open(self.output, 'w').close()
        
    def remove(self):
        if os.access(self.output, os.F_OK):
            try:
                return os.remove(self.output)
            except IOError:
                pass

if __name__ == "__main__":
    print "PyLF", __version__