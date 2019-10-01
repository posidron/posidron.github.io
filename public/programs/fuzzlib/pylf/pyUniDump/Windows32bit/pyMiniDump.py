#!C:\Programme\Python25\python.exe -u
# -*- coding: ISO-8859-1 -*- 

#=============================================================================
# Part of: pyLibFuzz
# ----------------------------------------------------------------------------
# This is NOT public software.
# It is restricted to give a copy of this source to somebody else.
#=============================================================================

from ctypes  import *
from Hexdump import *

__title__    = "pyMiniDump"
__version__  = "1.0"
__build__    = "4rd March 2007"
__update__   = "5th March 2007"
__author__   = "posidron"

DEBUG_SUPPORT = True

#=============================================================================
# Reference: - http://msdn2.microsoft.com/en-us/library/ms679304.aspx
#            - WinNT.h (for CONTEXT structure)
#=============================================================================

# WaitForDebugEvent() Types
EXCEPTION_DEBUG_EVENT      = 1
CREATE_THREAD_DEBUG_EVENT  = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT    = 4
EXIT_PROCESS_DEBUG_EVENT   = 5
LOAD_DLL_DEBUG_EVENT       = 6
UNLOAD_DLL_DEBUG_EVENT     = 7
OUTPUT_DEBUG_STRING_EVENT  = 8
RIP_EVENT                  = 9

# Exception Types
EXCEPTIONS = {
    0xC0000005L: "EXCEPTION_ACCESS_VIOLATION",
    0xC0000006L: "EXCEPTION_IN_PAGE_ERROR",
    0xC0000008L: "EXCEPTION_INVALID_HANDLE",
    0xC0000017L: "EXCEPTION_NO_MEMORY",
    0xC000001DL: "EXCEPTION_ILLEGAL_INSTRUCTION",
    0xC0000025L: "EXCEPTION_NONCONTINUABLE_EXCEPTION",
    0xC0000026L: "EXCEPTION_INVALID_DISPOSITION",
    0xC000008CL: "EXCEPTION_ARRAY_BOUNDS_EXCEEDED",
    0xC000008DL: "EXCEPTION_FLOAT_DENORMAL_OPERAND",
    0xC000008EL: "EXCEPTION_FLOAT_DIVIDE_BY_ZERO",
    0xC000008FL: "EXCEPTION_FLOAT_INEXACT_RESULT", 
    0xC0000090L: "EXCEPTION_FLOAT_INVALID_OPERATION",
    0xC0000091L: "EXCEPTION_FLOAT_OVERFLOW",
    0xC0000092L: "EXCEPTION_FLOAT_STACK_CHECK",
    0xC0000093L: "EXCEPTION_FLOAT_UNDERFLOW",
    0xC0000094L: "EXCEPTION_INTEGER_DIVIDE_BY_ZERO",
    0xC0000095L: "EXCEPTION_INTEGER_OVERFLOW",
    0xC0000096L: "EXCEPTION_PRIVILEGED_INSTRUCTION",
    0xC00000FDL: "EXCEPTION_STACK_OVERFLOW",
    0xC000013AL: "EXCEPTION_CONTROL_C_EXIT",
}

# CreateProcess() Flags
CREATE_BREAKAWAY_FROM_JOB        = 0x01000000
CREATE_DEFAULT_ERROR_MODE        = 0x04000000
CREATE_NEW_CONSOLE               = 0x00000010
CREATE_NEW_PROCESS_GROUP         = 0x00000200
CREATE_NO_WINDOW                 = 0x08000000
CREATE_PROTECTED_PROCESS         = 0x00040000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
CREATE_SEPARATE_WOW_VDM          = 0x00000800
CREATE_SHARED_WOW_VDM            = 0x00001000
CREATE_SUSPENDED                 = 0x00000004
CREATE_UNICODE_ENVIRONMENT       = 0x00000400
DEBUG_ONLY_THIS_PROCESS          = 0x00000002
DEBUG_PROCESS                    = 0x00000001
DETACHED_PROCESS                 = 0x00000008
EXTENDED_STARTUPINFO_PRESENT     = 0x00080000

# Set/GetThreadContext() Flags
MAXIMUM_SUPPORTED_EXTENSION  = 512
SIZE_OF_80387_REGISTERS	     = 80
CONTEXT_i386	             = 0x10000
CONTEXT_i486	             = 0x10000
CONTEXT_CONTROL	             = (CONTEXT_i386|0x00000001L)
CONTEXT_INTEGER	             = (CONTEXT_i386|0x00000002L)
CONTEXT_SEGMENTS	     = (CONTEXT_i386|0x00000004L)
CONTEXT_FLOATING_POINT	     = (CONTEXT_i386|0x00000008L)
CONTEXT_DEBUG_REGISTERS	     = (CONTEXT_i386|0x00000010L)
CONTEXT_EXTENDED_REGISTERS   = (CONTEXT_i386|0x00000020L)
CONTEXT_FULL	             = (CONTEXT_CONTROL|CONTEXT_INTEGER|CONTEXT_SEGMENTS)

# ContinueDebugEvent() Flags
DBG_CONTINUE              = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# OpenThread() Flags
THREAD_ALL_ACCESS  = 0x001F03FF
PROCESS_ALL_ACCESS = 0x001F0FFF

INFINITE = 0xffffffff
EXCEPTION_MAXIMUM_PARAMETERS = 15

#=============================================================================
# Event Structures
#=============================================================================

class EXCEPTION_RECORD(Structure):
    _fields_ = [
        ("ExceptionCode", c_ulong),
        ("ExceptionFlags", c_ulong),
        ("ExceptionRecord", c_void_p),
        ("ExceptionAddress", c_void_p),
        ("NumberParameters", c_ulong),
        ("ExceptionInformation", c_ulong * EXCEPTION_MAXIMUM_PARAMETERS),
    ]
    
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", c_ulong)
    ]

class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread", c_ulong),
        ("lpThreadLocalBase", c_void_p),
        ("lpStartAddress", c_ulong)
    ]

class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", c_ulong),
        ("hProcess", c_ulong),
        ("hThread", c_ulong),
        ("lpBaseOfImage", c_void_p),
        ("dwDebugInfoFileOffset", c_ulong),
        ("nDebugInfoSize", c_ulong),
        ("lpThreadLocalBase", c_void_p),
        ("lpStartAddress", c_ulong),
        ("lpImageName", c_void_p),
        ("fUnicode", c_ulong)
    ]

class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", c_ulong)
    ]

class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("dwExitCode", c_ulong)
    ]

class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", c_ulong),
        ("lpBaseOfDll", c_void_p),
        ("dwDebugInfoFileOffset", c_ulong),
        ("nDebugInfoSize", c_ulong),
        ("lpImageName", c_void_p),
        ("fUnicode", c_ulong)
    ]

class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", c_void_p),
    ]

class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData", c_char_p),
        ("fUnicode", c_ushort),
        ("nDebugStringLength", c_ushort)
    ]

class RIP_INFO(Structure):
    _fields_ = [
        ("dwError", c_ulong),
        ("dwType", c_ulong),
    ]

class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO)
    ]

class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", c_ulong),
        ("dwProcessId", c_ulong),
        ("dwThreadId", c_ulong),
        ("u", DEBUG_EVENT_UNION)
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", c_ulong),
        ("hThread", c_ulong),
        ("dwProcessId", c_ulong),
        ("dwThreadId", c_ulong)
    ]

class STARTUPINFO(Structure):
    _fields_ = [
        ("cb", c_ulong),
        ("lpReserved", c_char_p),
        ("lpDesktop", c_char_p),
        ("lpTitle", c_char_p),
        ("dwX", c_ulong),
        ("dwY", c_ulong),
        ("dwXSize", c_ulong),
        ("dwYSize", c_ulong),
        ("dwXCountChars", c_ulong),
        ("dwYCountChars", c_ulong),
        ("dwFillAttribute", c_ulong),
        ("dwFlags", c_ulong),
        ("wShowWindow", c_ushort),
        ("cbReserved2", c_ushort),
        ("lpReserved2", c_ubyte),
        ("hStdInput", c_ulong),
        ("hStdOutput", c_ulong),
        ("hStdError", c_ulong),
    ]

class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", c_ulong),
        ("StatusWord", c_ulong),
        ("TagWord", c_ulong),
        ("ErrorOffset", c_ulong),
        ("ErrorSelector", c_ulong),
        ("DataOffset", c_ulong),
        ("DataSelector", c_ulong),
        ("RegisterArea", c_byte * 80),
        ("Cr0NpxState", c_ulong)
    ]
	
class CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", c_ulong),
        ("Dr0", c_ulong),
        ("Dr1", c_ulong),
        ("Dr2", c_ulong),
        ("Dr3", c_ulong),
        ("Dr6", c_ulong),
        ("Dr7", c_ulong),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", c_ulong),
        ("SegFs", c_ulong),
        ("SegEs", c_ulong),
        ("SegDs", c_ulong),
        ("Edi", c_ulong),
        ("Esi", c_ulong),
        ("Ebx", c_ulong),
        ("Edx", c_ulong),
        ("Ecx", c_ulong),
        ("Eax", c_ulong),
        ("Ebp", c_ulong),
        ("Eip", c_ulong),
        ("SegCs", c_ulong),
        ("EFlags", c_ulong),
        ("Esp", c_ulong),
        ("SegSs", c_ulong),
        ("ExtendedRegisters", c_byte * MAXIMUM_SUPPORTED_EXTENSION)
    ]

#=============================================================================
# MiniDump
#=============================================================================

# GetMiniDump() Flags
DUMP_STDOUT = 0
DUMP_STRING = 1
DUMP_XML    = 2
DUMP_HTML   = 3
DUMP_TXT    = 4

#=============================================================================

kernel = windll.kernel32

class MiniDumpError(Exception):
    def __init__(self, msg):
        Exception.__init__(
            self, "Win32 Error %s failed: %s" %(msg, kernel.GetLastError()))

class MiniDump(object):
    def __init__(self):
        self.hprocess = None

    def createProcess(self, exe, args):
        sinfo = STARTUPINFO()
        pinfo = PROCESS_INFORMATION()
        if not kernel.CreateProcessW(None, " ".join((exe, args)),
                                     0, 0, 0, DEBUG_PROCESS, 0, 0,
                                     addressof(sinfo), addressof(pinfo)):
            raise MiniDumpError("createProcess()")
        self.hprocess = pinfo.hProcess
        return pinfo.dwProcessId
    
    def closeProcess(self):
        process = self.hprocess
        if process: kernel.TerminateProcess(process, 0)

    def openProcess(self, pid):
        self.hprocess = kernel.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not self.hprocess:
            raise MiniDumpError("OpenProcess()")

    def writeMemory(self, pos, input):
        ret = c_ulong(0)
        if not kernel.WriteMemory(self.hprocess,
                                  pos, input, len(input), addressof(ret)):
            raise MiniDumpError("WriteProcess()")
        return ret.value

    def readMemory(self, pos, size=32):
        output = (c_char * size)()
        kernel.ReadProcessMemory(self.hprocess,
                                 pos, addressof(output), size, None)
        return output.raw

    def openThread(self, threadId):
        thread = kernel.OpenThread(THREAD_ALL_ACCESS, False, threadId)
        if not thread: raise MiniDumpError("openThread()")
        return thread

    def getThreadContext(self, thread, ctx):
        ctx.ContextFlags = CONTEXT_FULL
        if kernel.GetThreadContext(thread, addressof(ctx)) == 0:
            raise MiniDumpError("GetThreadContext()")

    def continueDebugEvent(self, pid, tid):
        kernel.ContinueDebugEvent(pid, tid, DBG_CONTINUE)

    def waitForDebugEvent(self, until):
        event = DEBUG_EVENT()
        if not kernel.WaitForDebugEvent(addressof(event), until): return None
        return event

    def isValidEvent(self, event):
        if event.dwDebugEventCode != EXCEPTION_DEBUG_EVENT: return False
        code = event.u.Exception.ExceptionRecord.ExceptionCode
        if EXCEPTIONS.get(code): return True
        return False

    def getEvent(self):
        while True:
            event = self.waitForDebugEvent(INFINITE)
            if not event: continue
            if not self.isValidEvent(event):
                self.continueDebugEvent(event.dwProcessId, event.dwThreadId)
                continue
            self.__setMiniDump(event)
            return True

    def getEventSnapshot(self, until=10):
        start = kernel.GetTickCount()
        until *= 1000
        #FIXME while loop which uses float
        while (kernel.GetTickCount() - start < until):
            event = self.waitForDebugEvent(200)
            if not event: continue
            if not self.isValidEvent(event):
                self.continueDebugEvent(event.dwProcessId, event.dwThreadId)
                continue
            self.__setMiniDump(event)
            return True

    def __setMiniDump(self, event):
        self.crashdump = dict()
        ctx = CONTEXT()
        self.getThreadContext(self.openThread(event.dwThreadId), ctx)
        self.openProcess(event.dwProcessId)
        
        regs = (("EAX", ctx.Eax), ("EBX", ctx.Ebx),
                ("ECX", ctx.Ecx), ("EDX", ctx.Edx),
                ("ESI", ctx.Esi), ("EDI", ctx.Edi),
                ("ESP", ctx.Esp), ("EBP", ctx.Ebp),
                ("EIP", ctx.Eip))

        code = event.u.Exception.ExceptionRecord.ExceptionCode
        self.crashdump["Exception"] = EXCEPTIONS.get(code)
        
        info = event.u.Exception.ExceptionRecord.ExceptionInformation[0]
        if   info == 0:
            self.crashdump["Type"] = "when reading from"
        elif info == 1:
            self.crashdump["Type"] = "when writing to"
        elif info == 8:
            self.crashdump["Type"] = "user-mode DEP violation at"

        exception_addr = event.u.Exception.ExceptionRecord.ExceptionAddress
        self.crashdump["Location"]  = "0x%08x" % exception_addr
        register = []
        for name, obj in regs:
            register.append((name, "0x%08x" % obj, repr(self.readMemory(obj, 15))))
        self.crashdump["Context"] = register
        memory = Hexdump(self.readMemory(ctx.Esp, 255),ctx.Esp-16).getString()
        self.crashdump["Memory"] = memory.replace("\n", "\r\n")

    def getMiniDump(self, flag=None, name=None):
        length = 77
        simple = lambda x: "\r\n"+x*length+"\r\n"
        titled = lambda x: "\r\n"+"-[ "+x+" ]"+"-"*(length-len(x)-5)+"\r\n"
        if flag == DUMP_STDOUT:
            print simple("="),
            print titled("Message")
            print self.crashdump.get("Exception"),
            print self.crashdump.get("Type"), "address",
            print "[",self.crashdump.get("Location"),"]"
            print titled("Context")
            for name, addr, bytes in self.crashdump.get("Context"):
                print name, addr, bytes
            print titled("Memory")
            print self.crashdump.get("Memory"), simple("=")
        if flag == DUMP_STRING:
            dump = simple("=")+titled("Message")+"\r\n"
            dump += self.crashdump.get("Exception")+" "+self.crashdump.get("Type")+ " "
            dump += "address"+" "+"["+self.crashdump.get("Location")+"]"+"\r\n"
            dump += titled("Context")
            for name, addr, bytes in self.crashdump.get("Context"):
                dump += "\r\n" + name + " " + addr + " " + bytes
            dump += "\r\n"+titled("Memory")+self.crashdump.get("Memory")
            dump += simple("=")
            return dump
        else:
            return self.crashdump

    def attach(self, pid): 
        if not kernel.DebugActiveProcess(pid):
            raise MiniDumpError("attach()")

    def detach(self, pid):
        if not kernel.DebugActiveProcessStop(pid):
            raise MiniDumpError("detach()")


if __name__ == "__main__":
    print "pyMiniDump", __version__
