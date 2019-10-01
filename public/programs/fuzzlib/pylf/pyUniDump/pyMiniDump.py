import platform

DEBUG_SUPPORT = False

class MiniDump:
    def __init__(self):
        pass

sys_name = platform.system()
sys_arch = platform.architecture()[0]

print "Platform:", sys_name, sys_arch
print "*WARNING* [pyUniDump] has at time not support for your platform."

