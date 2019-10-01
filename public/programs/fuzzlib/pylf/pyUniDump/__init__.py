import os, platform

sys_name = platform.system()
sys_arch = platform.architecture()[0]

__path__.insert(0, os.path.join(__path__[0], sys_name+sys_arch))


import pyMiniDump
