"""
Silly script to print the opcode of an asm instruction.
Requirements: nasm, objdump, echo, ld, python

[~] $ python opcode.py "jmp [ecx+10]"
 8048080:       ff 61 0a                jmp    *0xa(%ecx)
[~] $ python opcode.py "jmp [ecx+11]"
 8048080:       ff 61 0b                jmp    *0xb(%ecx)
[~] $ python opcode.py "jmp ecx"
 8048080:       ff e1                   jmp    *%ecx
[~] $ python opcode.py "mov al, 1"
 8048080:       b0 01                   mov    $0x1,%al
[~] $
"""
import os
import re
import sys

asm = "[SECTION .text]\nglobal _start\n_start:\n\t"

try:
    instr = sys.argv[1];
except IndexError:
    sys.exit("opcode.py <instruction>");

asm += instr

cmd = "echo \"" + asm + "\" >  a.asm ; nasm -f elf a.asm ; ld -o a a.o ; objdump -d a > opcode"
os.system(cmd)

b = open("opcode", "r").read()

p = re.compile(".*:\s\w.*")

for m in p.findall(b):
    print m;
