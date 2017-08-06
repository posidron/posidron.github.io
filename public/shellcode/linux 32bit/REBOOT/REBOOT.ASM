section .text

global _start

_start:
	mov ebx, 0xfee1dead
	mov ecx, 0x28121969
	mov edx, 0x1234567
	mov al, 0x58
	int 0x80

