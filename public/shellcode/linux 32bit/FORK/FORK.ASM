section .text

global _start

_start:
	xor ebx, ebx
	mov al, 2
	int 0x80
