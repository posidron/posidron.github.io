section .text

global _start

_start:
	xor ecx, ecx
	push ecx
	push 1
	push 2
	mov ecx, esp
	mov bl, 1
	mov al, 66h
	int 0x80

	mov ebx, eax
	mov al, 6
	int 0x80

	mov al, 1
	int 0x80
