section .text

global _start

_start:
	xor eax, eax
	xor ebx, ebx
	mov byte al, 17h
	int 80h

	mov byte al, 1h
	int 80h
