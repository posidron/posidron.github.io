section .text

global _start

_start:
	; 0 = stdout, 1 = stdout, 2 = stderr, 3 descriptor
	xor ebx, ebx
	xor ecx, ecx
	mov al, 0x3f
	int 0x80

	inc ecx
	mov al, 0x3f
	int 0x80

	inc ecx
	mov al, 0x3f
	int 0x80

	mov al, 1
	int 0x80
