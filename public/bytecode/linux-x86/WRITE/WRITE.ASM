section .text

global _start

_start:
	jmp short gotocall

shellcode:

	pop ecx
	mov dl, 14
	mov bl, 1
	mov al, 4
	int 0x80

	mov al, 1
	int 0x80

gotocall:
    call        shellcode
    db          'Hello World!\n'
