#!/usr/bin/python3
from pwn import *
import os
fname = './hashim0_hronou' # change this
final = 'hashim_hronou'

def pwn():
	os.system('./upx -d ' + fname + ' -o ' + final)
	r = process(final)
	gdb.attach(r,'''
		b *0x400d32
		r
		set $rax = 0
		b *0x400d75
		c
		set $rax = 0
		b *0x400d8f
		c
		set {char [13]} $rdi = "~#$w3t&69420"
		b *0x400da0
		c
		set {char [13]} $rdi = "~#$w3t&69420"
		b *0x400db8
		c
		set {char [13]} $rdi = "~#$w3t&69420"
		c
		''')

if __name__ == '__main__':
	pwn()