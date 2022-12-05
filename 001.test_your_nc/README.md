# 知识点

签到题，测试nc链接。



# 题目分析

拖入IDA反编译后发现直接调用了system("/bin/sh")函数。



方法一：

linux命令行直接 nc xxx.xxx.xxx.xxx xxxx 连接成功后直接cat flag即可。



方法二：编写Exp

```python
from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')

io = remote('node4.buuoj.cn', 28698)

io.sendline('ls')
io.sendline('cat flag')

io.interactive()
```

