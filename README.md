# Pwn-WriteUp
BUUCTF-Pwn题解（ WriteUp For BUUCTF-Pwn）

|             题目名             |        知识点        |               备注               |
| :----------------------------: | :------------------: | :------------------------------: |
|         1.test_your_nc         |      测试nc链接      |               签到               |
|             2.rip              |       ret2text       |        高版本libc堆栈平衡        |
|       3.warmup_csaw_2016       |       ret2libc       |       提供system和cat flag       |
|        4.ciscn_2019_n_1        |    栈溢出覆盖变量    |          小数转十六进制          |
|        5.pwn1_sctf_2016        |       ret2text       |           观察汇编代码           |
|       6.jarvisoj_level0        |       ret2text       |             后门函数             |
|        7.ciscn_2019_c_1        |       ret2libc       |         通过puts泄露libc         |
|   8.[第五空间2019 决赛]PWN5    |     格式化字符串     |              随机数              |
|        9.ciscn_2019_n_8        |    栈溢出覆盖数组    |             简单溢出             |
|       10.jarvisoj_level2       |       ret2libc       |       提供system和/bin/sh        |
|     11.[OGeek2019]babyrop      | strlen截断、ret2libc | \x00截断strlen、通过puts泄露libc |
|   12.get_started_3dsctf_2016   |       ret2text       |           32位参数传递           |
|    13.bjdctf_2020_babystack    |       ret2text       |             简单溢出             |
|       14.ciscn_2019_en_2       |       ret2libc       |         通过puts泄露libc         |
|  15.not_the_same_3dsctf_2016   |   ret2text、write    |        程序提供write函数         |
|  16.[HarekazeCTF2019]baby_rop  |       ret2libc       |       提供system和/bin/sh        |
|     17.jarvisoj_level2_x64     |       ret2libc       |       提供system和/bin/sh        |
|       18.ciscn_2019_n_5        |    ret2shellcode     |    两次栈溢出，没开启NX保护。    |
|      19.others_shellcode       |         签到         |        运行得到shellcode         |
|       20.ciscn_2019_ne_5       |       ret2libc       |     strcpy溢出、sh字符串查找     |
| 21.铁人三项(第五赛区)_2018_rop |       ret2libc       |        通过write泄露libc         |
|     22.bjdctf_2020_babyrop     |       ret2libc       |         通过puts泄露libc         |
|         23.jarvisoj_fm         |     格式化字符串     |           修改变量的值           |
|   24.bjdctf_2020_babystack2    |  整数溢出、ret2text  |       size_t溢出、ret2text       |
|       25.pwn2_sctf_2016        |  整数溢出、ret2libc  |   unsigend溢出、printf泄露libc   |
|     26.babyheap_0ctf_2017      |                      |                                  |



# 技巧

## python代码包含中文无法运行

在源文件头部增加命令说明python代码的编码：

```python
# coding=utf-8
```



## context设置

32位程序对应i386，64位程序对应amd64。

```python
context(arch = 'i386', os = 'linux', log_level = 'debug')
context(arch = 'amd64', os = 'linux', log_level = 'debug')
```



## 接收泄漏的libc地址

32位libc地址\xf7开头，长度 4位。64位libc地址\x7f开头，长度6位。

32位直接接收并使用u32转换即可。

64位接收至\x7f，然后切片截取后6位，使用\x00补齐高两位，然后使用u64转换即可。

```python
address = u32(io.recv(4))
address = u64(io.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
```



## 踩坑

- 高版本libc（>= libc-2.23）在调用system时出现打不通的情况，可以尝试增加ret指令。

