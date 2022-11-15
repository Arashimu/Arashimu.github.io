---
title: 2022-hackgame复现
date: 2022-10-29 13:40:21
tags: wp
---

# General 部分

### 小技巧

- 在一个文件中搜索某一个关键词，可以将这个文件用 IDE 打开如 CLion 等，然后`Edit->Find-Find in Files`输入关键字搜索即可

- VsCode 正则替换

  - 具体语法参考[微软](https://learn.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-language-quick-reference)
  - 从左到右，每个用`()`括起来的部分，都默认对应一个`$n`，其中`n`从左到右从`1`开始编号，用来在替换的时候保存`()`中的内容使用。比如`3=1+2`，正则查找为`(\d)=(\d) `，会匹配`3=1`，替换为`$1>=$2`，之后会变成`3>=1+2`

### Xcaptcha

可以使用的Python库有`requests`、`re`、`BeautifulSoup`

``` python
import requests
import re

url='http://202.38.93.111:10047/xcaptcha'
session=requests.Session()
Html=session.get(url,cookies={'session','<session-cookies>'}).text
number=[int(i[0],i[1]) for i in re.findall(r'(\d+)+(\d+)',Html)]
session.post(url,data={
	'captcha1':number[0],
	'captcha2':number[1],
	'captcha3':number[2],
	})
print(session.text)
```

## Binary

### flag自动机

#### 知识点

##### Win32API

在 Windows 操作系统中，**窗口（Window）**的定义是抽象的。对于一个 Windows 下的 GUI 程序来说，不仅仅只有那个大大的对话框是窗口，对话框中的一个按钮，一段文本，一个输入框，都算作是一个窗口。每个 Windows 下的 GUI 程序都至少会创建一个窗口，它充当用户与应用程序之间的主接口，称为**主窗口**。

窗口有这样一些特性：

- 每个窗口都由一个被称为**窗口句柄（Window Handle）**的整数唯一标识
- 每个窗口都有一个**窗口过程（Window Procedure）**，它是一个回调函数，在窗口接收到消息时，这个回调函数就会被调用，常见的名称是`lpfnWndProc`

Windows 的消息机制：Windows 下的 GUI 程序是**事件驱动**的。在 Windows 下，用户敲击键盘、移动鼠标、点击鼠标按钮、改变窗口尺寸，这些操作都算作是一个**事件（Event）**。当有事件发生的时候，Windows 就会生成一条消息，将其放入相应应用的**消息队列**中。每个 GUI 程序都必须负责处理自己的消息队列，处理消息队列的逻辑被称为**消息循环（Message Loop）**。

一个简单的消息循环实现大概长这样：

``` cpp
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
```

##### Frida

#### IDA Patch二进制文件

选中一条汇编指令，然后在`Edit->Patch Program->Assemble`中可以修改汇编，然后点击在`Edit->Patch Program->Apply patches to input file `即可修改源文件。一般用于修改程序的控制流程达到绕过的目的

在本题中主要处理`0x401510 `这个窗口过程函数

+ 创建窗口，创建了三个按钮，一个是 “狠心夺取”，对应的 WPARAM为 3，一个 “放手离开”，WPARAM为 2，一个没有显示不管
+ 当点击会"狠心夺取"的时候，会判断`lParam`是否为`114514`，不是就不可以获得`flag`

所以想法就是：由于"狠心夺取"会一直动，不好点击，所以我们对换他们对应的WPARAM，然后更改`lParam`的执行流即可。

## Math

