---
title: 强网杯-polydiv
date: 2022-08-02 10:07:55
tags: 密码学
---

# Polydiv

## 知识点：

+ SHA256加密
+ 模二多项式环运算
+ 交互式脚本编写

## 下发文件

`poly2.py`

``` python

class Polynomial2():
    '''
    模二多项式环，定义方式有三种
    一是从高到低给出每一项的系数
        >>> Polynomial2([1,1,0,1])
        x^3 + x^2 + 1

    二是写成01字符串形式
        >>> Polynomial2('1101')
        x^3 + x^2 + 1

    三是直接给出系数为1的项的阶
        >>> Poly([3,1,4])
        x^4 + x^3 + x
        >>> Poly([]) # 加法元
        0
        >>> Poly(0) # 乘法元
        1
        >>> Poly(1,2) * Poly(2,3)
        x^5 + x^3
    '''
    def __init__(self,ll):
        
        if type(ll) ==  str:
            ll = list(map(int,ll))

        self.param = ll[::-1]
        self.ones = [i for i in range(len(self.param)) if self.param[i] == 1] # 系数为1的项的阶数列表
        self.Latex = self.latex()
        self.b = ''.join([str(i) for i in ll]) # 01串形式打印系数
        
        self.order = 0 # 最高阶
        try:self.order = max(self.ones)
        except:pass

    def format(self,reverse = True):
        '''
            格式化打印字符串
            默认高位在左
            reverse = False时，低位在左
            但是注意定义多项式时只能高位在右
        '''
        r = ''
        if len(self.ones) == 0:
            return '0'
        if reverse:
            return ((' + '.join(f'x^{i}' for i in self.ones[::-1])+' ').replace('x^0','1').replace('x^1 ','x ')).strip()
        return ((' + '.join(f'x^{i}' for i in self.ones)+' ').replace('x^0','1').replace('x^1 ','x ')).strip()

    def __call__(self,x):
        '''
            懒得写了，用不到
        '''
        print(f'call({x})')

    def __add__(self,other):
        '''
            多项式加法
        '''
        a,b = self.param[::-1],other.param[::-1]
        if len(a) < len(b):a,b = b,a
        for i in range(len(a)):
            try:a[-1-i] = (b[-1-i] + a[-1-i]) % 2
            except:break
        return Polynomial2(a)

    def __mul__(self,other):
        '''
            多项式乘法
        '''

        a,b = self.param[::-1],other.param[::-1]
        r = [0 for i in range(len(a) + len(b) - 1)]
        for i in range(len(b)):
            if b[-i-1] == 1:
                if i != 0:sa = a+[0]*i
                else:sa = a
                sa = [0] * (len(r)-len(sa)) + sa
                #r += np.array(sa)
                #r %= 2
                r = [(r[t] + sa[t])%2 for t in range(len(r))]
        return Polynomial2(r)

    def __sub__(self,oo):
        # 模二多项式环，加减相同
        return self + oo


    def __repr__(self) -> str:
        return self.format()
    
    def __str__(self) -> str:
        return self.format()

    def __pow__(self,a):
        # 没有大数阶乘的需求，就没写快速幂
        t = Polynomial2([1])
        for i in range(a):
            t *= self
        return t
    
    def latex(self,reverse=True):
        '''
            Latex格式打印...其实就是给两位及以上的数字加个括号{}
        '''
        def latex_pow(x):
            if len(str(x)) <= 1:
                return str(x)
            return '{'+str(x)+'}'
        
        r = ''
        if len(self.ones) == 0:
            return '0'
        if reverse:
            return (' + '.join(f'x^{latex_pow(i)}' for i in self.ones[::-1])+' ').replace('x^0','1').replace(' x^1 ',' x ').strip()
        return (' + '.join(f'x^{latex_pow(i)}' for i in self.ones)+' ').replace('x^0','1').replace(' x^1 ',' x ').strip()

    def __eq__(self,other):
        return self.ones == other.ones

    def __lt__(self,other):
        return max(self.ones) < max(other.ones)

    def __le__(self,other):
        return max(self.ones) <= max(other.ones)

def Poly(*args):
    '''
        另一种定义方式
        Poly([3,1,4]) 或 Poly(3,1,4)
    '''
    if len(args) == 1 and type(args[0]) in [list,tuple]:
        args = args[0]
        
    if len(args) == 0:
        return Polynomial2('0')
    
    ll = [0 for i in range(max(args)+1)]
    for i in args:
        ll[i] = 1
    return Polynomial2(ll[::-1])

```

`task.py`

``` python
import socketserver
import os, sys, signal
import string, random
from hashlib import sha256

from secret import flag
from poly2 import *

pad = lambda s:s + bytes([(len(s)-1)%16+1]*((len(s)-1)%16+1))
testCases = 40

class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b'> '):
        self.send(prompt, newline=False)
        return self._recvall()

    def close(self):
        self.send(b"Bye~")
        self.request.close()

    def proof_of_work(self):
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        _hexdigest = sha256(proof.encode()).hexdigest()
        self.send(f"sha256(XXXX+{proof[4:]}) == {_hexdigest}".encode())
        x = self.recv(prompt=b'Give me XXXX: ')
        if len(x) != 4 or sha256(x+proof[4:].encode()).hexdigest() != _hexdigest:
            return False
        return True

    def guess(self):
        from Crypto.Util.number import getPrime
        a,b,c = [getPrime(i) for i in [256,256,128]]
        pa,pb,pc = [PP(bin(i)[2:]) for i in [a,b,c]]
        r = pa*pb+pc
        self.send(b'r(x) = '+str(r).encode())
        self.send(b'a(x) = '+str(pa).encode())
        self.send(b'c(x) = '+str(pc).encode())
        self.send(b'Please give me the b(x) which satisfy a(x)*b(x)+c(x)=r(x)')
        #self.send(b'b(x) = '+str(pb).encode())
        
        return self.recv(prompt=b'> b(x) = ').decode() == str(pb)


    def handle(self):
        #signal.alarm(1200)

        if not self.proof_of_work():
            return

        for turn in range(testCases):
            if not self.guess():
                self.send(b"What a pity, work harder.")
                return
            self.send(b"Success!")
        else:
            self.send(b'Congratulations, this is you reward.')
            self.send(flag)
        
        

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

#class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
class ForkedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    
    HOST, PORT = '0.0.0.0', 10000
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()


```

## 解题思路

通过`nc`连接到服务器，一开始来到了`task.py`里的`proof_of_work()`函数，给出了一个`sha256(XXXX+{proof[4:]}) == {_hexdigest}`，要求解密`XXXX`。这个暴力跑就行了，破解脚本如下

``` python
from hashlib import sha256

ch['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9']

def  getXXXX(s,t):
    for a in ch:
        for b in ch:
            for c in ch:
                for d in ch:
                    ss=a+b+c+d
                    tt=ss+s
                    if sha256(tt.encode()).hexdigest()==t:
                        return ss

```

然后解密正确之后，进入`guess()`函数，然后会给出$3$模$2$多项式，其中$deg(r(x))=14$，$deg(a(x))=7$，$deg(c(x))=6$，要你给出$b(x)$满足在模$2$意义下$a(x)b(x)+c(x)=r(x)$。并且每个多项式给出的形式是$x^{14}+x^{12}+x^{9}+x^4+1$这样带$x$和$+$的字符串。并且有$40​$组这样的询问，全部通过应该才能拿到`flag`，所以要写一个交互式脚本

接下来看`poly2.py`文件，`Polynomial2`定义了一个模$2$多项式环的基本运算(没有除法运算和负幂次的运算)，每次定义一个对象需要传入一个$01$串来描述各个幂次的系数，并且`format`操作允许我们以标准形式输出多项式。而`Poly`函数则允许我们以一种更加简单的方式生成一个`Polynomial2`对象。

所以现在只需要考虑如何求除法，因为我们不能直接`(r-c)/x`或者`(r-c)*a**-1`，因此我们考虑暴力枚举$b(x)$的各个系数是多少，然后判断`ab+c==r`是否成立来返回$b$，因为$deg(b)=7$，所以最多$256$ 种情况，脚本如下

``` python
def get_b(r,a,c):
    ch=['00000000','00000001','00000010','00000011','00000100','00000101','00000110','00000111','00001000','00001001','00001010','00001011','00001100','00001101','00001110','00001111','00010000','00010001','00010010','00010011','00010100','00010101','00010110','00010111','00011000','00011001','00011010','00011011','00011100','00011101','00011110','00011111','00100000','00100001','00100010','00100011','00100100','00100101','00100110','00100111','00101000','00101001','00101010','00101011','00101100','00101101',
        '00101110','00101111','00110000','00110001','00110010','00110011','00110100','00110101','00110110','00110111','00111000','00111001','00111010','00111011','00111100','00111101','00111110','00111111','01000000','01000001','01000010','01000011','01000100','01000101','01000110','01000111','01001000','01001001','01001010','01001011','01001100','01001101','01001110','01001111','01010000','01010001','01010010','01010011','01010100','01010101','01010110','01010111','01011000','01011001','01011010','01011011',
        '01011100','01011101','01011110','01011111','01100000','01100001','01100010','01100011','01100100','01100101','01100110','01100111','01101000',
        '01101001','01101010','01101011','01101100','01101101','01101110','01101111','01110000','01110001','01110010','01110011','01110100','01110101','01110110','01110111','01111000','01111001','01111010','01111011','01111100','01111101','01111110','01111111','10000000','10000001','10000010','10000011','10000100','10000101','10000110','10000111','10001000','10001001','10001010','10001011','10001100','10001101','10001110','10001111','10010000','10010001','10010010','10010011','10010100','10010101','10010110',
        '10010111','10011000','10011001','10011010','10011011','10011100','10011101','10011110','10011111','10100000','10100001','10100010','10100011','10100100','10100101','10100110','10100111','10101000','10101001','10101010','10101011','10101100','10101101','10101110','10101111','10110000','10110001','10110010','10110011','10110100','10110101','10110110','10110111','10111000','10111001','10111010','10111011','10111100','10111101','10111110','10111111','11000000','11000001','11000010','11000011','11000100','11000101','11000110','11000111','11001000','11001001','11001010','11001011','11001100','11001101','11001110','11001111','11010000','11010001',
        '11010010','11010011','11010100','11010101','11010110','11010111','11011000','11011001','11011010','11011011','11011100','11011101','11011110','11011111','11100000','11100001','11100010','11100011','11100100','11100101','11100110','11100111','11101000','11101001','11101010','11101011','11101100','11101101','11101110','11101111','11110000','11110001','11110010','11110011','11110100','11110101','11110110','11110111','11111000','11111001','11111010','11111011','11111100','11111101','11111110','11111111']
    for s in ch:
        b= Polynomial2(s)
        if a*b+c==r:
            return b.format().encode()
```

但由于我们每次传入的是一个标准多项式，因此需要对标准多项式转换成可以传入的形式，即`Poly([3,1,4])` 或` Poly(3,1,4)`中参数的形式，所以编写脚本为

``` python
def p3(s):
    return eval( b'['+s.replace(b'+', b',').replace(b', 1', b', 0').replace(b'x^', b'').replace(b'x', b'1')+ b']' )    
```

感觉`python`的字符串操作很多也很杂，其实这题不是很难，难在交互式脚本的字符串操作，`python`用的不熟

接下来是交互式脚本的编写，考虑用`pwn`库远程连接，先给出最终脚本

``` python
from pwn import *
from hashlib import sha256
from poly2 import *
import string
ch=['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '0','1','2','3','4','5','6','7','8','9']

def  getXXXX(s,t):
    for a in ch:
        for b in ch:
            for c in ch:
                for d in ch:
                    ss=a+b+c+d
                    tt=ss+s
                    if sha256(tt.encode()).hexdigest()==t:
                        return ss

context.log_level = 'debug'
p =remote('39.107.137.85',13494)

p.recvuntil(b'sha256(XXXX+')

s=p.recvuntil(b') == ',drop=True)
t=p.recvline()[:-1]
print(s)
print(t)

XXXX=getXXXX(s.decode(),t.decode()).encode()
print(XXXX.decode())
p.sendlineafter(b'Give me XXXX: ',XXXX)


for i in range(0,40):
	p.recvuntil(b'(x) = ')
	r=Poly(p3(p.recvline()[:-1]))
	p.recvuntil(b'(x) = ')
	a=Poly(p3(p.recvline()[:-1]))
	p.recvuntil(b'(x) = ')
	c=Poly(p3(p.recvline()[:-1]))
	b=get_b(r,a,c)
	p.sendlineafter(b'> b(x) = ',b)
	p.recvuntil(b'Success!\n')

p.recv()
p.recv()
p.recv()
p.recv()
pause()
```

+ `context.log_level = 'debug'`可以将交互过程的信息显示出来
+ 注意`pwn`库里面的所接收和传递函数的参数都是`byte`类型的。所以字符串要用`b`来转化成`byte`类型
+ 用`encode`也可以转化成`byte`类型，用`decode`则可以把`byte`类型转换成字符串的类型
+ `recvline()[:-1]`表示接收一行(包括最后的`\n`)，`[:-1]`就是过滤`\n`

然后就可以成功`get flag`了。

其实还是可以在网上找到这个`Pply2.py`带有除法的脚本的

``` python
def div(self,other): 
        r,b = self.param[::-1],other.param[::-1] 
        if len(r) < len(b): 
            return Polynomial2(),self 
        q= [0]*(len(r) - len(b) + 1) 
        for i in range(len(q)): 
            if len(r)>=len(b): 
                index = len(r) - len(b) + 1 # 确定所得商是商式的第index位 
                q[-index] = int(r[0] / b[0]) # 更新被除多项式 
                b_=b.copy() 
                b_.extend([0]*(len(r) - len(b))) 
                b_ = [t*q[i] for t in b_] 
                r = [(r[t] - b_[t])%2 for t in range(len(r))] 
                for j in range(len(r)): #除去列表最左端无意义的0 
                    if r[0]==0: 
                        r.remove(0) 
                    else: 
                        break
            else: 
                break 
        return Polynomial2(q),Polynomial2(r)
```

加这个加入`Polynomial2`中即可。