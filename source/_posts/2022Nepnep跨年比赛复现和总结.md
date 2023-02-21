---
title: 2022Nepnep跨年比赛复现和总结
date: 2023-01-06 16:25:48
math: true
tags: 
---

# Crypto

## 总结

本次Crypto赛道一开始一道同态的题很快做出来了，然后就开始看盖茨比这题，得到相邻两个明文的异或以及明文和密钥的异或很简单，这也很快想到，但之后没思路了，尝试爆破密钥但觉得复杂度太高没有尝试，直到比赛也没做出来，赛后看wp发现原来这种形式可以用mtp来攻击，学习了。另一道DDH则是关于椭圆曲线的，赛后看题解发现涉及双线性对这个知识，没有接触过，这次比赛学习了。

##  cat_theory

### problem
``` python
from Crypto.Util.number import bytes_to_long, getStrongPrime, getRandomRange, getRandomNBitInteger
from secret import flag


class CatCrypto():
    
    def get_p_q(self) -> tuple:
        def get_blum_prime():
            while True:
                p = getStrongPrime(self.nbits // 2)
                if p % 4 == 3:
                    return p

        p = get_blum_prime()
        q = 2
        while gcd(p-1, q-1) != 2:
            q = get_blum_prime()
            
        return p, q
    
    # KeyGen:
    def __init__(self, nbits=1024):
        self.nbits = nbits
        
        self.p, self.q =  self.get_p_q()
        p, q = self.p, self.q
        
        self.n = p * q
        n = self.n
        
        self.lam = (p-1) * (q-1) // 2
        
        self.g = self.n + 1
        
        x = getRandomRange(1, n)
        h = -x^2 
        self.hs = int(pow(h, n, n^2))

        
    # Enc(pk, -) = Epk(-):
    def enc(self, m: int) -> int:
        n = self.n
        hs = self.hs
        
        a = getRandomNBitInteger(ceil( n.bit_length() / 2 ))
        c = (1 + m*n) * pow(hs, a, n^2)
        return int(c)
        
    # Dec(sk, -) = Dsk(-):
    def dec(self, c: int) -> int:
        lam = self.lam
        n = self.n
        
        L = lambda x: (x-1)//n
        
        mu = inverse_mod(lam, n)
        m = L( int(pow(c, lam, n^2)) ) * mu % n
        return m
        
        
    @property
    def nbits(self):
        return self.__nbits
    
    @nbits.setter
    def nbits(self, nbits):
        self.__nbits = nbits

cat = CatCrypto(nbits=1024)

m = bytes_to_long(flag)
assert m.bit_length() < 1024

m1 = getRandomNBitInteger(m.bit_length() - 1)
m2 = getRandomNBitInteger(m.bit_length() - 2)
m3 = m - m1 - m2

c1 = cat.enc(m1)
c2 = cat.enc(m2)
c3 = cat.enc(m3)

print(f'dec(c1*c2) = {cat.dec(c1*c2)}')
print(f'dec(c2*c3) = {cat.dec(c2*c3)}')
print(f'dec(c3*c1) = {cat.dec(c3*c1)}')

"""
dec(c1*c2) = 127944711034541246075233071021313730868540484520031868999992890340295169126051051162110
dec(c2*c3) = 63052655568318504263890690011897854119750959265293397753485911143830537816733719293484
dec(c3*c1) = 70799336441419314836992058855562202282043225138455808154518156432965089076630602398416
"""
```
### solve
给了一张交换图，其实就是同态关系，简单分析后可以得到
$dec(c_1,c_2)=m_1+m_2$，之后依次得到$m_2+m_3$，$m_3+m_1$，然后解$m_1,m_2,m_3$即可得到$m$



``` python
from Crypto.Util.number import bytes_to_long, long_to_bytes,getStrongPrime, getRandomRange, getRandomNBitInteger


#x=m1+m2    y=m2+m3   z=m3+m1
x=127944711034541246075233071021313730868540484520031868999992890340295169126051051162110
y=63052655568318504263890690011897854119750959265293397753485911143830537816733719293484
z=70799336441419314836992058855562202282043225138455808154518156432965089076630602398416

m1=(x-y+z)
m2=(y-z+x)
m3=(z-x+y)

m=(m1+m2+m3)
print(m)
flag=int(m//2)
print(flag)
print(long_to_bytes(flag))
```

## 盖茨比

+ mtp攻击

### problem
``` python
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor as xor
from Crypto.Util.Padding import pad
from random import *
from base64 import *
from copy import copy
from secret import data

iv=bytes([randint(0,2**8-1) for i in range(16)]) 
iva=copy(iv)
key=bytes([randint(0,2**8-1) for i in range(16)])
cipher=AES.new(key,mode=AES.MODE_ECB)
data=pad(data,16)
c=b""
for i in range(0,len(data),16):
    s=data[i:i+16].ljust(16,b"\n")
    c+=cipher.encrypt(xor(s,iv))
    iv=xor(s,c[-16:])


key=b64encode(key)
c=b64encode(c)

print(key)
print(c)
```

### solve
根据题目容易得到$dec(c_i)=s_i\oplus(s_{i-1}\oplus c_{i-1})$，因此可以得到$dec(c_i)\oplus c_{i-1}=s_i\oplus s_{i-1}$，然后就可以得到$\forall i \in (1,n)$，$s_i\oplus iv$，然后使用mtp攻击即可，mtp攻击是基于ascii异或性质得到的，具体参考[Mang-Time-Pad攻击](https://www.ruanx.net/many-time-pad/)

``` python
from base64 import *
from Crypto.Cipher import AES 
from Crypto.Util.strxor import strxor as xor 
from Crypto.Util.number import * 
import Crypto.Util.strxor as xo 
import libnum, codecs, numpy as np 

c=''
key=''
key=b64decode(key)
c=b64decode(c)
cipher=AES.new(key,mode=AES.MODE_ECB)
cc=[]
for i in range(0,int(len(c)/16)):
	cc.append(c[-16:])
	c=c[:-16]
cc=cc[::-1]
decc=[b"" for i in range(len(cc))]
for i in range(len(cc)):
	decc[i]=cipher.decrypt(cc[i])


s=[b"" for i in range(len(cc))]
sc=cc[0]
sdec=decc[0]
s[0]=decc[0]


for i in range(1,len(cc)):
	s[i]=xor(xor(decc[i],sdec),sc)
	sdec=xor(sdec,decc[i])
	sc=xor(sc,cc[i])


def isChr(x):
    if ord('a') <= x and x <= ord('z'): return True
    if ord('A') <= x and x <= ord('Z'): return True
    return False 
def infer(index, pos):  
    if msg[index, pos] != 0:  
    	return  
    msg[index, pos] = ord(' ')  
    for x in range(len(c)):
        if x != index:  
            msg[x][pos] = xo.strxor(c[x], c[index])[pos] ^ ord(' ') 
            
def know(index, pos, ch):  
    msg[index, pos] = ord(ch)  
    for x in range(len(c)):
        if x != index:  
            msg[x][pos] = xo.strxor(c[x], c[index])[pos] ^ ord(ch) 
            
def getSpace():  
    for index, x in enumerate(c):  
        res = [xo.strxor(x, y) for y in c if x!=y]  
        f = lambda pos: len(list(filter(isChr, [s[pos] for s in res])))  
        cnt = [f(pos) for pos in range(len(x))]  
        for pos in range(len(x)):  
            dat.append((f(pos), index, pos)) 
            
c=s
dat = [] 
msg = np.zeros([len(c), len(c[0])], dtype=int) 
getSpace() 
dat = sorted(dat)[::-1] 
for w, index, pos in dat:  
    infer(index, pos) 
    
print(''.join([''.join([chr(c) for c in x]) for x in msg])) 

```

最后得到
``` txt
Now, any author, from history's dawn, always had that most important aid to writing:-an ability to call upon any word in his dictionary in building up his story. That is, our strict laws as to word construction did not block his path. But in my story that mighty obstruction will constantly stand in my path; for many an important, common word I cannot adopt, owing to its orthography.

"Youth! What is it? Simply a start. A start of what? Why, of that most astounding of all human functions; thought. But man didn't start his brain working. No. All that an adult can claim is a continuation, or an amplification of thoughts, dormant in his youth. Although a child's brain can absorb instruction with an ability far surpassing that of a grown man; and, although such a young brain is bound by rigid limits, it contains a capacity for constantly craving additional facts. So, in our backward Branton Hills, I just know that I can find boys and girls who can show our old moss-back Town Hall big-wigs a thing or two. Why! On Town Hall night, just go and sit in that room and find out just how stupid and stubborn a Council, (put into Town Hall, you know, through popular ballot!), can act. Say that a road is badly worn. Shall it stay so? Up jumps Old Bill Simpkins claiming that it is a townsman's duty to fix up his wagon springs if that road is too rough for him!"

flag{This's_why_PCBC_is_not_living}

```

## DDH_Game

+ 双线性对
+ 匹配友好曲线

### 双线性对

#### 定义
设$G_1、G_2、G_3$分别是三个$n$阶循环群，一个双线性对(双线性映射)是一个从$G_1 \times G_2 \to G_3$的双线性映射，满足：
+ 双线性性：$(ag_1,bg_2)=ab(g_1,g_2)$，其中$g_1\in G_1,g_2\in G_2$
+ 非退化性：$\exist g_1,g_2$，$st.$$g_1,g_2$ 不为$G_3$中的单位元
+ 可计算性：存在有效的多项式时间算法计算双线性对的值

常见的内积运算就是双线性性映射

##### 椭圆曲线上的双线性对

设$g_1,g_2$分别是群$G_1$和$G_2$的元素，映射$\phi:G_1\times G_2\to G_3$是双线性映射，那么有
+ $(ag_1,bg_2)=ab(g_1,g_2)=(abg_1,g_2)=(g_1,abg_2)$
+ $(ag_1,bg_2)+(cg_1,dg_2)=(ab+cd)(g_1,g_2)$

更一般的写成乘法群的形式
+ $e(g_1^a,g_2^b)=e(g_1,g_2)^{ab}=e(g_1^{ab},g_2)=e(g_1,g_2^{ab})$
+ $e(g_1^a,g_2^b)e(g_1^{c},g_2^d)=e(g_1,g_2)^{ab+cd}$
##### 应用
+ 三方一轮密钥交换
+ SM9数字签名算法

### 配对友好曲线

目前主流的配对友好线有
+ BLS12
+ BN
+ MNT4
+ MNT6
+ Cocks-Pinch (Tate pairing)

### problem

``` python
from secret import flag
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import getRandomRange

assert flag.startswith(b'CatCTF{')
assert flag.endswith(b'}')

# BLS-12-381 but with my own G!
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
a = K(0x00)
b = K(0x04)
E = EllipticCurve(K, (a, b))
E.set_order(0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001 * 0x396C8C005555E1568C00AAAB0000AAAB)

G = E(3745324820672390389968901155878445437664963280229755729082200523555105705468830220374025474630687037635107257976475, 2578846078515277795052385204310204126349387494123866919108681393764788346607753607675088305233984015170544920715533)
n = G.order()

# Embedding degree of this curve
k = 12

m = Integer(bytes_to_long(flag[7:-1]))
sols = m.bits()

DDH_instances = []

for i in range(len(sols)):
    a = getRandomRange(1, n)
    b = getRandomRange(1, n)
    c = 0
    if sols[i] == True:
        c = a * b % n
    elif sols[i] == False:
        c = getRandomRange(1, n)
        assert a*b*G != c*G
    
    ins = ((a*G).xy(), (b*G).xy(), (c*G).xy())
    DDH_instances.append(ins)

with open('DDH_instances.txt', 'w') as f:
    f.write(str(DDH_instances))
```

### Solve
根据题目，可以发现我们只要判断$c$是否等于$ab\%n$即可，但题目只给了他们和$G$相乘得到的坐标。这是我一开始分析得到的，后面就不知道如何判断了。后面看了wp学习了双线性对才略有理解，而且题目也提示了BLS配对曲线

``` python
# sagemath 9.5
from Crypto.Util.number import long_to_bytes

# Before running, modify your filename and add "DDH_instances = " at the beginning of the file.
DDH_instances=[]
# curve
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
a = K(0x00)
b = K(0x04)
E = EllipticCurve(K, (a, b))
# G = E(0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB, 0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1)
E.set_order(0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001 * 0x396C8C005555E1568C00AAAB0000AAAB)

G = E(3745324820672390389968901155878445437664963280229755729082200523555105705468830220374025474630687037635107257976475, 2578846078515277795052385204310204126349387494123866919108681393764788346607753607675088305233984015170544920715533)
n = G.order()

# Embedding degree of the curve
k = 12


def solve_ECDDHP(DDH_instances, G, Ep, m, n):
    """
    Parameters:
        DDH_instances - list consists of (aG, bG, cG), where aG, bG, cG are EC_point.xy()
        m - embedding degree of <G>
        n - G's order. 
    """
    sols = []
    
    Fpm.<x> = GF(p^m)
    Epm = Ep.base_extend(Fpm) 
    
    G = Epm(G)
    
    for ins in DDH_instances:
        aG, bG, cG = ins
        aG = Epm(aG); bG = Epm(bG); cG = Epm(cG)
        
        # e_aG_bG = aG.weil_pairing(bG, n)
        e_aG_bG = aG.tate_pairing(bG, n, m)
        
        e_G_cG = G.tate_pairing(cG, n, m)
        if e_aG_bG == e_G_cG:
            sols.append(True)
        else:
            sols.append(False)
    
    return sols

sols = solve_ECDDHP(DDH_instances, G, E, k, n)
# print(sols)

pt = 0
for i in range(len(sols)):
    pt += sols[i] * (2^i)

flag = long_to_bytes(pt)
print(flag)
print(b'CatCTF{' + flag + '}')
```

# Reverse

逆向这次就看了关于llvm-ir这道题，用llvm-as将文件编译成`.bc`文件后再得到`.o`文件就可以不能分析IR代码了，但没发现被加了混淆，分析了半天后放弃了。赛后看了wp发现有D810这个强大的插件可以去掉ollvm的控制流平坦化混淆，太神奇了，学习了。

## ReadingSection

先使用llvm-15及以上的版本获得
``` shell
llvm-as task.ll -o task.bc
clang -c -o task.o task.bc
```
然后安装D810插件，在IDA中用ollvm去混淆得到`task.o`原来的代码，发现就是一个异或加密和TEA加密。

TEA加密
``` c
#include <stdint.h>

void encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1],  i;  /* set up */
    uint32_t delta=0x9e3779b9; /* a key schedule constant */
    uint32_t sum=delta*32;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
```

注意，题目在用TEA加密时是每$4$个字节一起加密的，而判断的时候拆成了$1$个字节判断。我们从IDA导出的数据也是$1$个字节，注意转化为$4$字节的。这里可以用一个联合体来转换，然后使用`reinterpret_cast`函数来转换指针，这种转换保证不会改变数据每一位的信息，而转换到另一种类型。但使用`static_cast`等转换不行。这也是看wp学习的，否则只能自己手动组装$4$字节了

``` cpp
#include <cstdio>
#include <stdlib.h>
#include <iostream>
#include <windows.h>
union data{
	unsigned char enc[32];
	unsigned int  data[8];
};
unsigned char chiper[32] ={
  0xAA, 0x7D, 0x07, 0x7D, 0xB1, 0xF7, 0x80, 0x71, 0xDA, 0xAF, 
  0x23, 0xE5, 0x10, 0x07, 0x58, 0x57, 0x1E, 0xF7, 0x7D, 0x71, 
  0xE6, 0x78, 0x74, 0x56, 0x9B, 0xC0, 0x53, 0x11, 0xF3, 0x39, 
  0x31, 0x2E
};
unsigned int key[4]={
	0x18BC8A17,0x29D3CE1E,0x42F740E3,0x199C7F4A
};
void decrypt (unsigned int* v, unsigned int* k) {
    unsigned int v0=v[0], v1=v[1],  i;  /* set up */
    unsigned int delta=0xCA7C7F00;                     /* a key schedule constant */
    unsigned int k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    unsigned int sum=delta*28;
    for (i=0; i<28; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

int main(){
	for(int i=0;i<4;i++)
	 decrypt(&reinterpret_cast<union data*>(chiper)->data[2*i],key);
	for(int i=0;i<32;i++)
	 printf("0x%02X ",chiper[i]);
	for(int i=30;i>=0;i--)
		chiper[i]^=chiper[i+1];
	for(int i=0;i<32;i++)
		printf("%c",chiper[i]);
}
```
