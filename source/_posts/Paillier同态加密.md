---
title: Paillier同态加密
date: 2022-09-29 15:38:20
tags: 密码学
math: true
---

## 同态加密(Homomorphic Encryption)

### 概念

是一种加密方式，用于在不使用密钥的情况下对加密数据进行计算，这种计算的结果仍然是加密的。拥有密钥的用户对经过同态加密处理过的加密数据进行解密后，得到的结果还是正确的原文信息。

### 分类

+ 半同态加密(Partially Homomorphic Encryption（PHE))：只支持加法或乘法中的一种运算
+ 部分同态加密(Somewhat Homomorphic Encryption (SHE))：支持同时进行加法和乘法运算，但运算次数有限制
+ 全同态加密(Fully Homomorphic Encryption (FHE))：支持任意次数的加法和乘法运算

## Paillier半同态加密方案

### 介绍

Paillier是一个支持加法同态的公钥密码系统

### Key Generation

1. 随机选择两个独立的大素数$p$和$q$，满足$\gcd(pq,(p-1),(q-1))=1$并且$p$和$q$长度相同
2. 计算$n=pq$和$\lambda=\text{lcm}(p-1,q-1)$
3. 选择一个随机的整数$g\in \mathbb{Z}_{n^2}^{*}$，且满足$g$的阶是$n$的非零倍数，一般取$n+1$
4. 定义函数$L(x)=\frac{x-1}{n}$，然后计算$\mu \equiv (L(g^{\lambda}\mod{n^2}))^{-1}\mod{n}$

公钥$(n,g)​$，私钥$(\lambda,\mu)​$

### Encryption

1. 假设$m$是要加密的消息，并且满足$0\le m\lt n$
2. 选择一个随机的整数$r​$，满足$0\lt r\lt n​$
3. 计算$c\equiv g^mr^n\mod{n}$

### Decryption

1. 让$c$是加密后的密文，$c\in \mathbb{Z}_{n^2}^{*}$
2. 计算$m\equiv L(c^{\lambda}\mod{n^2})\mu\equiv \frac{L(c^{\lambda}\mod{n^2})}{L(g^{\lambda}\mod{n^2})}\mod{n}$

解密具体推导过程

前置知识：

+ $(1+n)^x\equiv 1+nx \mod{n^2}$，将$(1+n)^x$用二项式展开即可证明

  + 令$y\equiv (1+n)^x\mod{n^2}$，可以化简为$x\equiv \frac{y-1}{n}\mod{n} $
  + 令$L(u)=\frac{u-1}{n}​$，则$L((1+n)^x\mod{n^2})\equiv L(y)\equiv \frac{y-1}{n}\equiv \frac{nx+1-1}{n}\equiv x\mod{n}​$
  + 因此$L((1+n)^x\mod{n^2})\equiv x\mod{n}​$

+ 卡麦尔函数($\text{Carmichael}​$函数)

  + 定义：使得$x^m\equiv 1\mod{n}​$成立的最小正整数$m​$，其中$(x,n)=1​$，将$m​$记作$\lambda(n)​$

  + 计算$\lambda(n)$：将$n$算术分解得到$n=\prod_{i=1}^kp_i^{r_i}$，则
    $$
    \lambda(n)=\text{lcm}(\lambda(p_1^{r_1}),\lambda(p_2^{r_2}),\cdots,\lambda(p_k^{r_k}))\\
    
    \lambda(p^r)=
    \begin{cases}
    \phi(p^r)\quad \ \ \ p^r=2\or p^r=4\or p\gt 2\\
    \frac{\phi(p^r)}{2} \quad \ \ \ \ p=2\and r\gt 2
    \end{cases}
    \tag{1}
    $$

  + 令$n=pq$，则$\lambda(n)=\text{lcm}(\lambda(p),\lambda(q))=\text{lcm}(\phi(p),\phi(q))=\text{lcm}(p-1,q-1)$

    在数域$\mathbb{Z}_{n^2}^{*}$中，$|\mathbb{Z}_{n^2}^{*}|=\phi(n^2)$，对于$\forall w\in \mathbb{Z}_{n^2}^{*}$，有
    $$
    \begin{cases}
    w^{\lambda}\equiv 1\mod{n}\\
    w^{n\lambda}\equiv 1\mod{n^2}
    \end{cases}
    \tag{1}
    $$

+ 解密推导
  $$
  c^{\lambda}\equiv g^{m\lambda}r^{n\lambda}\equiv g^{m\lambda}\equiv 1+nm\lambda\mod{n^2}\\
  g^{\lambda}\equiv (1+n)^{\lambda}\equiv 1+n\lambda \mod{n^2}\\
  L(c^{\lambda}\mod{n^2})\equiv m\lambda \mod{n}\\
  L(g^{\lambda}\mod{n^2})\equiv \lambda\mod{n}\\
  m\equiv \frac{L(c^{\lambda}\mod{n^2})}{L(g^{\lambda}\mod{n^2})}\mod{n}
  $$
  

  

### 同态运算

+ 明文同态加
  $$
  D(E(m_1,r_1)\cdot E(m_2,r_2)\mod{n^2})\equiv m_1+m_2\mod{n}\\
  D(E(m_1,r_1)\cdot g^{m_2}\mod{n^2})\equiv m_1+m_2\mod{n}
  $$

+ 明文同态乘
  $$
  D(E(m_1,r_1)^{m_2}\mod{n^2})\equiv m_1m_2\mod{n}\\
  D(E(m_2,r_2)^{m_1}\mod{n^2})\equiv m_1m_2\mod{n}\\
  D(E(m_1,r_1)^k\mod{n^2})\equiv km_1\mod {n}
  $$
  

## ByteCTF2022_Compare

### Problem

``` python
from Crypto.Util.number import getPrime, getRandomNBitInteger, inverse
from fractions import Fraction
from gmpy2 import lcm
import re

N = 512
safe_expr = re.compile(r'^([-+*/0-9.~%^&()=|<>]|and|or|not|MSG)+$')


def encode(m, n, g):
    r = getRandomNBitInteger(N)
    c = pow(g, m, n*n) * pow(r, n, n*n) % (n*n)
    return c


def decode(c, n, l, u):
    return int(Fraction(pow(c, l, n * n) - 1, n) * u % n)


def round(expr):
    p = getPrime(N)
    q = getPrime(N)

    n = p * q
    g = getRandomNBitInteger(N)
    print('n =', n)
    print('g =', g)

    a = getRandomNBitInteger(N)
    b = getRandomNBitInteger(N)

    print('a =', encode(a, n, g))
    print('b =', encode(b, n, g))

    msg = int(input("msg = "))

    l = int(lcm(p - 1, q - 1))
    u = inverse(Fraction(pow(g, l, n * n) - 1, n), n)

    return (a > b) is bool(eval(expr, None, {'MSG': decode(msg, n, l, u)}))


def main():
    expr = input('Hello, Give me your expr: ')
    expr = re.sub(r'\s', '', expr)

    if safe_expr.match(expr) is None:
        raise Exception('Hacker?')

    for i in range(100):
        print('Round:', i)
        try:
            assert round(expr)
        except:
            print('You lost.')
            break
    else:
        print('Congratulations!')
        print(open('/flag').read())


if __name__ == '__main__':
    main()

# ByteCTF{ed4dad6f-45a4-41bf-a538-fd5d0754b3df}
```

### Solve

这里讲一下`eval()`的用法，`eval(exp,globals,locals)`用来执行一个字符串表达式即`exp`，并返回表达式的值，`exp`里面的变量可以在`locals`里面用字典来声明并计算

在本题中，`eval`展开就是

```python
eval('MSG < 2**512',None,{'MSG':decode(msg, n, l, u)})
```

先计算出`MSG`的值，然后带入`MSG<2*512`来返回表达式的值

在本题中，可以明显看到就是一个$\text{Paillier}$加密，然而只有见过才知道，然后这里的$a,b$就是$m_1,m_2$，题目每次给出$c_1,c_2$和公钥$(n,g)$，需要用户输入一个`msg`，程序对`msg`解密后带回表达式要和`a>b`同真假

根据同态得到$D(c_1\cdot c_2^{-1}\mod{n^2})\equiv m_1-m_2\mod{n}$

如果$m_1\gt m_2$，那么$m_1-m_2\gt 0$，而$m_1$和$m_2​$一般很接近，所以可以认为这个差值不会太大

而如果$m_1\le m_2$，那么$m_1-m_2\equiv m_1-m_2+n\mod{n}$，注意到$n\le 2^{1024}$，而$|m_1-m_2|$不会太大，所以$m_1-m_2\mod{n}$在这种情况下会很大

所以我们可以选择一个数$x=2^{512}$，如果$D(c_1\cdot c_2\mod{n^2})\lt x$，说明$a\gt b$，反之说明$a\le b$

``` python
from Crypto.Util.number import *
from pwn import *
p=remote('e9ce6445e564ac67295cb28d2c5692b2.2022.capturetheflag.fun',1337, ssl=True)
context.log_level='debug'
p.recvuntil("expr: ")
p.sendline("MSG < 2**512")

for i in range(100):
	p.recvuntil("n = ")
	n=int(p.recvline(False),10)
	p.recvuntil("a = ")
	a=int(p.recvline(False),10)
	p.recvuntil("b = ")
	b=int(p.recvline(False),10)
	msg=a*inverse(b,n**2)%(n**2)
	p.recvuntil("msg = ")
	p.sendline(str(msg))

p.interactive()
#ByteCTF{ed4dad6f-45a4-41bf-a538-fd5d0754b3df}
```















