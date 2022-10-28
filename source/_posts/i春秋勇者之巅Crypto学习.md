---
title: i春秋勇者之巅Crypto学习
date: 2022-09-03 11:23:21
tags: Crypto
math: true
---

## bob_enc

### 知识点

- 格密码难题 CVP
- 域上解线性方程组

### Problem

```python
from secret import *
import random

prime =  2141
print len(flag)
flag = map(ord,flag)
flag1 = flag[:21] #前21个
flag2 = flag[21:] #后面部分
row = 64

def add(msg1,msg2):
    return [(x+y)%prime for x,y in zip(msg1,msg2)]

def multi(msg1,msg2):
    out = []
    for l in msg1:
        s = 0
        for x,y in zip(l,msg2):
            s += (x*y)%prime
            s %= prime
        out.append(s)
    return out
def genkey(leng):
    l = [[] for i in range(row)]
    for x in range(row):
        for i in range(leng):
            l[x].append(random.randint(0,511))
    return l

key = genkey(len(flag1))#64组长度为len(flag1)的(0,511)之间的随机数
print key

cipher1 = multi(key,flag1)

print cipher1

cipher2 = multi(key,flag2)

noise = [random.randint(0,6) for i in range(row)]
print add(noise,cipher2)
```

### Solve

已知`key`、`cipher1`和`cipher2`

根据题目，发现`key`是根据`flag1`生成的一个$64\times 21​$大小的矩阵，记作$K​$。

将`flag1`看做一个$21\times 1$的列向量$X_1$，那么`cipher1`就是$KX_1$两个矩阵的乘积，得到一个$64 \times 1$的列向量$A$)

那么解`flag1`就是解方程组$KX_1=A$，得到$X_1$即可

```python
key=[]
chiper1=[]
prime=2141
B=Martix(Zmod(prime),chiper1) #定义一个prime域上的1x24的矩阵
K=Matrix(Zmod(prime),key)
B=B.T #转换为64x1
flag1=''
X1=K.solve_right(B)
for i in range(0,21):
    flag1+=chr(X1[i,0])
print(flag1)
#flag1=flag{14e6f236-9eb9-46
```

`chiper2`基本上和`chiper1`的处理过程是一样的，不过在得到`chiper2`的列向量后，对列向量每个元素加入了一定的噪音。即每个元素在原来的基础上偏移了一点点，所以我们需要在给定的加了噪音的向量的基础上，还原出原来的列向量，并且这个加了噪音的列向量和原来的列向量之间的距离要尽可能小。这就变成了$\text{Lattic}$中的$\text{CVP}$问题。

具体地，记加了噪音后的列向量为$B^{'}$，原来的列向量为$B$，`flag2`记作$X_2$，则$KX_2=B$，$B\rightarrow B^{'}$。

然后这类问题也叫做$\text{LWE}$容错学习问题，具体就是给一个矩阵$A_{n\times m}$，一个向量$X_{m\times 1}$和一个噪音向量$E_{n\times 1}$，$\text{LWE}$系统输出$B=AX+E$，现在给出$B,A,E$，要求还原$X$

这类问题构造格的形式是

$$
A \quad E\\
B \quad 0
$$

而在本题中构造一个单位矩阵$ pI\_{64\times64}$作为基向量，那么格的矩阵就是

$$
\left[
\begin{matrix}
pI\\
K^T
\end{matrix}
\right]
\tag{3}
$$

然后求这个矩阵的格规约基，再用格规约基和$\text{Babai}$算法从$B^{'}$得到$B$

```python
from sage.modules.free_module_integer import IntegerLattice
key = []
chiper2 =[]
chiper1=[]
p=2141
A=Matrix(Zmod(p),chiper1)
A=A.T
K=Matrix(Zmod(p),key)
X1=K.solve_right(A)
flag1=''
for i in range(0,21):
    flag1+=chr(X1[i,0])
print(flag1)
#flag{14e6f236-9eb9-46

def Babai_closest_vector(basis, v):
    """Returns an approximate CVP solution using Babai's nearest plane algorithm.
    """
    BL = basis.LLL()
    # 施密特正交化基
    G, _ = BL.gram_schmidt()
    _, n = BL.dimensions()
    small = vector(ZZ, v)
    for i in reversed(range(n)):
        c = QQ(small * G[i]) / QQ(G[i] * G[i])
        c = c.round()
        small -= BL[i] * c
    return (v - small).coefficients()
base=matrix.identity(64)*p
KK=Matrix(ZZ,key)
KK=KK.T
C=block_matrix([[base],[KK]])
print(C.nrows())
lattice = IntegerLattice(C, lll_reduce=True)
print("LLL done")
BB=vector(ZZ,chiper2)
B = Babai_closest_vector(lattice.reduced_basis,BB)
print("Closest Vector: {}".format(B))
X2=K.solve_right(B)
print("X2: {}".format(X2))
flag2=''
for i in range(len(X2)):
    flag2+=chr(X2[i])
print(flag2)
#fc-b636-4c54c3732e5f

#flag{14e6f236-9eb9-46fc-b636-4c54c3732e5f
```

## notKnapsack

### 知识点

- 群换阶
- 离散对数
- 同余方程组

### Problem

```python
 #!/usr/bin/python3
# -*- coding: utf-8 -*-
import random

from Crypto.Util.number import bytes_to_long
from secret import FLAG

assert FLAG.startswith(b'flag{') and FLAG.endswith(b'}')

q = 210767327475911131359308665806489575328083

#bin() 返回一个整数 int 或者长整数 long int 的二进制表示
#bytes_to_long(ab)=24930  发现 97 * 2^8 + 98 = 24930
flag_bin = bin(bytes_to_long(FLAG[5:-1]))[2:]
l = len(flag_bin)

n = random.randint(l, 2*l)
cipher = []
for _ in range(n):
    r = [random.randint(2, q-2) for _ in range(l)]
    s = 1
    for i in range(l):
        s = s * r[i] ** int(flag_bin[i]) % q
    cipher.append([r, s])

with open('output.txt', 'w') as f:
    f.write(str(cipher))
```

### Solve

记`flag`的第$i$位是$m_i$且长度为$len$，则会生成$n$组同余方程，第$i$组是

$$
s_i=\prod_{j=1}^{len}r_{ij}^{m_j}\mod{q}\\
m_j\in \left\{0,1\right\}
$$

由于连乘不好处理，考虑利用对数的形式，把上式变成和式的形式。这里就用到了离散对数的知识

离散对数问题：当模$m$有原根的时候，设$l$为模$m$的一个原根，即$l^{\phi(m)}\equiv 1\mod{m}$，则当$x\equiv l^k\mod(m)$时：

$$
\text{Ind}_l x\equiv k\mod(\phi(m))
$$

此处的$\text{Ind}_lx​$为$x​$以整数$l​$为底，模$\phi(m)​$时的离散对数值

常见的性质有

$$
\text{Ind}_lxy\equiv \text{Ind}_lx+\text{Ind}_ly\mod{\phi(m)}\\
\text{Ind}_lx^y\equiv y\text{Ind}_lx\mod{\phi(m)}
$$

注意到，这是一个在有限域$\mathbb{Z}_q​$上的运算，那么这个域的阶是$q​$，并且如果我们把最后利用离散对数，就转换到$\phi(q)=q-1​$下的有限域$\mathbb{Z}_{q-1}​$下的运算。

假设$g$是$\mathbb{Z}_{q}$的一个生成元，则原式可以表示为

$$
g^{b_i}\equiv g^{\sum_{j=1}^{len}a_{ij}m_j\mod{\phi(q)}}\mod{q}\\
g^{b_i}\equiv s_i \mod{q}, \quad g^{a_{ij}m_j}\equiv r_{ij} \mod{q}\\
b_i\equiv \sum_{j=1}^{len}a_{ij}m_j\mod{q-1}\\
B\equiv AX \mod{q-1}
$$

考虑将$q - 1$分解，得到$q-1=2 \times331\times318379648755152766403789525387446488411$，因为$X$中元素的取值只有$0$和$1$，所以我们考虑直接取$\mod{2}$来运算，实际上如果$a\equiv b\mod{pq}$，那么$a-b=kpq$，两边同时模$p$可以得到$a\equiv b\mod{p}$，所以$B\equiv AX \mod{q-1}$可以得到 $B\equiv AX \mod{2}$

域包含群的性质，如果从群即$\mathbb{Z}_{q-1}​$上的乘法群方面考虑，假设这个群的生成元是$g​$，$|g|=q-1​$，则这个群中其他的元素$x​$，假设$x=g^p​$，则有

$$
|x|=|g^p|=\frac{q-1}{\gcd(p,q-1)}
$$

那么如果两边同时乘$\frac{q-1}{2}​$，那么这个群就可以转化为阶为$2​$的子群$<g^{\frac{q-1}{2}}> ​$，因为$\frac{q-1}{\gcd(\frac{q-1}{2},q-1)}=2​$。

那么方程两边同时乘以$\frac{q-1}{2}​$后取离散对数就变成了求解线性方程组的问题，令$\frac{q-1}{2}=t​$，则方程变为

$$
\text{Ind}_{g^t}s_i\equiv \sum_{j=1}^{len}m_i\text{Ind}_{g^t}r_{ij} \mod{2}
$$

$\text{Ind}_{g^t}s_i​$和$\text{Ind}_{g^t}r_{ij}​$可以利用勒让德符号求出

计算$\left(\frac{a}{p}\right)$有一个简单的公式

$$
\left(\frac{a}{p}\right)\equiv a^{\frac{p-1}{2}}\mod{p}
$$

```python
from Crypto.Util.number import *
def legendre(a,p):
    if pow(a,(p-1)//2,p)==1:
        return 1
    else:
        return 0

f=open('output.txt','rb')
q = 210767327475911131359308665806489575328083
out=eval(f.read())

A=Matrix(GF(2),len(out))
v=vector(GF(2),len(out))
for i in range(len(out)):
    r,s=out[i]
    for j in range(len(r)):
        A[i,j]=legendre(r[j],q)
        v[i]=legendre(s,q)+1

x=A.solve_right(v)
x=''.join(map(str,x))
print(long_to_bytes(int(x,2)))

# flag{4cc78358-ce69-4539-a33a-2c44433414ab}
```

感谢[ToverPomelo](https://github.com/ToverPomelo)的解答
