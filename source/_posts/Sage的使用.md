---
title: Sage的使用
date: 2022-09-03 23:27:57
tags: 
math: true
---

# Sage相关库的使用

## 基本环和域

``` python
ZZ  #整数环
QQ  #有理数环
RR  #实数域
CC  #复数域

F.<x>=PolyomialRing(ZZ)  #定义在整数环上的多项式环，多项式的变量定义为x
P.<x, y> = PolynomialRing(Zmod(p)) #多变量
# F是多项式环的名字，自定义
# x是多项式环变量的名字，自定义



G=GF(p) # 定义伽罗瓦域，阶是p，并且p要是一个素数或者一个素数的幂次
x=G(5) #定义在有限域GF(p)上的数5，可以把G看做一个类型
ZN=Zmod(N) #一般有限环

#后续使用时，如果我们想要一个元素x在某个环或域上计算，直接ZZ(x),QQ(x),ZN(X)这样

x, y = var('x, y') #定义形式变量，可以利用这个来得到带变量的方程

```

## 数论基本函数

``` python
d=gcd(a,b) #求a,b的gcd
lcm(a,b ) #求a,b的lcm

d,u,v=xgcd(a,b) #扩展欧几里得，返回三个参数，满足 au+bv=d ,gcd(a,b)=d

y=inverse_mod(x,p) #返回x在模p下的逆元y

p=random_prime(a,b) #返回[a,b)之间的随机素数

is_prime(p) #判断是否是素数

nth_prime(n) #返回第n个素数

next_prime(p) #素数p的下一个素数

pow(x,y,p) #计算x^y mod p

euler_phi(n) #计算欧拉函数

crt([a1,a2,...,an],[m1,m2,...,m3]) #中国剩余定义，其中 x=ai mod mi

factorial(x) #求x的阶乘

factor(x) #素数分解

euler_phi(n) #n的欧拉函数
binomial(n,m) #组合数
moebius(n)  #莫比乌斯函数
Partitions(n).list() #n的正整数划分
divisors(x) #返回一个列表，包含x的所有因子
prime_divisors #返回一个列表，包含x的所有素因子

#有限域开根，比如整数域上开根
ZZ(7^64).nth_root(64) #得到7
ZN(x).nth_root(y,all=True) #得到所有满足 x=z^y mod N 的z

```

## 线性代数

``` python
A=Matrix(ZZ,[[1,2,3],[1,2,3],[1,2,3]]) #声明一个在ZZ上的三行三列的矩阵A
A=matrix(Zmod(7),[[1,2,3],[1,2,3],[1,2,3]]) #声明一个在Zmod(7)上的三行三列的矩阵A
A=matrix(Zmod(7),n,m) #定义在Zmod(7)上大小为nxm的矩阵，并且初始值均为0
I=matrix.identity(n) #大小为nxn的单位矩阵
# Matrix 和 matrix 一样
print(A[i,j]) #取A第i行第j列的元素
A.T #A的矩阵转置
A^(-1) #A的逆矩阵
A.rank() #A的秩
A.nrows() #将返回矩阵行数
A.ncols() #将返回矩阵列数
A.det() #A的特征值
A.eigenvalues() #特征值
M.eigenvectors_right() #特诊向量
A+B #矩阵加法
A*B #矩阵乘法

M=block_matrix([[A,B],[C,D]]) #定义分块矩阵，其中A,B,C,D都是在一个环或域上的矩阵

v=vector(Zmod(7),[1,2,3,4,5,6,7,8,9]) #声明一个在Zmod(7)上的向量
print(v[i]) #去v的第i个元素

X=A.solve_right(B) #解线性方程组 形如 AX=B ,X在右边
X=A.solve_left(B)  #XA=B，X在左边

#矩阵空间 Matrix spaces
M = MatrixSpace(QQ,n,m) #定义在有理数域上的nxm维矩阵空间
B = M.basis()
```

## 多项式相关

``` python
R = PolynomialRing(QQ, 't') #定义在有理数域上的多项式环，且变量为t
R.<t> = PolynomialRing(QQ)
t=R.0 #R.0就是这个多项式环上的未知量

#多变量定义
PolynomialRing(GF(5), 3, 'xyz')
z = GF(5)['z0, z1, z2'].gens() #z=(z0, z1, z2)

R, (x, y) = PolynomialRing(RationalField(), 2, 'xy').objgens()
f = (x^3 + 2*y^2*x)^2
g = x^2*y^2
f.gcd(g) #求公因式
```

## 有限域和阿贝尔群

``` python
G = PermutationGroup(['(1,2,3)(4,5)', '(3,4)']) #置换群
G.order() #阶
G.center() #生成元

```



## 格相关函数

``` python
lattice = IntegerLattice(A, lll_reduce=True) #定义一个格，其中A是一个内积空间矩阵，并且自动计算lll_reduce(格规约)

M.LLL() # LLL算法

#Babai算法：需要手动实现，一般如下
#输入格的基basis 和目标向量v 
def approximate_closest_vector(basis, v):
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
```

## 椭圆曲线

``` python
#y^2=x^3=ax+b
E = EllipticCurve(Zmod(N), [a, b])
E.lift_x(x_cord) #得到三元组
```



