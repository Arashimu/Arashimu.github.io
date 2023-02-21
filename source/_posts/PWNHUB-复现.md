---
title: PWNHUB-复现
date: 2022-12-26 23:13:08
tags:
---

## Crypto

### ASR

problem
``` python
from gmpy2 import *
from Crypto.Util.number import *
from secret import flag
m = bytes_to_long(flag)

R = getPrime(256)
S = getPrime(512)
A = getPrime(1024)

N = R * S * A
c = pow(m, 0x10001, N)

RA = R & A
print('RSA1',hex(RA * S))
print('RSA2',hex(RA | S))

print('c', hex(c))
print('N',hex(N))

#RSA1
#RSA2
#c
#N
```

$RA=R\&A$可以推出$RA$只有低$256$位有效，因此通过$RSA2=RA|S$可以直接得到$S$的高$256$位即$RSA2$的高$256$位。之后可以根据$RSA1$和$RSA2$利用剪枝暴力求$S$。但发现这样复杂度有点高，最坏到达$O(2^{256})$。

当然也可以使用高位攻击来求，如下，参考官方wp
``` python
offset=256
RSA2>>=offset
RSA2<<=offset
PR.<x>=PolynomialRing(Zmod(RSA1))
f=x+RSA2
roots=f.small_roots(X=2^offset,beta=0.4)
S=RSA2+roots[0]
S=int(S)
```

但发现$R、S、A$都是素数，并且$RA\le R\lt S\lt A$，所以$RA$必然互素于$R、S、A$，所以$\gcd(N,RSA1)=S$，直接求即可。

下一步思路就是求$R$和$A$了，但只通过$R\&A$和$R\times A$这两个条件不可能求出来，所以换个方向考虑。这个也是我比赛时没有想到的，一直在纠结如何求$R$和$A$。考虑到$m$一般只有$300$位，所以$m$是小于$S$的，所以我们可以将模$N$转换位模$S$，这样$m$还是可以求出来的，只要把$c$规约到$S$的域下即可，即$c\%S$，然后求$ed\equiv1\mod{S-1}$即可。

exp
``` python
import gmpy2
import sympy
import math
from Crypto.Util.number import *
RSA1=
RSA2=
c=
e=
N=
S=GCD(RSA1,N)
d=gmpy2.invert(e,S-1)
m=pow(c,d,S)
print(long_to_bytes(m))
#flag{b66f68258f184bd7afddd32c1518eed0}
```

## 大杂烩
知识点
+ 椭圆曲线密码
+ 格
+ 已知$e$和$d$求$p$、$q$


problem
``` python
from Crypto.Util.number import *
from gmpy2 import *
from random import *

padding = lambda num, bit_len: (num << (512 - bit_len)) + getrandbits(512 - bit_len)

flag = b'**************************************'
m1, m2 = bytes_to_long(flag[:19]), bytes_to_long(flag[19:])
p = next_prime(padding(m1, m1.bit_length()))
q = next_prime(padding(m2, m2.bit_length()))
n = p * q
e = getPrime(128)
d = inverse(e, (p - 1) * (q-1))
a, b = e & 0x3ffffffffff, e >> 42 # a是e的低42位
N = getPrime(128)
E = EllipticCurve(Zmod(N), [a, b])
NN = getPrime(1024)
S = inverse(getPrime(128), NN) * inverse(getPrime(128), NN)   
d1 = d >> 512          
d2 = d & (1 << 512) - 1 #d的低512位
enc1 = S * d1 % NN
enc2 = S * d2 % NN

print('n =', n)
print('a =', a)
print('N =', N)
print('POINT =', E.lift_x(996))
print('enc1 =', enc1)
print('enc2 =', enc2)
print('NN =', NN)
```

需要求$m1$和$m2$，根据题目只有$p$和$q$与$m1$、$m2$有关，题目给出了$e$、$d$的相关信息，所以最后要根据$e$、$d$求$p$、$q$。

$a$是$e$的第$42$位，$b$是$e$的高$86$位，和$a$、$b$有关的信息是将$a$、$b$用作了椭圆曲线函数的参数，即$y^2=x^3+ax+b$，而题目也给出了该曲线上的一点$POINT$，并且给出了$a$，那么只需要带入方程在有限域$\mathbb{Z}_N$上求$b$即可
``` python
from Crypto.Util.number import *

a = 1755716071599
N = 236038564943567983056828121309828109017
POINT = (996 ,151729833458737979764886336489671975339 )
x,y=POINT
b=(pow(y,2,N)-(pow(x,3,N)+a*x)%N)%N
print(b)
e=(b<<42)+a
print(e)
```
之后求$d$，和$d$有关的条件是$enc1\equiv S\times d1\mod{NN}$、$enc2\equiv S\times d2\mod{NN}$。我的思路是由于$S$都是随机得到的，所以求$S$的意义不大，所以考虑先把$S$消掉，得到等式$enc1\times enc2^{-1}\equiv d1\times d2^{-1}\mod{N}$，那么这个形式很像之前我在格的学习例题中做过的一道题的形式$h\equiv fg^{-1}\mod{q}$，构造格$\left[\begin{matrix} 1 & enc1\times enc2^{-1}\\0 & NN\end{matrix}\right]$，然后用高斯求即可。
``` python
NN=
enc1=Zmod(NN)()
enc2=Zmod(NN)()
h=enc1/enc2
def Guass(v1,v2):
    while True:
        if v2.norm()<v1.norm():
            v1,v2=v2,v1
        m=round(v1*v2/v1.norm()^2)
        if m==0:
            return (v1,v2)
        v2=v2-m*v1
v1,v2=vector([1,H]),vector([0,NN])
V=Guass(v1,v2)
print(V)
d1=V[0][1]
d2=V[0][0]
d=(d1<<512)+d2
print(d)
```
当然也可以构造这样的格$\left[\begin{matrix}NN & 0 &0\\ 0&NN&0\\enc1&enc2&1 \end{matrix}\right]$，然后用$LLL$算法求即可
``` python
v1,v2,v3=vector(ZZ,[NN,0,0]),vector(ZZ,[0,NN,0]),vector(ZZ,[enc1,enc2,1])
m=Matrix([v1,v2,v3])
print(m.LLL()[0])
```

求出$e$、$d$后就是求$p$和$q$了，一开始我尝试使用二次函数形式来求解，就是$N=pq$，$\phi(N)=(p-1)(q-1)=pq-(p+q)+1=N-(p+q)+1$，进一步得到$p+q=N-\phi(N)+1$，然后把$p$、$q$看作二次函数的两个根，根据韦达定义得，$y=x^2-(N-\phi(N)+1)x+N=(x-p)(x-q)$，但得到得结果一直不对，后来参考了wp，发现可以使用一个算法
``` python
from random import *
from Crypto.Util.number import *
import gmpy2
def divide_pq(ed,n):
    k=ed-1
    while True:
        g=randint(3,n-2)
        t=k
        while True:
            if t%2 != 0:
                break
            t//=2
            x=pow(g,t,n)
            if x>1 and gcd(x-1,n)>1:
                p=gcd(x-1,n)
                return (p,n//p)

e=
d=
n=
#print(divide_pq(e*d,n))
p,q=divide_pq(e*d,n)
for i in range(100):
    print(long_to_bytes(p>>i))
    print(long_to_bytes(q>>i))
```

## PPC

### task1
简单的模拟
``` python
import base64

n=int(input().strip())


def wir(ctx,t):
	m=(len(ctx)+16-1)//16
	for i in range(m):
		if t==1:
			print("        ",end="")
		print(hex(i*16)[2:].zfill(8),end="  ")
		for j in range(16):
			if i*16+j<len(ctx):
				print(hex(ctx[i*16+j])[2:].zfill(2),end="")
			else:
				print("  ",end="")
			if j==7 :
				print(end="  ")
			elif j==15:
				print(end="   ")
			else:
				print(end=" ")
		for j in range(16):
			if i*16+j<len(ctx):
				if ctx[i*16+j]>=32 and ctx[i*16+j]<=126:
					print(chr(ctx[i*16+j]),end="")
				else:
					print(".",end="")
				if j==7:
					print(" ",end="")
			else:
				print(" ",end="")
				if j==7:
					print(" ",end="")
		print()

for i in range(n):
	d,s=input().strip().split()
	d=int(d)
	ctx=list(base64.b64decode(s))
	wir(ctx,d)
```

### task3(二分、贪心)

题意：勇者有$HP$点生命值，有$n$个怪兽，每个怪兽的攻击力为$attack_i$，生命值为$hp_i$，每秒勇者可以选择攻击一个怪兽，这个被选择的怪兽此时不嫩攻击勇者，而其他怪兽则可以攻击勇者，请确定勇者的攻击力使得勇者可以在最短时间内击杀所以怪兽

思路：二分攻击力，检查的时候判断贪心的先攻击可能会对勇者造成伤害最高的怪兽，怎么判断，很经典的一个问题，参考国王的游戏这道题目，考虑邻项交换来证明即可。
``` cpp
#include <bits/stdc++.h>
using namespace std;
int n,h;
struct smile{
	int sa,sh,cnt;
	bool operator < (const smile&t)const{
		return t.sa*cnt>sa*t.cnt;
	}
};
smile s[1005];

int check(int x){
	int attack=0;
	for(int i=0;i<n;i++){
		s[i].cnt=(s[i].sh+x-1)/x;
		attack+=s[i].sa;
	}
	sort(s,s+n);
	int bh=h;
	//int res=0,time=0;
	for(int i=0;i<n;i++){
		attack-=s[i].sa;
		bh-=attack*s[i].cnt;
		if(bh<=0) return 0;
	}
	return 1;
}
int main(){
	scanf("%d%d",&n,&h);
	for(int i=0;i<n;i++){
		scanf("%d%d",&s[i].sa,&s[i].sh);
	}
	int l=1,r=1000;
	int ans=-1;
	while(l<=r){
		int mid=(l+r)>>1;
		if(check(mid)) ans=mid,r=mid-1;
		else l=mid+1;
	}
	printf("%d\n",ans);
	return 0;
}
```
