---
title: BUU_Crypto
date: 2022-09-23 19:50:18
tags: 密码学
math: true
---

## 1.[羊城杯 2020]Power

### Problem

``` python
from Crypto.Util.number import *
import gmpy2
from secret import flag

p = getPrime(512)
q = getPrime(512)
n = p**4*q

e = 0x10001
phi = gmpy2.lcm(p - 1, q - 1)
d = gmpy2.invert(e, phi)
dp = d % (p - 1)
m = bytes_to_long(flag)
c = pow(m, e, n)
print "dp = " + str(dp)
print "c = " + str(c)

y = 449703347709287328982446812318870158230369688625894307953604074502413258045265502496365998383562119915565080518077360839705004058211784369656486678307007348691991136610142919372779782779111507129101110674559235388392082113417306002050124215904803026894400155194275424834577942500150410440057660679460918645357376095613079720172148302097893734034788458122333816759162605888879531594217661921547293164281934920669935417080156833072528358511807757748554348615957977663784762124746554638152693469580761002437793837094101338408017407251986116589240523625340964025531357446706263871843489143068620501020284421781243879675292060268876353250854369189182926055204229002568224846436918153245720514450234433170717311083868591477186061896282790880850797471658321324127334704438430354844770131980049668516350774939625369909869906362174015628078258039638111064842324979997867746404806457329528690722757322373158670827203350590809390932986616805533168714686834174965211242863201076482127152571774960580915318022303418111346406295217571564155573765371519749325922145875128395909112254242027512400564855444101325427710643212690768272048881411988830011985059218048684311349415764441760364762942692722834850287985399559042457470942580456516395188637916303814055777357738894264037988945951468416861647204658893837753361851667573185920779272635885127149348845064478121843462789367112698673780005436144393573832498203659056909233757206537514290993810628872250841862059672570704733990716282248839
g = 2
x = 2019*p**2 + 2020*p**3 + 2021*p**4
c1 = pow(g, x, y)
print "c1 = " + str(c1)

```

### Solve

已知情报

+ 已知`dp,c,c1`
+ $c1\equiv g^x\mod{y}$，$x=2019p^2+2020p^3+2021p^4$
+ $dp\equiv d\mod{p-1}$
+ $ed\equiv 1\mod{(p-1)(q-1)}$
+ $c\equiv m^e\mod{n}$

可以利用`discrete_log()`求出$x$，然后用$z3$求解出$p$

`discrete_log()`用法

``` python
# y = x**p mod n
p=discrete_log(n,y,x)
```

``` python
import sympy
y =
c1 =
g=2
# c1 = g**x mod y  
x=sympy.discrete_log(y,c1,g)
print(x)
x=

from z3 import *
s=Solver()
p=Int('p')
s.add(2019*p**2+2020*p**3+2021*p**4==x)
s.check()
print(s.model())
```

然后推公式
$$
c \equiv m^e \mod{p^4q}\\
c^{dp}\equiv m^{e\times dp}\mod{p^4q}\\
e\times dp\equiv e\times d \equiv 1\mod{(p-1)}\\
c^{dp}\equiv m^{1+k(p-1)}\mod{p}\\
c^{dp}\equiv m\times (m^{p-1})^k\mod{p}\\
c^{dp}\equiv m\times 1\mod{p}\\
$$
所以

``` python
print(long_to_bytes(pow(c,dp,p)))
# GWHT{f372e52f2a0918d92267ff78ff1a9f09}
```



## 2.[GKCTF 2021]Random

### Knowledges

+ 破解伪随机数的生成方式
+ 伪随机数生成算法：梅森旋转算法(mt19937)
+ `randcrack`库的使用

### Problem

``` python
import random
from hashlib import md5

def get_mask():
    file = open("random.txt","w")
    for i in range(104):
        file.write(str(random.getrandbits(32))+"\n")
        file.write(str(random.getrandbits(64))+"\n")
        file.write(str(random.getrandbits(96))+"\n")
    file.close()
get_mask()
flag = md5(str(random.getrandbits(32)).encode()).hexdigest()
```

### Solve

+ MT19937是$623$维$32$比特准确的。$\lfloor \frac{19937}{32} \rfloor=623$

题目给出了$104+104\times2+104\times3=624$组$32$比特的随机数，于是我们就可以根据这$624$个去推出这个生成规律

用`randcrack`库即可

``` python
from hashlib import md5
from randcrack import RandCrack


with open('random.txt','r') as f:
	p=f.readlines()
p=[int(i.strip()) for i in p]
t=[]
#注意，这里要按照从低32位加到高32位，按照生成顺序加
for i in range(len(p)):
	if i%3==0:
		t.append(p[i])
	elif i%3==1:
		t.append(p[i]&(2**32-1))
		t.append(p[i]>>32)
	else:
		t.append(p[i]&(2**32-1))
		t.append((p[i]&(2**64-1))>>32)
		t.append(p[i]>>64)

rc=RandCrack()
for i in t:
	rc.submit(i)
flag = rc.predict_getrandbits(32)
print(md5(str(flag).encode()).hexdigest())
# GCTF{14c71fec812b754b2061a35a4f6d8421}
```



