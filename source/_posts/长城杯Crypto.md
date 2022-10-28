---
title: 长城杯Crypto
date: 2022-08-24 09:53:33
tags: 密码学
math: true
---

## Know_phi

### 考点

+ 已知$\phi$分解$n$
+ DSA数字签名算法

### DSA算法

安全性基于求离散对数的困难性

+ 全局公开钥

  $p​$：满足$2^{L-1}\lt p\lt 2^L​$的大素数，其中$512\le L\le 1024​$，并且$L​$是$64​$的倍数

  $q$：$p-1$的素因子，满足$2^{159}\lt q\lt 2^{160}，即$$q$长为$160$比特

  $g$：$g\equiv h^{\frac{p-1}{q}}\mod{p}$，其中$h$是满足$1\lt h\lt p-1$且使得$h^{\frac{p-1}{q}}\pmod{p}\gt 1$的任一整数

+ 用户秘密钥$x$

  $x$是满足$0\;t x\lt q$的随机数或伪随机数

+ 用户的公开钥$y​$
  $$
  y\equiv g^x\mod{p}
  $$

+ 用户为待签消息选取的秘密数$k​$

  $k$是满足$0\lt k\lt q$的随机数或伪随机数

+ 签名过程

  用户对消息$M​$的签名为二元对$(r,s)​$，其中$r\equiv(g^k\mod{p})\mod{q}​$，$s\equiv[k^{-1}(H(M)+xr)]\mod{q}​$，$H(M)​$是由$\text{SHA}​$求出的哈希值

+ 验证过程

  设接收方受到的消息为$M^{'}​$，签名为$(r^{'},s^{'})​$。计算
  $$
  w\equiv (s^{'})^{-1}\mod{q} \text{,} \quad u_1\equiv [H(M^{'})w]\mod{q}\\
  u_2\equiv r^{'}w\mod{q} \text{,} \quad v\equiv [(g^{u_1}y^{u_2})\mod{p}]\mod{q}
  $$
  检查$v$是否和$r^{'}$相等，若相等则认为签名有效，因为若$(M,r,s)=(M^{'},r^{'},s^{'})$，则
  $$
  v\equiv[(g^{H(M)w}g^{xrw})\mod{p}]\mod{q} \equiv [g^{(H(M)+xr)s^{-1}}\mod{p}]\mod{q}\\
  由于k\equiv s^{-1}(H(M)+xr)\mod{q}\\
  v\equiv [g^k\mod{p}]\mod \equiv r
  $$
  

### 题目

``` python
from Crypto.Util.number import getPrime, bytes_to_long, inverse, long_to_bytes
from Crypto.PublicKey import DSA
from hashlib import sha256
import random
from secret import flag

def gen(a):
    p = getPrime(a) 
    q = getPrime(a)
    r = getPrime(a)
    x = getPrime(a)
    n = p*q*r*x
    phi = (p-1)*(q-1)*(r-1)*(x-1)

    return n, phi, [p, q, r, x]

def sign(m, k, x, p, q, g):
    hm = bytes_to_long(sha256(m).digest())
    r = pow(g, k, p) % q
    s = (hm + x*r) * inverse(k, q) % q

    return r,s

e = 65537
a = 256
x = bytes_to_long(flag)
# print(x)

n, phi, n_factors = gen(a)
n_factors = sorted(n_factors)
print(f'n = {n}')
print(f'phi = {phi}')
m1 = long_to_bytes(n_factors[0] + n_factors[3])
m2 = long_to_bytes(n_factors[1] + n_factors[2])
# print(f'm1 = {m1}')
# print(f'm2 = {m2}')
key = DSA.generate(int(2048))
q = key.q
p = key.p
g = key.g
assert q > x
k = random.randint(1, q-1)
r1, s1 = sign(m1, k, x, p, q, g)
r2, s2 = sign(m2, k, x, p, q, g)
# print(f'k = {k}')
print(f'q = {q}')
print(f's1 = {s1}')
print(f'r1 = {r1}')
print(f's1 = {s1}')
print(f'r2 = {r2}')
print(f's2 = {s2}')
'''
n =   104228256293611313959676852310116852553951496121352860038971098657350022997841589403091722735802150153734050783858816709247647536393314564077002364012463220999962114186339228164032217361145009468516448617173972835797623658266515762201804936729547278758839604969469770650218191574897316410254695420895895051693
phi = 104228256293611313959676852310116852553951496121352860038971098657350022997837434645707418205268240995284026522165519145773852565112344453740579163420312890001524537570675468046604347184376661743552799809753709321949095844960227307733389258381950812717245522599433727311919405966404418872873961877021696812800
q = 24513014442114004234202354110477737650785387286781126308169912007819
s1 = 764450933738974696530033347966845551587903750431946039815672438603
r1 = 8881880595434882344509893789458546908449907797285477983407324325035
r2 = 8881880595434882344509893789458546908449907797285477983407324325035
s2 = 22099482232399385060035569388467035727015978742301259782677969649659
'''
```

### Solve

给定了对不同消息的签名$(M_1,r_1,s_1)、(M_2,r_2,s_2)$和公开钥$q$，目标是求$x$

$M_1$和$M_2$没有直接给出，但根据题目知道我们需要分解$N$来得到$p、q、r、s$，但用`yafu`分解不了，但已知$\phi$，有一个根据$\phi$分解$N$的脚本

``` python
def factorize_multi_prime(N,phi):
	 """
	 Recovers the prime factors from a modulus if Euler's totient is known.
	 This method works for a modulus consisting of any number of primes, but is considerably be slower than factorize.
	 More information: Hinek M. J., Low M. K., Teske E., "On Some Attacks on Multi-prime RSA" (Section 3)
	 :param N: the modulus
	 :param phi: Euler's totient, the order of the multiplicative group modulo N
	 :return: a tuple containing the prime factors
	 """
	 prime_factors=set()
	 factors=[N]
	 while len(factors)>0:
	 	N=factors[0]
	 	w=randrange(2,N-1)
	 	i=1
	 	while phi%(2**i)==0:
	 		sqrt_1=pow(w,phi//(2**i),N)
	 		if sqrt_1>1 and sqrt_1!=N-1:
	 			factors=factors[1:]
	 			p=gcd(N,sqrt_1+1)
	 			q=N//p
	 			if gmpy2.is_prime(p):
	 				prime_factors.add(int(p))
	 			elif p>1:
	 				factors.append(int(p))
	 			if gmpy2.is_prime(q):
	 				prime_factors.add(int(q))
	 			elif q>1:
	 				factors.append(int(q))
	 			break
	 		i=i+1
	 return tuple(prime_factors)
```

然后一般对于DSA的攻击，需要求出$k$，所以就是式子推导时间
$$
s_1\equiv[k^{-1}(H(M_1)+xr_1)]\mod{q}\\
s_2\equiv[k^{-1}(H(M_2)+xr_2)]\mod{q}\\
s_1-s_2\equiv[k^{-1}((H(M_1)-H(M_2)+xr_1-xr_2)]\mod{q}\\
k\equiv [(s_1-s_2)^{-1}((H(M_1)-H(M_2)+xr_1-xr_2)]\mod{q}
$$
由于$r_1\equiv r_2\equiv [g^{k}\mod{p}]\pmod{q}$，故$xr_1-xr_2\equiv0\mod{q}$，题目给的也是$r_1=r_2$

故
$$
k\equiv[(s_1-s_2)^{-1}((H(M_1)-H(M_2)]\mod{q}
$$
之后求$x$
$$
x\equiv r_1^{-1}[s_1k-H(M_1)]\mod{q}
$$

``` python
from Crypto.Util.number import getPrime, bytes_to_long, inverse, long_to_bytes
from Crypto.PublicKey import DSA
from hashlib import sha256
from math import gcd
from random import randrange
import gmpy2
import libnum
def factorize_multi_prime(N,phi):
	 """
	 Recovers the prime factors from a modulus if Euler's totient is known.
	 This method works for a modulus consisting of any number of primes, but is considerably be slower than factorize.
	 More information: Hinek M. J., Low M. K., Teske E., "On Some Attacks on Multi-prime RSA" (Section 3)
	 :param N: the modulus
	 :param phi: Euler's totient, the order of the multiplicative group modulo N
	 :return: a tuple containing the prime factors
	 """
	 prime_factors=set()
	 factors=[N]
	 while len(factors)>0:
	 	N=factors[0]
	 	w=randrange(2,N-1)
	 	i=1
	 	while phi%(2**i)==0:
	 		sqrt_1=pow(w,phi//(2**i),N)
	 		if sqrt_1>1 and sqrt_1!=N-1:
	 			factors=factors[1:]
	 			p=gcd(N,sqrt_1+1)
	 			q=N//p
	 			if gmpy2.is_prime(p):
	 				prime_factors.add(int(p))
	 			elif p>1:
	 				factors.append(int(p))
	 			if gmpy2.is_prime(q):
	 				prime_factors.add(int(q))
	 			elif q>1:
	 				factors.append(int(q))
	 			break
	 		i=i+1
	 return tuple(prime_factors)

n=104228256293611313959676852310116852553951496121352860038971098657350022997841589403091722735802150153734050783858816709247647536393314564077002364012463220999962114186339228164032217361145009468516448617173972835797623658266515762201804936729547278758839604969469770650218191574897316410254695420895895051693
phi=104228256293611313959676852310116852553951496121352860038971098657350022997837434645707418205268240995284026522165519145773852565112344453740579163420312890001524537570675468046604347184376661743552799809753709321949095844960227307733389258381950812717245522599433727311919405966404418872873961877021696812800
q = 24513014442114004234202354110477737650785387286781126308169912007819
s1 = 764450933738974696530033347966845551587903750431946039815672438603
r1 = 8881880595434882344509893789458546908449907797285477983407324325035
r2 = 8881880595434882344509893789458546908449907797285477983407324325035
s2 = 22099482232399385060035569388467035727015978742301259782677969649659

fac=factorize_multi_prime(n,phi)
invs=inverse(s1-s2,q)
invr1=inverse(r1,q)

for P in fac:
	for Q in fac:
		if P==Q:
			continue
		for R in fac:
			if P==R or Q==R:
				continue
			for X in fac:
				if P==X or Q==X or R==X:
					continue
				M1=long_to_bytes(P+X)
				M2=long_to_bytes(Q+R)
				HM1=bytes_to_long(sha256(M1).digest())
				HM2=bytes_to_long(sha256(M2).digest())
				k=invs*(HM1-HM2)%q
				x=invr1*(s1*k-HM1)%q
				if b'flag' in long_to_bytes(x):
					print(long_to_bytes(x))
```

`flag{ea16de7-1981-11ed-b58f}`

## rsa

### 题目

``` python
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from Crypto.Random import random
from random import getrandbits
from sympy.ntheory.residue_ntheory import nthroot_mod
from sympy import nextprime
from secret import flag

def get_primes(m):
    p = getPrime(Bits)
    pl = p & int('f'*(m//4), 16)
    q = (getrandbits(Bits - m) << m)^^pl
    while not isPrime(q):
        q = (getrandbits(Bits - m) << m)^^pl
    return (p, q)

def get_key(p, q, delta, beta, Bits):
    phi = (p - 1) * (q - 1)
    d1 = getPrime(floor(2 * Bits * delta))
    e1 = inverse_mod(d1, phi)
    d2 = nextprime(d1 ^^ getrandbits(floor(2 * Bits * beta)))
    e2 = inverse_mod(d2, phi)
    d3 = getPrime(floor(2 * Bits * delta))
    e3 = inverse_mod(d3, phi)
    return (e1, e2, e3, d1, d2, d3)

    
if __name__ == '__main__':
    Bits = 1024 
    alpha = 0.098
    delta = 0.536
    beta = delta
    gamma = 1
    m = floor(2 * alpha * Bits)

    p, q = get_primes(m)
    n = p * q
    assert n % 2^3 == 1
    u0 = nthroot_mod(n, 2, 2^m, all_roots=False)
    v0 = (2*u0 + ((n - u0^2) * inverse_mod(u0, 2^(2*m)) % 2^(2*m)))
    e1, e2, e3, d1, d2, d3 = get_key(p, q, delta, beta, Bits)

    flag = bytes_to_long(flag)
    c = pow(flag, e3, n)
    l0 = d1 - d2

    print(f'N = {hex(n)}')
    print(f'e1 = {hex(e1)}')
    print(f'e2 = {hex(e2)}')
    print(f'e3 = {hex(e3)}')
    print(f'c = {hex(c)}')
    print(f'v0 = {hex(v0)}')
    print(f'l0 = {hex(l0)}')

# N = 0x62c048bc886075bffb9ad01255786dd8ef2480ba510f13689c1e84ffaaf21dfb5695a4d83f4ba22093bdd75bfc8f5979185d29724ecccf045e1857b1b2a4757dd82dc44318c054c9fce9bc451e6beecb97bbda6562420fc8c295521c5455443413f90403cf1af6271fb6d2d54378b86ced18ae6844a877890ea853a215880a09c68c517a75c1183c067b706ce630f3f0913591f7354cfa60c8f6b7ab2f15e466a1ea6e8034417a5fc3c11b8ba746596c22c734b09257e9a6fb18358738d416eda0ba0e7b028dd2d550b1e018b180916ac25f47910657a5db2410946c0593b7e23ed1659a811083f363ad4eb65642091a040befbd643089bbee376634d2394d11
# e1 = 0x124241a12ea2be53f9b9b1fd92e10d089cfa32aa07e6c2cace848aaa6c73ff06d4c6c92b7d1f29160b2eef95a5f580915d3f15c0ea23975cbadfe8347a10daab2bd0827d7e909b329ec53c5eb306f0a5125b3817e7ea0c15b2317a46c36c4f34fc626dadc6c769bcc7be18ddf7954fae8dde3fd4ce3c5146c019bdb0d9552af1dc9ef7186e06b1d59e763fb05c7cd21fbb3f509fee52d4e24921ebfa76bb8302ea6760e92606e440907cc1c110946af53900904e84dbc309fcef15ea060c667070e5e0310891606df151609ff609bcc6125c6043c35119b25df78b4d5ca61ab6492753cc5e5b32e044fce0aeb0442464f36298add254e9fb6505fa4cddae1cf7
# e2 = 0x17b3937cec3ca5fdddad8db29c6dc4efae1408bf5b4aa2ff602112c50f302e9698c79c7ab79fef0210c621dcc218d91d358b7f93a978c4e3f2b982794697c4797cef89189d1464ed1c767bf72433092922352885f8e355952c558ad2c9ade58a19375ddc5dcf3f9fa28c68a5cff158734d94224b85f77bd939133f39ab7884ece61d9fb3496373008827c2ae694dfe7da08eee348ef99c3a6737a4b088b62978cf209ef3d1140a30d42872615b94378108266e3d344caf51b497a585a4b5ef8619cc46959bad9b89f59f36175fbf9b64363443f3f7743896c72a198decedf89c518fa07b1d401d0359578a4926b7d67de86232ee24751f17dafbc749c0783b33
# e3 = 0x5647c4490bda9e7e497651551600572c5ef4e2d889b9b1ba0e9a493660497e10877e975c01da9aebae5e3ba9aad976a1a783b39191e8fd799689dfa26b069264d60543602d514ac412ac75d827d67c78ad544bda633f0fa69fb5bbc37e0f6b95714576ff53bae3f7f991d143a4b1e841730d5d580d4effeb8fb02e8b3c3c9a1f1899d2eb411ce37f16d30cfa1f7af7322be4f42f5d012f484a1181fa4aa0b5f420a472030a5c08c80bff76ab82ef5768bfd495abcdc5f22aae1891561322dfb28ff63c4e467411c8b73c11d64b05f411e2a1de0c7754c6a62d1f72cded9e2592ccc21be3fce4ea6f083a617a246fd3fe464ef2487adbfabfb628c882ea991675
# c = 0x45f2ee650d622d1e0f0e2e2e861001e9866c541f9f1dd2ec1dec18194f8b7224914916ecd68bbc74b28a000d2664e671586aed63b54c0928a939caf28d39eeba03c0ce3afcf2cdc5805e8e2792d76e88545aa4dee11078ba1e2e5b56ee23d58e443d7aff180d4e7463ae66ea8e96e0c8d4e1443e7664b99599af14e591e28cf2f833bd30b44b89c396b5fc1ee81ea3f7bc08dab426b1871eb66829c81d57e2ebf5c7a3e9c593ce496f0b0c4237906b019ae75ca551d6b0b1adfe64958c2ead6c39e517eb75eaf4b4d72402bea40f043cf0a80317aa2f1a996c727e195e15f903c0cac618f668af1015ee479d1c7b1c1b370fd4a5a76f5bf295e6bd7d0f4ae56f
# v0 = 0x2c77a013f2595a90c4e10a53a0f863d02b361c7407dad7d59db7c98df427da00c8d8627dbaef9557279ca31227cdb402d2d2
# l0 = 0x3dbabf6ea5b801221c283bd234f04264d292c8f3048c8b59c21e003cda983a3a41e4392c6ea77a706631de60d261f2b367027e037d37fda5a13a8e01b2c6c0f48a3112315cffe7420a50a3ebada09aba61f8e6da793654a467b9f780c20c5085012e064ab9205c076073b4fb4895e01d0d568fd5c30159879180093855d39d5548a1389a94f57c680c
```

### Solve

比较裸的RSA，令$m=flag$，根据题目，已知$n,e_1,e_2,e_3,c,v_0,l_0$
$$
N=pq\\
L=(p-1)(q-1)\\
e_1d_1\equiv 1\mod{L}\\
e_2d_2\equiv 1\mod{L}\\
e_3d_3\equiv 1\mod{L}\\
l_0=d_1-d_2\\
c\equiv m^{e_3}\mod{n}
$$
可以发现其实$v_0$没有用，目标是求$d_3$，要先求出$L$，但由于$N$太大不好分解，所以又是推式子时间
$$
e_1d_1\equiv 1 \mod{L}\\
e_2d_2=e_2(d_1-l_0)\equiv 1\mod{L}\\
(e_1-e_2)d_1+e_2l_0\equiv 0 \mod{L}\\
(e_1-e_2)d_1e_1+e_2e_1l_0\equiv (e_1-e_2)+e_2e_1l_0\equiv 0\mod{L}\\
kL=e_1-e_2+e_2e_1l_0\\
d_3^{'}e_3\equiv1\mod{kL}\\
m\equiv c^{d_3^{'}}\mod{n}
$$

``` python
from gmpy2 import *
from Crypto.Util.number import *
N,e1,e2,e3,c,v0,l0 

kL=e1-e2+e1*e2*l0
d3=inverse(e3,kL)
m=pow(c,d3,N)
print(long_to_bytes(m))
```

`flag{-oh!!h0w_c4N_Y0u_sOlVe_th15_d_bouNd_of_RSA???_}`