---
title: NTRU
date: 2022-09-29 19:31:50
tags: 密码学
math: true
---

## NTRU

### 介绍

NTRU 是基于格的加密算法来加密数据的。它包括两部分算法：NTRUEncrypt 用来加密数据，NTRUSign 用来进行数字签名。

### 内容

首先确定$3$个参数$(N,p,q)$以及$4$个度为$N-1$的多项式集合$\mathcal{L}_f,\mathcal{L}_g,\mathcal{L}_r,\mathcal{L}_m$

需要满足$\gcd(p,q)=1$并且$q>p$，并且所有多项式需要在环$R=\mathbb{Z}[X]/(X^N-1)$ ，这个环中的多项式形式

$$
F=a_0+a_1X+a_2X^2+\cdots+a_{N-2}x^{N-2}+a_{N-1}x^{N-1}
$$

其中系数都是整数，度数不超过$N-1$

$\mathcal{L}_m$里面的多项式$m$需要满足$-\frac{1}{2}(p-1)\lt [X^i]m\lt \frac{1}{2}(p-1)$

$\mathcal{L}_f$里面多项式的系数只有$1,-1,0$三种，记系数为$1$的个数为$d_1$，系数为$-1$的个数为 $d_{-1}$，满足$d_1=d_{-1}+1$

$\mathcal{L}_g$里面多项式的系数只有$1,-1,0$三种，满足$d_1=d_{-1}$

$L_{r}$里面多项式的系数只有$1,-1,0$三种，满足$d_1=d_{-1}$

### Public key generation

令$f\in \mathcal{L}_f$，$g\in \mathcal{L}_g$，计算$F_p$和$F_q$，满足

$$
F_p*f\equiv 1 \mod{p}\\
F_q*f\equiv 1 \mod{q}
$$

计算公钥

$$
h\equiv p*g*F_q\mod{q}
$$

公钥$(h,N,p,q)$，私钥是$(f,F_p)$

### Encryption

选择明文$m\in \mathcal{L_m}$以及随机生成一个多项式$r\in \mathcal{L}_r$，计算

$$
e\equiv r*h+m\mod{q}
$$

### Decryption

第一步

$$
\begin{aligned}
a &\equiv  e*f\mod{q}\\
&\equiv r*p*g*F_q*f+m*f\mod{q}\\
&\equiv r*p*g+m*f\mod{q}
\end{aligned}
$$

第二步

$$
\begin{aligned}
a*F_p\equiv 0+m*f*F_p\equiv m\mod{p}
\end{aligned}
$$
