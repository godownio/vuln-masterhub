---
id: ctf-crypto-lll-public-key-linear-combination-forge-private-key
title: 公钥系数线性组合的 LLL 明文恢复与无校验私钥伪造
type: scenario
domain: ctf
path: ctf/crypto
technique: lll-public-key-linear-combination-forge-private-key
tags:
- ctf
- crypto
- lll
- lattice
- knapsack
- public-key
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:31+08:00'
  notes: 已对照 sk 原代码核对：2^512 缩放分块 LLL、v[-1]=±1 行恢复 pt、f=[-pt%p,1]/h=[0,0]/R,S=(1,p) 伪造一致；未复跑。
url: /docs/ctf/crypto/ctf-crypto-lll-public-key-linear-combination-forge-private-key/
draft: false
kb_aliases:
- 公钥线性组合 LLL
- 隐藏明文格攻击
- 伪造私钥
- sk
---

## 一句话结论

当密文是“公钥系数与明文幂的 Z 上线性组合”且组合系数是小量时，把公钥、密文与缩放因子 `2^512` 组成格，LLL 可找到最后一位为 ±1 的短向量并直接解出明文 `pt`；题目对私钥 `f,h,R1,S1,R2,S2` 没有额外范围/格式校验，因此知道明文后构造 `f=[-pt mod p, 1]`、`h=[0,0]`、`R1/S1=R2/S2=(1,p)` 就能通过解密/验签。

## 原理

- 题目加密式形如 `Σ_i P_i * (u * pt^i mod p)`，即密文是公钥元素在整数环上的线性组合，组合系数由明文 `pt` 的幂与小因子 `u` 决定。公钥规模与 `p` 相差很大，导致这个组合在普通整数域里“很长”，但乘以缩放因子后可以把明文向量嵌成格中的短向量。
- 构造分块矩阵
  `[[1, 2^512*(P0+P1)^T, 2^512*(Q0+Q1)^T, 0], [0, 2^512*PP, 2^512*QQ, 1]]`
  并做 LLL：最后一列为 `±1` 的行表示用整数系数组合公钥/密文后得到 1，行内其余坐标与明文相关；由相邻坐标的比值模 `p` 可恢复 `pt`。
- 题目验证只检查提交的 `f,h,R1,S1,R2,S2` 是否使解密关系成立，不检查它们是否真的是合法私钥（没有范数、次数或格式约束）。因此一个平凡的 `f=[-pt mod p, 1]`、`h=[0,0]`、`R1/S1=R2/S2=(1,p)` 就能让等式成立，直接解出密文。
- LLL 在此题是概率性成功：需要多跑几次或重启连接，直到短向量最后一位为 `±1`。

## 触发条件

- 公钥与密文以整数/多项式系数形式给出，密文可表示为公钥的 Z 线性组合，且秘密明文是小量。
- 题目允许提交自定义私钥参数进行解密/验签，且没有对参数做合法性/范围检查。
- 可以多次连接或多次尝试，以抵消 LLL 的概率性失败。

## 利用步骤

1. 连接服务，解析 `pk=(P,Q,p)` 与 `enc=(PP,QQ)`。
2. 按上面的分块矩阵构造格，对 `(P[0]+P[1])`、`(Q[0]+Q[1])` 与 `(PP,QQ)` 乘 `2^512` 缩放。
3. LLL 后遍历行，寻找最后一维绝对值为 1 的向量 `v`。
4. 用 `m = v[1] * inverse(v[0], p) mod p`（或相邻坐标比）恢复明文 `pt`。
5. 构造 `f=[-pt % p, 1]`、`h=[0,0]`、`R1,S1=1,p`、`R2,S2=1,p`。
6. 提交解密操作与这组伪造私钥，得到明文/flag。

## PoC

```python
from sage.all import *
from pwn import *

io = remote(host, port)
io.sendlineafter(b"team token:", token)
P, Q, p = eval(io.recvline().strip().decode())
PP, QQ = eval(io.recvline().strip().decode())

L = block_matrix(ZZ, [
    [1, 2**512 * matrix(P[0] + P[1]).T, 2**512 * matrix(Q[0] + Q[1]).T, 0],
    [0, 2**512 * PP, 2**512 * QQ, 1],
]).LLL()

for v in L:
    if abs(v[-1]) == 1:
        pt = v[1] * inverse_mod(v[0], p) % p
        break

b = -pt % p
f = [b, 1]
h = [0, 0]
R1, S1 = 1, p
R2, S2 = 1, p

io.sendlineafter(b"op>", b"2")
io.sendlineafter(b"ct:", f"{PP} {QQ}".encode())
io.sendlineafter(b"your f:", f"{f[0]} {f[1]}".encode())
io.sendlineafter(b"your h:", b"0 0")
io.sendlineafter(b"your R1 S1:", b"1 " + str(p).encode())
io.sendlineafter(b"your R2 S2:", b"1 " + str(p).encode())
io.interactive()
```

说明：`host/port/token` 为题目参数；坐标比值公式按原文实现保留，未在本机复跑原题。

## 变体与关联

- **Knapsack/子集和**：同类“公钥是系数、密文是短组合”的格攻击，缩放因子与嵌入维数按规模调整。
- **NTRU/LWE**：短秘密嵌入格中找短向量；见 [[ctf-crypto-ntru-xplus1-lll-distinguish-mt]]。
- **签名伪造**：若验证只检查代数关系而不检查私钥范围，知道明文后总可以构造平凡私钥；这是“验证逻辑不完整”的常见模式。

## 检测与防御

- 私钥参数必须做范围、范数、次数与格式校验；不能只验算最终等式。
- 加密方案应使用标准构造（RSA-OAEP、NTRU 标准参数），不要自定义“公钥线性组合”类协议。
- 检测：同一连接反复 LLL 尝试、提交异常小的 `f/h/R/S` 参数；对解密接口做速率限制与参数审计。
