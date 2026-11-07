---
id: ctf-reverse-right-shift-constraint-md5-bruteforce
title: 右移一位约束 + MD5 校验：笛卡尔积爆破恢复 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: right-shift-constraint-md5-bruteforce
tags:
- ctf
- reverse
- md5
- bruteforce
- bit-shift
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:14:00+08:00'
  notes: 已对照原文核对：input[i]>>1==target[i] 的 29 字节约束、每位 2*t/2*t+1 候选、MD5 目标 3a22c098710019b31c328a861429d3ad、笛卡尔积爆破与 flag xmctf{welc0me_2_polar1s_1022} 均一致（候选与 flag 逐位已核对）。未验证点：PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-right-shift-constraint-md5-bruteforce/
draft: false
kb_aliases:
- 右移一位
- input >> 1
- MD5 校验
- 笛卡尔积爆破
- 移动的秘密
---

## 一句话结论

程序要求每个输入字符右移一位后等于目标字节（`input[i] >> 1 == target[i]`），每位只有两个候选字符；再用 `MD5(input)` 与硬编码值比较，枚举每位候选的笛卡尔积并逐个哈希即可唯一恢复 flag。

## 原理

- 右移一位丢弃最低位：`input[i] >> 1 == target[i]` 意味着 `input[i]` 只能是 `2*target[i]` 或 `2*target[i]+1`；若目标字节对应可打印字符集只有一个合法值，则候选唯一。
- 程序同时要求 `MD5(input) == 3a22c098710019b31c328a861429d3ad`，这是一个强约束；只要候选空间不大（每位 1-2 个），直接笛卡尔积枚举即可。
- 示例 29 字节输入，前 6 位由 `xmctf{` 前缀唯一确定，其余每位最多 2 个候选；总空间远小于 2^29，普通 CPU 秒级可爆破。
- 该手法说明“位运算约束 + 哈希校验”不是安全校验：位运算泄露大量信息，MD5 只用于最终筛选，不能阻止枚举。

## 触发条件

- 程序对输入做右移/左移/掩码等位运算后与目标比较。
- 另有哈希/校验和（MD5/SHA/CRC）作为最终约束。
- 候选空间可枚举（每位候选数小、总长度可控）。
- 目标哈希已知或可从二进制提取。

## 利用步骤

1. 从反汇编/源码提取位运算表达式与目标字节数组。
2. 对每个目标字节计算候选字符集合（`2*t`、`2*t+1`，过滤不可打印/不在字符集的值）。
3. 用已知前缀/格式进一步缩小候选。
4. 对候选列表做 `itertools.product`，逐个计算 MD5 并与目标比较。
5. 命中后输出明文，套上 flag 格式。

## PoC

```python
import hashlib
import itertools

md5_target = bytes.fromhex("3a22c098710019b31c328a861429d3ad")
cand = [
    ['x','y'], ['l','m'], ['b','c'], ['t','u'], ['f','g'], ['z','{'],
    ['v','w'], ['d','e'], ['l','m'], ['b','c'], ['0','1'], ['l','m'],
    ['d','e'], ['_'], ['2','3'], ['_'], ['p','q'], ['n','o'], ['l','m'],
    ['a'], ['r','s'], ['0','1'], ['r','s'], ['_'], ['0','1'], ['0','1'],
    ['2','3'], ['2','3'], ['}'],
]

for tup in itertools.product(*cand[6:]):
    s = "xmctf{" + "".join(tup)
    if hashlib.md5(s.encode()).digest() == md5_target:
        print(s)
        break
```

## 变体与关联

- 变体：左移、掩码、异或、取反等位运算；候选集合按表达式推导。
- 变体：最终约束换成 SHA-1/SHA-256/CRC/自定义校验；枚举方式不变。
- 变体：多位字符/UTF-8 输入时，候选空间可能变大，需要剪枝或 meet-in-the-middle。
- 关联：[[crypto-hash-md5-digest-strcmp-nullbyte-truncation]]（MD5 比较缺陷）、[[ctf-reverse-predictable-score-derived-aes-key-iv]]（可预测校验）、[[ctf-reverse-printable-ascii-caesar-hidden-permutation-table]]（字符变换逆推）。

## 检测与防御

- 检测：反汇编中出现 `>> 1`、`<<`、`& mask` 与目标数组比较，随后调用 MD5/SHA。
- 防御：不要用位运算 + 哈希做授权；使用带密钥的 MAC/签名或服务端校验，并对输入做速率限制。
- 响应：确认校验可枚举后，视为逻辑泄露，轮换相关密钥并审计客户端。
