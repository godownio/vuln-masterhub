---
id: crypto-hash-md5-three-way-collision-nested-fastcoll
title: MD5 三碰撞构造：identical-prefix 二碰撞嵌套两次 + 三层嵌套协议
type: scenario
domain: crypto
path: crypto/hash
technique: md5-three-way-collision-nested-identical-prefix
tags:
- crypto
- hash
- md5
- collision
- fastcoll
- multicollision
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:19:05+08:00'
  notes: 已对照原文核对：三层 MD5 校验归约为固定前缀三碰撞、fastcoll identical-prefix 二碰撞嵌套（m0/m1→n0/n1）、ext0=n0[len(m0+tag2):]、c2=m1+tag2+ext0、tag 带轮次/层号去重、提交时裁掉共同前缀均一致。未验证点：PoC 未实际运行 fastcoll/远程复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/crypto/hash/crypto-hash-md5-three-way-collision-nested-fastcoll/
draft: false
kb_aliases:
- polarisCTF truck
- MD5 三碰撞
- 3-way collision
- fastcoll
- identical prefix collision
- 三层 MD5 校验
- 碰撞后缀去重
---

## 一句话结论

题目要求三层 MD5 校验中每组三个不同输入哈希相同，可把每层归约为“固定前缀 + 三个不同后缀、MD5 相同”的子问题；用 fastcoll 在 `m0` 前缀上做一次 identical-prefix 二碰撞得到 `n0/n1`，再把 `n0` 去掉共同前缀的后缀拼回 `m1`，即可用两次二碰撞构造出三条 MD5 相同的消息。

## 原理

- **MD5 迭代结构**：MD5 按 Merkle-Damgård 结构迭代压缩；两条消息若在某个前缀后内部状态相同，则后续拼接相同后缀仍保持哈希相同。identical-prefix collision 工具（fastcoll）正是构造两条共享指定前缀、哈希相同的消息 `m0,m1`。
- **三碰撞构造**：
  1. 在 `base+tag1` 上跑 fastcoll，得到 `m0,m1`，`MD5(m0)=MD5(m1)`。
  2. 以 `m0+tag2` 为前缀再跑 fastcoll，得到 `n0,n1`，`MD5(n0)=MD5(n1)`。
  3. 令 `ext0 = n0[len(m0+tag2):]`，构造 `c0=n0`、`c1=n1`、`c2=m1+tag2+ext0`。
  - 因为 `MD5(m0)=MD5(m1)`，所以 `MD5(m1+tag2+ext0)=MD5(m0+tag2+ext0)=MD5(n0)`；于是 `c0,c1,c2` 三条不同消息哈希相同。
- **三层归约**：第一层要求 `md5(A)=md5(B)=md5(C)`，第二层要求 `md5(ha+D)=md5(hb+E)=md5(hc+F)`，第三层同理。第一层通过后 `ha=hb=hc`，第二层就变成同一前缀 `ha` 后接三个后缀；第三层同理。每层只需对共同前缀做一次三碰撞。
- **去重约束**：题目要求同一轮 9 段两两不同、十轮之间不复用。构造时把轮次和层编号放进 tag（如 `L1|ROUND|i|`），让每层前缀不同，从而打散碰撞上下文；生成后先检查本轮 9 段互异，再整体检查跨轮集合。
- **提交后缀**：碰撞工具输出的是带前缀的完整消息；远程只接收后缀，需统一裁掉共同前缀 `base`。
- **为什么成立**：MD5 的碰撞可被高效构造（fastcoll 秒级），而题目的校验只比较哈希、不校验长度/内容结构；三层嵌套没有引入新的密码学难度，只是重复同一子问题。

## 触发条件

- 目标使用 MD5 做多组输入的相等性校验，且允许多轮/多组提交。
- 攻击者能运行 fastcoll（或等价 identical-prefix MD5 碰撞工具），并能为每层选择共同前缀。
- 题目对输入长度/字符集没有严格限制，或允许二进制后缀。
- 有去重逻辑时，需要能控制前缀/后缀使各组消息互异。

## 利用步骤

1. 分析校验逻辑：确认每层都是“三组输入的 MD5 相等”，且上一层输出会作为下一层前缀的一部分。
2. 实现 `triple_collision(base, tag)`：`m0,m1 = fastcoll(base+tag1)`；`n0,n1 = fastcoll(m0+tag2)`；`ext0 = n0[len(m0+tag2):]`；返回 `n0, n1, m1+tag2+ext0`。
3. 第一层用空前缀生成 `A,B,C`；第二层用 `ha` 生成 `D,E,F`；第三层用 `hd` 生成 `G,H,I`。
4. 每层 tag 带轮次/层号；生成后检查 9 段互异，并检查跨轮不复用。
5. 把每条消息裁掉共同前缀，得到远程需要的后缀；按提示符逐条提交。
6. 若 fastcoll 输出不满足前缀/碰撞校验，重跑或换工具版本；缓存已生成的碰撞对以加速多轮。

## PoC

```python
import hashlib, subprocess, tempfile, os

def H(m): return hashlib.md5(m).digest()

def fastcoll(prefix: bytes):
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td, "prefix.bin"), "wb").write(prefix)
        subprocess.run(["fastcoll", "--prefixfile", "prefix.bin",
                        "-o", "m1.bin", "m2.bin"], cwd=td, check=True)
        m1 = open(os.path.join(td, "m1.bin"), "rb").read()
        m2 = open(os.path.join(td, "m2.bin"), "rb").read()
    assert m1 != m2 and H(m1) == H(m2)
    assert m1.startswith(prefix) and m2.startswith(prefix)
    return m1, m2

def triple(base: bytes, tag: bytes):
    m0, m1 = fastcoll(base + b"L1|" + tag + b"|")
    n0, n1 = fastcoll(m0 + b"L2|" + tag + b"|")
    ext0 = n0[len(m0 + b"L2|" + tag + b"|"):]
    c0, c1, c2 = n0, n1, m1 + b"L2|" + tag + b"|" + ext0
    assert len({H(c0), H(c1), H(c2)}) == 1
    assert len({c0, c1, c2}) == 3
    return c0, c1, c2

# 每层：A,B,C = triple(b"", tag1); D,E,F = triple(H(A), tag2); G,H,I = triple(H(H(A)+D), tag3)
```

## 变体与关联

- 碰撞工具变体：fastcoll、hashclash、Marc Stevens 的 chosen-prefix 工具；chosen-prefix 更强但更慢，identical-prefix 足够本题。
- 层数变体：两层/四层同理，每层对共同前缀做三碰撞；更多层只是重复。
- 去重变体：tag 里加入随机 nonce/轮次/层号；若题目限制后缀长度，需要压缩 tag 或使用更短的碰撞块。
- 关联：[[ctf-crypto-linear-hash-collision-lll]]（线性哈希碰撞的格方法）、[[crypto-hash-md5-digest-strcmp-nullbyte-truncation]]（MD5 摘要比较缺陷）。

## 检测与防御

- 检测：提交数据中出现大量二进制/高熵块、重复的碰撞块特征、每轮 9 段长度异常；同一前缀反复出现；MD5 校验通过但内容不可读。
- 防御：不要用 MD5 做安全相等性校验；改用 SHA-256/SHA-3 或 HMAC；对输入做长度/字符集/结构限制；对多轮提交做去重与速率限制。
- 加固：若必须兼容旧哈希，使用带密钥的 HMAC 或对哈希结果再做一次签名；禁止把 MD5 用作完整性/身份凭据。
