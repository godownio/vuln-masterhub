---
id: ctf-crypto-rsa-noncoprime-common-modulus-iroot-wiener-chain
title: RSA 非互素指数共模攻击：gcdext 得 m^g 后加 n 开 g 次根恢复明文
type: scenario
domain: ctf
path: ctf/crypto
technique: rsa-noncoprime-common-modulus-iroot
tags:
- ctf
- crypto
- rsa
- common-modulus
- non-coprime
- integer-root
- wiener
- docx-repack
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V203
  verified_at: '2026-11-07T02:17:11+08:00'
  notes: 已对照原文核对：e1=341/e2=209/g=11、gcdext 得 m^g mod n、反复加 n 开 11 次根、Wiener 恢复第一层压缩包密码、docx 重建与字节反转，与原文 PoC/截图一致。dedup top 候选 crypto-rsa-common-modulus 为 likely_duplicate，但其仅覆盖 gcd(e1,e2)=1，本卡的 g>1 开根扩展不构成同一利用链，理由成立。未验证点：未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-rsa-noncoprime-common-modulus-iroot-wiener-chain/
draft: false
kb_aliases:
- 非互素共模攻击
- 共模攻击扩展
- gcd(e1,e2)!=1
- 共模后开根
- iroot 加 n 爆破
- RSA 多层压缩包
---

## 一句话结论

同一明文用同一模数 `n`、两个不互素的指数 `e1/e2` 加密时，扩展欧几里得只能得到 `m^g mod n`（`g = gcd(e1,e2)`）而不是 `m`；对结果反复加 `n` 并开 `g` 次整数根，找到完全 `g` 次方即可恢复明文。本例先用 Wiener 从“大 e 小 d”恢复压缩包密码，再在重建的 docx 内用该变体解出 flag。

## 原理

- 共模攻击基础：`c1 = m^e1 mod n`、`c2 = m^e2 mod n`；由扩展欧几里得求 `s1·e1 + s2·e2 = g = gcd(e1,e2)`，于是 `c1^s1 · c2^s2 ≡ m^g (mod n)`。负指数用模逆/`powmod` 处理。
- 当 `g=1` 时直接得到 `m`；当 `g>1` 时得到的是 `m^g mod n`，即 `m^g - k·n` 对某个未知 `k`。由于明文（如 flag）通常远小于 `n`，`m^g` 本身可能小于 `n`，也可能被 `n` 回绕若干次。
- 恢复办法：令 `v = m^g mod n`，依次尝试 `v, v+n, v+2n, ...`，对每个候选做 `g` 次整数开根；若存在精确整数根 `r` 且 `r^g == v + k·n`，则 `r` 就是明文。`g` 越大，`m^g` 增长越快，通常只需少量 `k`。
- 本例 `e1=341=11×31`、`e2=209=11×19`，`g=11`，因此共模计算后得到 `flag^11 mod n`，再开 11 次根。
- Wiener 前置：RSA 参数文件中出现“e 与 n 同量级、d 很短”时，用 `e/n` 连分数收敛恢复 `d`（详见关联卡），得到下一层压缩包密码；这是多层 CTF 压缩包常见的“先解一层再拿下一层参数”结构。
- 包装层技巧：损坏的 zip 可用 WinRAR 修复；注释/备注常藏密码；docx 本质是 zip，缺 `_rels/.rels` 等文件时从其他目录补齐后重新压缩并改后缀即可打开。

## 触发条件

- 两组密文使用相同模数 `n`、不同公钥指数 `e1/e2`，且 `g = gcd(e1,e2) > 1`（普通共模脚本会因指数不互素而失败）。
- 攻击者已知 `n、e1、e2、c1、c2`，并能进行大整数开根与模幂运算。
- 明文相对模数较小，`m^g` 的回绕次数 `k` 可枚举（通常 flag 级别足够小）。
- 前置层可能是“大 e 小 d”的 RSA（Wiener）；需要先恢复上一层密码才能拿到共模参数。

## 利用步骤

1. 修复损坏的压缩包（WinRAR“修复”），查看注释/备注得到第一层密码；解压出含 RSA 参数（`n、e、c`，并提示 `d=short integer`）的文本。
2. 对第一层参数跑 Wiener：连分数展开 `e/n`，枚举收敛 `k/d`，用 `(e·d−1) % k == 0` 求 `φ` 与 `p+q`，判别式 `s²−4n` 为完全平方即恢复 `d`，解出下一层压缩包密码。
3. 解压第二层，识别其为 docx（zip 结构）；缺失的 `_rels/.rels` 等文件从第一层目录补齐，重新压缩并改后缀为 `.docx`，用 Word 打开得到第二组 RSA 参数（`m1=m2、e1、e2、n、c1、c2`）。
4. 计算 `g, s1, s2 = gcdext(e1, e2)`，求 `v = c1^s1 · c2^s2 mod n`，此时 `v = m^g mod n`。
5. 令 `cand = v`，循环：尝试整数 `g` 次根 `r`；若 `r^g == cand` 则明文为 `r`；否则 `cand += n` 继续。`g` 次根可用 `gmpy2.iroot` 或整数二分。
6. 把明文转字节；若字节序被反转（CTF 常见 `[::-1]`），反转后按 flag 格式校验。

## PoC

```python
import gmpy2

# e1=341, e2=209, gcd=11；c1/c2/n 为题目参数
g, s1, s2 = gmpy2.gcdext(e1, e2)
v = (pow(c1, int(s1), n) * pow(c2, int(s2), n)) % n   # v = m^g mod n

cand = v
while True:
    r, ok = gmpy2.iroot(cand, int(g))
    if ok:
        break
    cand += n

pt = bytes.fromhex(hex(int(r))[2:])
print(pt[::-1])   # 本例反转后得到 flag
```

```text
# 说明：若 g=1 则退化为普通共模攻击；g>1 时不能直接 long_to_bytes(v)。
# 前缀 "m1=m2=flag" 是关键前提；e1/e2 不互素时先算 gcd 再决定是否需要开根。
```

## 变体与关联

- 变体：`g=1` 的普通共模攻击，见 [[crypto-rsa-common-modulus]]；`g>1` 且 `k` 较大时，可结合明文格式/长度约束缩小枚举。
- 变体：低指数广播攻击也做“整数开根”，但模数不同，见 [[ctf-crypto-rsa-hastad-broadcast-e3-crt]]。
- 关联：[[crypto-rsa-wiener-small-private-exponent-large-e]]（大 e 小 d 连分数恢复私钥）、[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（小指数直接开根）、[[ctf-misc-broken-docx-zip-mtime-thumbnail-stego]]（docx/zip 结构修复思路）。
- 边界：`m^g` 的回绕次数随 `g` 与明文大小增长；若 `g` 很大或明文接近 `n`，枚举 `k` 可能不可行。参数必须满足 `m1=m2`（同一明文）且模数复用。

## 检测与防御

- 检测（CTF）：看到两组密文同 `n`、指数不同，先算 `gcd(e1,e2)`；`g>1` 时不要直接返回 `long_to_bytes(m)`，应转入开根流程；用 `iroot` 验证完全幂。
- 防御（真实 RSA）：禁止复用模数；每次生成独立密钥；使用 RSA-OAEP 等带随机化的填充，使相同明文产生不同密文。
- 加固（工程）：密钥生成后校验 `gcd(e, φ)=1` 与 `d` 的规模；不要把“大 e 小 d”的私钥用于生产。
