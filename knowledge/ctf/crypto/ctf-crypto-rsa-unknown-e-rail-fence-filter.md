---
id: ctf-crypto-rsa-unknown-e-rail-fence-filter
title: RSA 未知指数 e：小范围暴力解密 + 明文字符集筛选 + 栅栏还原
type: scenario
domain: ctf
path: ctf/crypto
technique: rsa-unknown-e-bruteforce-railfence-filter
aliases:
- 栅栏里的保险箱
- RSA 未知 e
- 遍历 e 解密
- 明文字符集筛选
- 栅栏密码还原
- yafu 分解 n
tags:
- ctf
- crypto
- rsa
- unknown-exponent
- brute-force
- rail-fence
- yafu
- plaintext-filter
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:44:12+08:00'
  notes: 已对照原文与图11/12/13核对：p/q/c 数值、yafu 20.0055秒分解、e=23537、筛选字符 f/l/a/g/{/}、解出 f513lb9f22}a1a161gfe1f9{74ac82cc27cf23、随波逐流栅栏还原均一致；已将卡内 n 规模修正为 334位（十进制101位），zigzag 栅栏解码实测 rails=7 得 flag{2fc7f1b59ae4c22a11f126fc73c89123}。未验证点：PoC 未本机跑完整 1100万次循环（用 sympy 替代 gmpy2）；栅栏具体实现以随波逐流为准；非组件漏洞无版本；frontmatter无sources/source_url。
---

## 一句话结论

当 RSA 题只给出 n、c、p、q 而公钥指数 e 未知时，先分解 n 得到 φ(n)，在小范围内遍历 e 并用 `m = c^d mod n` 解出候选明文，再用“必须包含 flag 字符集且可打印”过滤误报；若明文还经过栅栏换位，对候选枚举栏数还原即可得到 flag。

## 原理

- RSA 解密需要私钥 d = e⁻¹ mod φ(n)。e 未知时，若 e 的取值空间很小（小整数或常见值），可以逐个尝试：只有正确的 e 才会把 c 解成有意义的明文，错误 e 得到的是伪随机字节。
- 仅靠“可打印”过滤不够：错误 e 也可能偶然产生可打印字符串。题目明文格式提供了强约束——flag 一定包含 `f`、`l`、`a`、`g`、`{`、`}` 六个字符，长度也有限，因此可以要求解密结果同时可打印且字符集覆盖这六个字符。
- 本题明文在 RSA 加密前还做过栅栏换位，所以正确 e 解出的是一段“字符齐全但顺序错乱”的栅栏密文（`f513lb9f22}a1a161gfe1f9{74ac82cc27cf23`）；再枚举栏数做栅栏解密，重排成 `flag{...}`。
- 为什么成立：RSA 解密是确定性的，e 的遍历成本远低于分解 n；格式约束把 1..1.1e7 的候选压缩到唯一。分解 n 本身可用 yafu/ECM/Pollard rho，本题的 n 为 334 位（十进制 101 位），yafu 约 20 秒即可分出 p、q。

## 触发条件

- 已知 n、c，以及 p、q 或能分解的 n；e 未知但范围有限（常见 3/17/65537 先试，再小范围遍历）。
- 明文有已知格式（flag 前缀/字符集）或长度约束，可用于过滤错误 e。
- 明文可能叠加了换位/替换等可逆编码，需要在 RSA 解密后再还原。

## 利用步骤

1. 用 `yafu factor(n)` 或 `sympy.factorint(n)` 分解 n，验证 `p*q == n`，计算 `phi = (p-1)*(q-1)`。
2. 先尝试常见 e（3、17、65537）；不中则从 1 开始遍历，计算 `d = inverse(e, phi)`、`m = pow(c, d, n)`，转成字节。
3. 过滤候选：`long_to_bytes(m)` 可 UTF-8 解码、可打印、长度合理，且包含 `f/l/a/g/{/}` 六个字符。
4. 对候选明文枚举栅栏栏数 2..len（或交给 CyberChef/随波逐流），寻找 `flag{...}` 格式。
5. 验证 flag 内容并提交；若仍有多解，增加语言模型/词频/已知前缀等约束。

## PoC

```python
from Crypto.Util.number import long_to_bytes
from sympy import mod_inverse

p = 475983529392229563986300263627
q = 50994851324392722608175048292980313487272936248176620246821369736608473
c = 14357527460442347355096404625497793506543049498914015672502337590355030280127374107997576931872991169
n, phi = p * q, (p - 1) * (q - 1)
need = set("flag{}")

for e in range(1, 11_000_001):
    try:
        d = mod_inverse(e, phi)
    except ValueError:
        continue
    pt = long_to_bytes(pow(c, d, n))
    try:
        s = pt.decode()
    except UnicodeDecodeError:
        continue
    if s.isprintable() and need.issubset(set(s)):
        print(e, s)   # e=23537 -> f513lb9f22}a1a161gfe1f9{74ac82cc27cf23
```

```python
# 栅栏还原：枚举栏数，按行填充后按列读出
def rail_decode(s, rails):
    rows = [""] * rails
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    idx = [pattern[i % len(pattern)] for i in range(len(s))]
    counts = [idx.count(r) for r in range(rails)]
    pos = 0
    for r in range(rails):
        rows[r] = s[pos:pos + counts[r]]
        pos += counts[r]
    out, ptr = [], [0] * rails
    for r in idx:
        out.append(rows[r][ptr[r]])
        ptr[r] += 1
    return "".join(out)

for rails in range(2, len(candidate)):
    print(rails, rail_decode(candidate, rails))
```

## 变体与关联

- 变体：e 很大但 d 很小时用 Wiener 连分数攻击；同一 m 用多个小 e 加密时用 Håstad 广播；共享素数用批量 GCD。
- 变体：n 无法直接分解时，先查 factordb、用 ECM/Pollard p-1/二次筛；p、q 距离近时用 Fermat 分解。
- 变体：过滤条件可换成已知前缀、Base64 字符集、JSON/XML 结构、语言词频；换位可换成列置换、栅栏、螺旋读序。
- 关联：[[ctf-crypto-rsa-structured-prime-class-group-factor]]（特殊素数直接分解 n）、[[ctf-crypto-rsa-noncoprime-common-modulus-iroot-wiener-chain]]（e/d 相关攻击）、[[ctf-crypto-rsa-shared-prime-batch-gcd]]（共享素数）。
- 边界：e 的搜索空间过大时暴力不可行；错误 e 可能产生多个可打印候选，需要更强格式约束；栅栏栏数未知时要全枚举并人工判断。

## 检测与防御

- **检测（CTF）**：题目只给 n/c/p/q 或提示“钥匙很多/保险箱”，先尝试常见 e，再小范围遍历并用 flag 字符集过滤；解出乱序明文后优先尝试栅栏/列换位。
- **修复（真实设计）**：RSA 公钥必须公开且使用标准 e（65537）；不要依赖 e 的保密性；密钥生成使用标准库并校验素数随机性。
- **加固**：私钥存储与运算做常量时间/盲化；对异常 e（过小、过大、非标准）在证书/协议解析层告警；不要使用可预测结构或弱随机素数。
