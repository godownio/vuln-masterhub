---
id: crypto-implementation-elgamal-private-key-debug-log-leak
title: ElGamal 长期私钥出现在 DEBUG 日志：恢复共享秘密并解密任意密文
type: scenario
domain: crypto
path: crypto/implementation
technique: elgamal-private-key-debug-log-leak
aliases:
- ElGamal 私钥泄露
- DEBUG 日志打印私钥
- 共享秘密恢复
- ElGamal 解密
- 调试信息泄露
tags:
- crypto
- elgamal
- key-leak
- debug-log
- decryption
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V106
  verified_at: '2026-11-05T22:27:00+08:00'
  notes: 已对照原文与图10核对：DEBUG 日志泄露 ElGamal 私钥 x、验证 pow(g,x,p)==y、s=c1^x、m=c2*s^-1 恢复 flag，公式与步骤均正确；CTF 题，无产品版本；PoC 为等价 Python 脚本未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

ElGamal 的安全性完全依赖长期私钥 `x` 的保密；服务端把 `x` 直接打印进 DEBUG 日志后，任何能读到日志的人都能对任意密文计算共享秘密 `s = c1^x mod p`，进而还原明文 `m = c2 · s^(-1) mod p`，无需破解离散对数。

## 原理

- ElGamal 参数：模数 `p`、生成元 `g`、私钥 `x`，公钥 `y = g^x mod p`。
- 加密：选择随机数 `k`，密文 `c1 = g^k mod p`、`c2 = m · y^k mod p`。
- 解密的关键是共享秘密 `s = c1^x = g^(xk) = y^k mod p`；拿到私钥 `x` 后，`s` 可以直接算出，再求模逆得到明文。
- 私钥泄露的路径是“实现缺陷”而不是算法弱点：调试日志、异常堆栈、配置 dump、环境变量或备份文件把 `x` 写到了低权限可读的位置。日志常被采集到 ELK/SIEM、开发者本地或对象存储，读取面远大于密钥管理系统。
- 验证泄露的 `x` 是否正确：计算 `pow(g, x, p) == y`。成立后用同一组参数解任意截获的密文，不需要知道随机数 `k`。

## 触发条件

- 服务端/CTF 题目的 DEBUG 日志、错误输出或附件中包含 ElGamal 私钥 `x`；
- 攻击者能读取该日志（日志平台权限、公开附件、目录遍历、备份泄露等）；
- 同时能获得目标密文 `(p, g, y, c1, c2)` 或附件输出文件。

## 利用步骤

1. 从 DEBUG 日志/附件中提取 `p`、`g`、`y`、`x`，以及密文 `c1`、`c2`。
2. 验证私钥：`pow(g, x, p) == y`；不成立则可能是参数不匹配或 `x` 被截断。
3. 计算共享秘密 `s = pow(c1, x, p)`。
4. 求 `s` 在模 `p` 下的逆元 `s_inv = pow(s, -1, p)`（Python 3.8+ 支持三参数 `pow`；旧版本用扩展欧几里得）。
5. 还原明文整数 `m = c2 * s_inv % p`，再转字节串（注意大端序与可能的填充）。
6. 若明文仍有编码/压缩/填充，按题目/协议继续解码；CTF 中通常直接得到 flag。

## PoC

```python
from Crypto.Util.number import long_to_bytes

# 从 DEBUG 日志/附件读取
p = ...
g = ...
y = ...
x = ...          # 泄露的长期私钥
c1 = ...
c2 = ...

# 1. 验证私钥
assert pow(g, x, p) == y, "x 与公钥不匹配"

# 2. 共享秘密与模逆
s = pow(c1, x, p)
s_inv = pow(s, -1, p)

# 3. 还原明文
m = (c2 * s_inv) % p
print(long_to_bytes(m))
```

原文实测：验证 `pow(g, x, p) == y` 成立后，按上述步骤从 `output.txt` 恢复出明文 flag。

## 变体与关联

- 变体：私钥出现在异常堆栈、`repr()` 对象、配置 dump、环境变量、CI 日志或备份文件中；读取面不同，恢复步骤相同。
- 变体：只泄露私钥的一部分时，可结合离散对数/格方法尝试恢复，但超出本卡范围。
- 关联 [[crypto-implementation-5g-aka-xres-star-log-leak]]：同属“日志泄露密钥材料”的实现缺陷，可对照日志采集面的排查思路。
- 关联 [[crypto-rsa-common-modulus]]：同属“拿到额外数学关系即可恢复明文”的密码学攻击，区别是 RSA 共模利用两个模数相同的密文，本卡利用私钥泄露。
- 边界：若日志已轮转/清理、私钥未真正泄露、或密文使用了不同的 `p/g/y` 参数，本方法不成立；读取日志本身也需要相应权限。

## 检测与防御

- **禁止记录私钥**：日志、异常、监控、APM 中不得出现私钥、共享秘密、会话密钥；对敏感变量使用结构化日志的脱敏字段。
- **日志治理**：DEBUG 级别默认关闭；日志平台按最小权限授权；对包含长整数/密钥形态的日志做正则扫描与告警。
- **密钥管理**：私钥放 KMS/HSM 或受控配置文件，不进入应用日志与镜像；定期轮换；怀疑泄露后立即更换密钥并重加密。
- **检测**：搜索历史日志中的私钥打印；监控异常的大量解密请求；对 ElGamal 参数与公钥做一致性校验，发现 `x` 泄露痕迹及时处置。
