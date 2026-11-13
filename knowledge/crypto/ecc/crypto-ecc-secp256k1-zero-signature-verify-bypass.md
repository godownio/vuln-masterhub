---
id: crypto-ecc-secp256k1-zero-signature-verify-bypass
title: secp256k1 签名验证未校验 r/s 非零：全零签名使 point=O、O.x=0=r 恒等通过
type: scenario
domain: crypto
path: crypto/ecc
technique: ecdsa-zero-signature-point-at-infinity-verify-bypass
aliases:
- 全零签名绕过
- r=s=0 签名
- 零值签名验证绕过
- point at infinity verify bypass
- 签到签名伪造
- secp256k1 验证缺陷
tags:
- crypto
- ecdsa
- secp256k1
- zero-signature
- signature-bypass
- point-at-infinity
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V568
  verified_at: '2026-11-12T09:16:59+08:00'
  notes: 已对照原文12937及全部21张图逐张核对：图21 verify源码（r,s=int(signature[:64],16),int(signature[64:],16); s_inv=pow(s,q-2,q); u1=(z*s_inv)%q; u2=(r*s_inv)%q; point=u1*G+u2*self.P; return point.x==r）与卡片缺陷逻辑一致；图20 发送128个0后返回Hello xenny!与flag DASCTF{...}，host 1.14.108.193:30406一致。已修正两处表述：r/s 应为各64个hex字符(32字节)而非64字节；Hello xeny→Hello xenny。dedup最接近的CVE-2022-21449 JWT Web卡为不同实现/场景，无同链，无需删除。原文无受影响版本，未设versions。
---

## 一句话结论

自定义 ECDSA 验证实现只做 `point = u1*G + u2*P; return point.x == r` 而不校验 `r,s ∈ [1,q-1]`、也不判断 `point` 是否为无穷远点 O 时，提交 `r=s=0` 的签名会让 `s_inv=0`、`u1=u2=0`、`point=O`，而 O.x 在实现中为 0，恰好等于 r，验证恒真，从而伪造任意消息的签名通过校验。

## 原理

- **验证公式**：标准 ECDSA 验证计算 `u1 = z*s_inv mod q`、`u2 = r*s_inv mod q`、`point = u1*G + u2*P`，要求 `point.x mod q == r`，并且必须先检查 `r,s` 在 `[1, q-1]` 内。
- **零值输入**：取 `r = s = 0` 时 `s_inv = pow(0, q-2, q) = 0`（q 为素数），于是 `u1 = 0`、`u2 = 0`，`point = 0*G + 0*P` 是椭圆曲线群单位元——无穷远点 O。
- **无穷远点的 x 值**：很多自实现点类把 O 的 x 坐标初始化为 0（或直接复用 `(0,0)`），于是 `point.x == r` 变成 `0 == 0`，条件成立，`verify` 返回 True。
- **为什么成立**：标准要求 r、s 非零且 point 不是 O，就是为了杜绝这种退化；实现省掉这两个前置检查后，攻击者不需要私钥、不需要计算离散对数，直接填全零即可通过任意消息的验证。
- **同源案例**：CVE-2022-21449（Java ECDSA "Psychic Signatures"）即 ECDSA 验证未检查 r/s 为零，与本卡同一原理（本卡目标为 Python 自实现/CTF 题）。

## 触发条件

- 目标使用自实现（或缺陷库）的 ECDSA 验证，未校验 r、s 范围与无穷远点；
- 攻击者可提交任意签名（如通过 socket/API 的签名校验接口）；
- 签名解析为固定长度的 r||s（本卡为 128 个 hex 字符，即 r、s 各 64 个 hex 字符/32 字节）。

## 利用步骤

1. 获取/反编译 verify 源码，确认没有 `r != 0 and s != 0`、`point != O` 的检查（原文输入 `2` 取 flag 时拿到部分源码）。
2. 构造签名：`r=0`、`s=0`，按接口要求编码（本题为 128 个 `0` 字符）。
3. 把签名提交给签名校验/取 flag 接口，验证通过后直接获得 flag/权限。
4. 若接口还校验其他参数（z/消息），全零签名与消息内容无关，任意消息均可通过。

## PoC

```python
from pwn import *
context.log_level = 'debug'
r = remote('1.14.108.193', 30406)
r.sendlineafter(b'4. exit', b'2')
# 签名校验接口要求 r||s 共 128 个 hex 字符（各 32 字节）；全零
r.sendlineafter(b'sign:', b'0' * 128)
# 服务端返回 "Hello xenny!" / flag
print(r.recvall())
```

```text
# 原始 verify 关键逻辑（有缺陷）
r, s = int(signature[:64], 16), int(signature[64:], 16)
s_inv = pow(s, secp256k1.q - 2, secp256k1.q)
u1 = (z * s_inv) % secp256k1.q
u2 = (r * s_inv) % secp256k1.q
point = u1 * secp256k1.G + u2 * self.P
return point.x == r          # r=s=0 时 point=O，O.x=0，0==0 恒真
```

## 变体与关联

- 变体：只校验 r 非零不校验 s（或反之）、校验范围用 `0 <= r < q`（应为 `1 <= r <= q-1`）、点类把 O 表示为 `(0,0)` 且未拒绝。
- 关联：CVE-2022-21449 Psychic Signatures 的 Web/JWT 版本 [[ctf-web-ecdsa-zero-signature-jwt-thymeleaf-template-overwrite]]（不同实现/场景，同一零值原理）。
- 变体：其它签名方案（Schnorr/EdDSA）同样可能因未校验标量范围或单位元而退化；审计时先看前置校验。

## 检测与防御

- 检测：代码审计检查 ECDSA 验证是否在计算前校验 `r,s ∈ [1,q-1]`、`point` 非无穷远点；测试用例加入全零、全 q-1、单零签名。
- 防御：使用标准库（cryptography/OpenSSL/BoringSSL）并保持更新；自实现时严格按 SEC1/ANSI X9.62 流程；禁止 O 点参与输出，`r=0`/`s=0` 一律拒绝。
