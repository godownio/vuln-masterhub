---
id: web-generic-auth-cookie-cbc-bitflip-iv-first-block-role-forgery
title: 加密 Cookie 的 CBC 位翻转：改 IV 控制首块明文，role=guest 伪造为 role=admin
type: scenario
domain: web
path: web/generic/auth/cookie
technique: cbc-bitflip-iv-first-block-role-forgery
tags:
- web
- cookie
- session
- cbc
- bitflip
- iv
- identity-forgery
- crypto
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:52:07+08:00'
  notes: 已对照原文「cryweb」核对并修正卡片分块描述：name=A 时明文 uid=1001&name=A&role=guest&level=1 的首块为 uid=1001&name=A&（16 字节，原文常量多写了一个 r 但循环只取前 16 字节），第二块为 role=guest&level；改 IV 将首块替换为 role=admin&name= 后总明文 role=admin&name=role=guest&level=1，parse_str 解析出 role=admin。原卡把 role=guest 误写为首块内容，已同步 knowledge 与 staging 修正；PoC 逻辑不变。未复跑；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/cookie/web-generic-auth-cookie-cbc-bitflip-iv-first-block-role-forgery/
draft: false
kb_aliases:
- CBC 位翻转攻击
- IV 篡改伪造 Cookie
- 加密票据身份伪造
- role=admin 位翻转
- 加密不等于签名
---

## 一句话结论

服务端把用户身份序列化后用 AES-CBC 加密放进 Cookie，但没有做签名/MAC；攻击者拿到自己的合法票据后，只需按 CBC 解密公式 `P[0] = D(C[0]) XOR IV` 修改 IV 的对应字节，就能把 16 字节首块替换为 `role=admin&name=`，且不会破坏其他块；解密后的总明文变为 `role=admin&name=role=guest&level=1`，解析后得到管理员角色，从而伪造身份。

## 原理

- **加密不等于完整性**：CBC 只提供机密性，不提供认证。服务端解密后直接反序列化/解析身份字段，没有校验密文是否被篡改，也没有 HMAC/签名。
- **CBC 解密公式**：`P[i] = D(C[i]) XOR C[i-1]`，其中 `C[-1] = IV`。`D(C[i])` 是黑盒，但前一块密文（或 IV）完全由攻击者控制。
- **位翻转的可控性**：修改 `C[i-1]` 的第 j 个字节，`P[i]` 的第 j 个字节会同步异或同样的差值：想让 `g` 变 `a`，把 `C[i-1][j]` 异或上 `g XOR a` 即可，不需要密钥。
- **副作用权衡**：修改 `C[i-1]` 会让 `P[i-1]` 变成不可预测的乱码（因为 `D(C[i-1])` 已变）；而修改 IV 只影响 `P[0]`，IV 不参与任何其他块的解密输出，因此改 IV 是“零副作用”控制首块的最佳位置。
- **首块可控的前提**：攻击者知道自己的明文首块（登录后服务端下发的票据可反推/可预测），且替换后的首块与已知首块长度相同（本题均为 16 字节）；本题把 `role=admin&name=` 放到首块，原第二块开头的 `role=guest` 成为 `name` 参数值的一部分，因此最终查询串仍能解析出 `role=admin`。
- **为什么能接管后台**：服务端解密后按 `role=admin` 做权限判断，攻击者用伪造 Cookie 访问 `/admin.php` 即获得管理员权限。

## 触发条件

- Cookie/票据是 AES-CBC 加密（常见结构 `base64(IV || ciphertext)`），没有签名或 MAC。
- 服务端解密后直接信任其中的身份字段（role/is_admin/uid 等）。
- 攻击者能获得一份合法票据（注册/登录即可），并知道或能推断首块明文格式。
- 需要伪造的字段与已知字段长度一致，或可通过调整可控字段（如用户名）对齐块边界。

## 利用步骤

1. 用自己的账号登录，拿到 Cookie/票据；Base64 解码，取前 16 字节为 IV、其余为密文。
2. 推断明文分块：本题登录后身份为 `uid=1001&name=ctfer&role=guest&level=1`；用单字符用户名 `A` 时总明文为 `uid=1001&name=A&role=guest&level=1`，首块 16 字节为 `uid=1001&name=A&`，第二块为 `role=guest&level`。
3. 确定目标首块：`role=admin&name=`，长度同为 16 字节。
4. 逐字节计算 `IV'[i] = IV[i] XOR known_p0[i] XOR target_p0[i]`。
5. 重新拼接 `IV' || ciphertext` 并 Base64（注意 URL-safe/填充与目标一致）。
6. 用伪造 Cookie 访问管理员接口（如 `/admin.php`），服务端解密得到首块 `role=admin&name=`、第二块仍为 `role=guest&level`，总明文 `role=admin&name=role=guest&level=1` 解析出 `role=admin`。
7. 若目标字段不在首块，改前一块密文 `C[i-1]`，接受 `P[i-1]` 变乱码的代价；必要时把乱码字段放在不参与校验的位置。

## PoC

```python
import base64, urllib.parse, urllib.request, re

def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')

def forge_p0(ticket, known_p0, target_p0):
    raw = base64.urlsafe_b64decode(ticket + '=' * (-len(ticket) % 4))
    iv = bytearray(raw[:16])
    for i in range(16):
        iv[i] ^= known_p0[i] ^ target_p0[i]
    return b64u(bytes(iv) + raw[16:])

KNOWN  = b'uid=1001&name=A&'
TARGET = b'role=admin&name='
forged = forge_p0(ticket, KNOWN, TARGET)
```

原文用登录名 `A` 得到首块 `uid=1001&name=A&`（原文常量写成 `uid=1001&name=A&r`，但循环只取前 16 字节），替换为 `role=admin&name=` 后访问 `/admin.php` 成功拿到 flag；未在本机复跑。

## 变体与关联

- **非首块**：改 `C[i-1]` 控制 `P[i]`，代价是 `P[i-1]` 乱码；可把被破坏的字段选为无关字段（如 name/level）。
- **IV 不可控**：若 IV 不在 Cookie 内而是服务端固定，则只能改密文块，需要接受前块乱码。
- **结构变体**：CBC 之外还有 CTR/CFB 的位翻转（改密文直接翻转对应明文位，无扩散）、GCM 若 nonce 可控也可能伪造，但 GCM 有 tag 时应优先检查 tag 校验。
- **关联**：[[web-generic-auth-myblog-hardcoded-aes-cookie-forgery]]（密钥泄漏型伪造）、[[web-java-framework-shiro-721-padding-oracle]]（CBC+Padding Oracle 伪造）；本卡是“知道明文 + 无签名”的纯位翻转，不需要密钥或 Padding Oracle。

## 检测与防御

- 加密必须搭配完整性保护：使用 AES-GCM/ChaCha20-Poly1305 等 AEAD，或 encrypt-then-MAC（HMAC-SHA256）。
- 服务端不要直接信任 Cookie 中的身份字段；会话状态存服务端，Cookie 只放不可猜测的会话 ID。
- 若必须用 CBC，校验 HMAC 后再解密，并拒绝长度/结构异常的票据。
- 检测：Cookie 长度不变但解密后字段异常、同一会话出现多个 role、IV 高频变化且首块明文与用户不符、管理员接口来自普通用户会话。
