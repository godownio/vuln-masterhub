---
id: code-analysis-reverse-obfuscation-3des-192-ecb-key-from-username-zero-padded
title: 登录密码 3DES-192-ECB 且密钥由用户名补零派生：密钥可离线重建，抓包密文可解出明文密码
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: des3-ecb-key-username-zero-padded
tags:
- js-reverse
- frontend-encryption
- 3des
- des
- ecb
- key-derivation
- login
- traffic-decrypt
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V527
  verified_at: '2026-11-11T15:28:16+08:00'
  notes: 复验闭环（id 规范化后）：本卡由旧 id code-analysis-reverse-obfuscation-aes-ecb-key-from-username-zero-padded 更名而来。改名原因：复验时按截图核对发现算法实际是 3DES-192-ECB 而非 AES-192——图13 密文 sy9cWiUt/5U= 仅 8 字节（Base64 12 字符），AES 分组 16 字节不可能成立；本地用 pycryptodome 复算 DES3-192-ECB/PKCS7、key=wqew@163.com 补 0 至 24 字节对明文 eqwewq 加密恰得 sy9cWiUt/5U=（解密得 eqwewq\x02\x02），而同密钥 AES-192 得 EVURMQN1jUfl04It4U9IOA==、DES(8B) 与 2-key DES3(16B) 亦不匹配，前端函数名 DesencodeURIObject 亦为 DES 族佐证。主会话据修正后内容新建本 id 并将旧 id 卡 delete-card 移入回收站。现已复核本卡：id/标题/正文/PoC/technique/tags 均为 3DES-192，与原文 content.md 及全部 13 张截图一致；frontmatter 无禁用字段（cve 为空数组、未设 affected_versions、无 source 类字段）；dedup 候选均为 related/new 非同链；PoC 未对真实目标执行。保留。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-3des-192-ecb-key-from-username-zero-padded/
draft: false
kb_aliases:
- 用户名派生 3DES 密钥
- 3DES-192 ECB 密码解密
- userName 补零 key
- 登录密文解密验证
- 前端密码加密不可靠
---

## 一句话结论

当登录页用 3DES（Triple DES，192 位密钥、8 字节分组）ECB 加密密码、而密钥由「用户名 + 补零」派生到 24 字节时（本例 `wqew@163.com` 补 `0` 至 24 字节），密钥完全可由请求中明文可见的用户名重建，攻击者拿到任意抓包密文即可离线解出明文密码；ECB 的确定性还让相同明文块产生相同密文块。

## 原理

- **密钥派生公开可算**：密钥不是随机值，而是 `userName` 拼接固定填充字符 `0` 到 24 字节（192 位 3DES 的密钥长度）。用户名在登录请求里以明文提交，攻击者无需逆向混淆代码即可拼出密钥；若换用手机号/邮箱等公开字段，效果相同。前端函数名 `DesencodeURIObject` 也表明是 DES 族算法。
- **模式不安全**：3DES/ECB/PKCS#7 没有 IV，同一明文块永远加密成同一密文块；密文经 Base64 输出后再 URL 编码（`sy9cWiUt/5U=` → `sy9cWiUt%2F5U%3D`），且密文仅 8 字节（12 个 Base64 字符、8 字节分组），这是 DES/3DES 而非 AES（16 字节分组）的明显特征。
- **离线验证**：用密钥 `wqew@163.com000000000000`（用户名补 `0` 至 24 字节）、模式 ECB、填充 PKCS7 对明文 `eqwewq` 做 3DES 加密，得到 Base64 `sy9cWiUt/5U=`，与抓包 password 字段完全一致；解密该密文得到 `eqwewq\x02\x02`（PKCS7 去填充后为 `eqwewq`）。作为对照，同密钥 AES-192-ECB 加密结果为 `EVURMQN1jUfl04It4U9IOA==`（16 字节），与抓包不符，可排除 AES。
- **影响边界**：该加密方案只隐藏了「肉眼可见的明文」，不能防止抓包者解密；若其他敏感字段复用同一密钥，也可被解密甚至伪造。它本身不等于认证绕过——登录仍需知道明文口令，但已截获的凭据会被还原，且 ECB 无完整性保护、密文可重放。

## 触发条件

- 前端 JS 在提交前对密码（或其他敏感字段）做对称加密。
- 密钥由用户名/手机号/邮箱等已知字段拼接固定填充（如补 `0`、补空格、截断/重复）派生，而非随机或服务端下发。
- 使用 ECB 模式或固定 IV 的 CBC；攻击者能抓到登录请求（代理、日志、流量留存）。
- 若目标系统在日志/监控中留存了历史请求密文，可批量解密恢复口令。

## 利用步骤

1. 抓取登录请求，记录 `userName` 与 `password` 密文（注意 URL 解码后的 Base64）。
2. 按前端逻辑构造密钥：用户名 + 填充字符补到目标密钥长度（DES 8 字节、3DES 24 字节、AES 16/24/32 字节）；同时按密文块长判断算法族（8 字节块 → DES/3DES，16 字节块 → AES）。
3. 依次尝试 ECB 与常见填充（PKCS7/ZeroPadding），解出明文；用「重新加密结果等于原密文」验证参数正确。
4. 对同一系统的其他接口/历史流量复用同一密钥，评估泄露范围。
5. 只在授权测试中验证一条凭据即停止，不批量解密。

## PoC

```python
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad
import base64

user = b"wqew@163.com"
key = (user + b"0" * 24)[:24]            # 3DES-192：用户名补 0 到 24 字节
ct = base64.b64decode("sy9cWiUt/5U=")
pt = unpad(DES3.new(key, DES3.MODE_ECB).decrypt(ct), 8)
print(pt)  # b'eqwewq'
```

重新加密验证：`DES3.new(key, DES3.MODE_ECB).encrypt(pad(b"eqwewq", 8))` 得到相同 Base64 密文 `sy9cWiUt/5U=`（本地实测）。PoC 未在本机对真实目标执行。

## 变体与关联

- 变体：密钥取手机号后 8 位、`MD5(username)`、固定前缀 + 用户名、或用户名重复/截断填充；模式可为 CBC + 全零 IV；算法族可为 DES/3DES 或 AES（按密文块长 8/16 字节区分）。
- 变体：同一套前端加密用于请求签名，则密钥泄露后可伪造「合法」请求。
- 关联：[[front-end-hardcoded-aes-ecb-traffic-decrypt]]（硬编码密钥变体）、[[code-analysis-reverse-obfuscation-js-aes-zeropadding-authorization-key]]（key/iv 来源与填充对齐）、[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（混淆代码中还原 AES 参数）、[[code-analysis-reverse-obfuscation-async-stack-promise-encryption-locate]]（定位加密点的方法）。

## 检测与防御

- 不要把密钥从用户名等公开字段派生；前端加密无法提供保密性，真正的保护应由 TLS 承担。
- 避免 ECB；DES/3DES 本身已过时且分组仅 8 字节，必须加密时使用带随机 IV 的 AEAD（AES-GCM）并绑定上下文，防止重放与块重排。
- 服务端不要记录密码密文/明文日志；认证使用不可逆哈希（Argon2/bcrypt/scrypt）或 PAKE（SRP/OPAQUE）方案，口令永远不以可解密密文形式传输。
- 检测：前端 JS 中出现 `userName` 拼接固定字符作为 key 的模式；登录请求密码字段 Base64 长度固定且相同口令密文相同（ECB 特征）。
