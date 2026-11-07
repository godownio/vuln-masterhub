---
id: crypto-aes-ecb-byte-at-a-time-hidden-suffix-oracle
title: AES-ECB 字节恢复 Oracle：可控前缀 + 固定隐藏后缀逐字节还原水印
type: scenario
domain: crypto
path: crypto/aes
technique: aes-ecb-byte-at-a-time-hidden-suffix-oracle
aliases:
- ECB byte-at-a-time
- ECB Oracle
- AES-ECB 逐字节恢复
- 隐藏后缀 oracle
- 数字水印泄露
tags:
- aes
- ecb
- oracle
- chosen-plaintext
- byte-at-a-time
- web
- credential-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:08:45+08:00'
  notes: 已对照原文 SecureDoc 段核对：total_length=输入+82、16 字节块、A*15 逐字节恢复、水印含 suP3r@dm!n/S3cur3P@ssZWRjMGI0! 均一致；PoC 未本机复跑；原文未标注组件版本。
---

## 一句话结论

当 Web 接口把用户可控内容与固定隐藏后缀拼接后用 AES-ECB 加密并返回密文时，攻击者可以用“可控前缀 + 已知明文 + 候选字节”构造选择明文，比较目标块的密文是否一致，逐字节恢复隐藏后缀（如管理员账号密码、水印、token）。

## 原理

- ECB 模式对每个 16 字节块独立加密，相同明文块得到相同密文块，且不隐藏块边界；这是字节恢复攻击的前提。
- 服务端计算 `AES_ECB(user_input || secret)`，用户输入长度可控。攻击者先发送 `A * (15 - offset)`，使目标块的最后 1 字节落在 secret 的第 1 个未知字节上，记录该块密文 `C_target`。
- 然后枚举候选字符 `c`，发送 `A * (15 - offset) + known + c`；若某个候选使目标块与 `C_target` 相同，说明 `c` 就是 secret 的下一个字节。固定前缀使已知部分对齐，逐字节推进即可恢复整个 secret。
- 隐藏内容长度可由 `total_length = 输入长度 + 固定长度` 推断；块大小可由长度增长步长（16）确认。
- 为什么可行：ECB 是确定性加密，攻击者拥有加密 oracle（任意明文→密文）且能观察到块级相等关系；不需要密钥，也不需要解密 oracle。
- 若服务端使用 CBC/CTR/GCM、随机 IV、每次加密加随机前缀，或只返回长度不返回密文，则本攻击不成立。

## 触发条件

- 加密接口使用 AES-ECB（或任何确定性、无随机化的块加密），且把用户输入与固定秘密拼接。
- 攻击者可控制输入前缀/长度，接口返回完整密文（或至少目标块的密文）。
- 知道或能推断块大小与秘密长度；秘密字符集可枚举。
- 接口可高频调用（每次恢复 1 字节需要最多 |charset| 次请求）。

## 利用步骤

1. 注册/登录普通账号，找到加密预览接口（如 `/documents/apply-template`），提交不同长度的 `content`。
2. 观察 `total_length` 随输入长度的变化：差值即固定隐藏内容长度（原文为 82 字节），增长步长即块大小（16）。
3. 发送 `A * 15`，记录密文中目标块（secret 起始所在块）的十六进制。
4. 对 secret 的每个位置：
   - 计算 padding，使目标块最后 1 字节为未知字节；
   - 记录该块密文；
   - 枚举字符集，构造 `padding + recovered + candidate`，比较目标块密文；
   - 命中则固定该字符，进入下一位。
5. 恢复完整隐藏内容后，解析其中的账号/密码/token，登录更高权限账户。
6. 若字符集未知，可先恢复长度和可见字符，再用二分/分组扩大字符集。

## PoC

```python
import requests, string

BASE = "http://target"
s = requests.Session()
s.post(f"{BASE}/login", json={"username": "u", "password": "p"})

def oracle(content):
    r = s.post(f"{BASE}/documents/apply-template", json={"content": content})
    p = r.json()["preview"]
    return bytes.fromhex(p["encrypted_content"]), p["total_length"]

secret_len = oracle("")[1]          # 固定隐藏后缀长度
recovered = ""
for i in range(secret_len):
    pad = "A" * (16 - 1 - (len(recovered) % 16))
    target = oracle(pad)[0]
    block = (len(recovered) // 16) * 16
    target_block = target[block:block + 16]
    for c in string.printable:
        probe = pad + recovered + c
        if oracle(probe)[0][block:block + 16] == target_block:
            recovered += c
            break
print(recovered)
```

说明：PoC 为原文脚本的结构化精简，未在本机执行；仅用于授权测试。原文恢复出的隐藏水印包含管理员用户名与密码。

## 变体与关联

- 变体（前缀/后缀位置）：secret 在输入之前时用后缀 padding；secret 在中间时用两侧 padding；可用已知明文块做对齐。
- 变体（字符集）：先恢复可打印字符，再对二进制/UTF-8 字节做分组或逐字节枚举；长度未知时先做长度探测。
- 变体（ECB 其他利用）：块重排/剪切拼接、块删除、跨用户密文复用；本卡是“字节恢复”方向。
- 关联：[[crypto-aes-cbc-padding-oracle-certificate-service]]（CBC 填充 oracle 的同类逐字节恢复）；[[crypto-aes-fixed-key-ecb-ciphertext-reproduce]]（固定 key/ECB 的密文复现）。
- 边界：AEAD/随机 IV/随机前缀、只返回布尔不返回密文、限速严格或秘密长度不可控时，本攻击不成立。

## 检测与防御

- 检测：同一账号对加密预览接口的高频、逐字符递增的请求；请求体中出现大量重复填充字符（`AAAA...`）；响应密文长度/块边界被频繁比较。
- 防御：不要用 ECB 加密含秘密的用户可控数据；改用 AES-GCM 或 AES-CBC + 随机 IV + HMAC。
- 加固：不要把秘密与用户输入拼接后加密；不要向用户返回密文或块级长度；对加密接口限速并记录异常模式；秘密使用独立密钥/HSM 保护。
