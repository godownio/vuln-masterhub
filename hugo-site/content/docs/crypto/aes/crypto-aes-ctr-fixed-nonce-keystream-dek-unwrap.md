---
id: crypto-aes-ctr-fixed-nonce-keystream-dek-unwrap
title: KMS 固定 nonce AES-CTR：import_dek(全零) 泄露 keystream 还原被包装 DEK
type: scenario
domain: crypto
path: crypto/aes
technique: aes-ctr-fixed-nonce-keystream-dek-unwrap
tags:
- crypto
- aes
- ctr
- fixed-nonce
- keystream
- kms
- dek
- aes-gcm
- ssrf
- path-traversal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:46:17+08:00'
  notes: 已对照原文第5节 Web/KMS 部分核对：Apache 2.4.49 /assets/.%2e 路径穿越读 httpd.conf、/app/web/app.py、/app/kms/app.py；SSRF 仅校验 netloc 字符串，整数 IP 2130706433=127.0.0.1 绕过；KMS 使用 AES.MODE_CTR、KEK 启动时生成一次、STATIC_NONCE=b'DataVaul'；import_dek(00...00) 返回 keystream，old_dek=enc_dek XOR S，再以 nonce/tag 做 AES-GCM 解密 snapshot 的 enc_data。未验证点：CTF 环境接口/字段随题变化，未复跑；无 CVE/受影响版本；frontmatter 无 sources/source_url。
url: /docs/crypto/aes/crypto-aes-ctr-fixed-nonce-keystream-dek-unwrap/
draft: false
kb_aliases:
- KMS DEK 包装 keystream 泄露
- fixed nonce AES-CTR
- import_dek(0) 泄露密钥流
- AES-GCM 备份解密
- 整数 IP SSRF 打 KMS
---

## 一句话结论

KMS 用固定 key + 固定 nonce 的 AES-CTR 包装 DEK，并提供 `import_dek` 接口对任意 DEK 做 CTR 加密；攻击者提交全零 DEK 即可拿到完整 keystream，与备份中的 `enc_dek` 异或还原真实 DEK，再用它解密 AES-GCM 备份，形成“路径穿越读源码 → 整数 IP SSRF 打 KMS → keystream 泄露 → 备份解密”的完整链。

## 原理

- AES-CTR：`C = P XOR S`，`S` 是 key 与 nonce 生成的 keystream。若 key 与 nonce 固定，任意相同长度的输入都复用同一条 `S`。
- KMS 的 `import_dek(dek)` 对传入 DEK 做 CTR 加密并返回；攻击者传 32 字节全零，得到 `C = 0 XOR S = S`，即 keystream 本身。
- 备份接口返回 `enc_dek = old_dek XOR S`；攻击者计算 `old_dek = enc_dek XOR S`，恢复被包装的旧 DEK。
- 备份的 `enc_data` 由 `old_dek` 做 AES-GCM 加密，`nonce`/`tag` 同接口返回；用恢复的 DEK 解密并校验 tag，即可得到明文。
- 前置条件通过两个 Web 缺陷获得：Apache 2.4.49 的 `/assets/.%2e/.%2e/...` 路径穿越读取 `httpd.conf`/`app.py`/KMS 源码；SSRF 白名单只匹配 `netloc` 字符串，整数形式 `2130706433`（=127.0.0.1）绕过并访问内网 KMS。
- 根因是“密钥包装使用可预测 nonce + 提供加密 oracle + 备份接口暴露包装后的 DEK”，三者叠加使 CTR 的密钥流复用从理论变成可利用。

## 触发条件

- KMS/密钥服务使用 AES-CTR（或流式模式）包装 DEK，key 固定、nonce 固定/可预测，且同一 key/nonce 下允许攻击者提交任意明文获取密文。
- 存在 `import_dek`/`wrap`/`encrypt` 类接口，攻击者可控制输入并拿到输出；接口可通过 SSRF/内网访问到达。
- 备份/快照接口返回 `enc_dek`、`enc_data`、`nonce`、`tag`，且 `enc_dek` 是用同一 keystream 包装的。
- 攻击者能读到 KMS/Web 源码或配置，确认算法、nonce、接口路径；或通过错误/长度推断。
- 目标可被路径穿越/源码泄露/SSRF 等前置漏洞触及；KMS 与 Web 服务在同一内网可达。

## 利用步骤

1. 通过 Apache 2.4.49 路径穿越读取 `httpd.conf`、`supervisord.conf`、`/app/web/app.py`、`/app/kms/app.py`，确认隐藏备份接口与 SSRF 接口。
2. 确认 KMS 使用 AES-CTR、固定 key 与固定 nonce（如 `STATIC_NONCE`），`import_dek` 接受任意 DEK。
3. 用整数 IP `http://2130706433:5000/` 绕过 SSRF 的 `127.0.0.1`/`localhost` 字符串黑名单，访问 KMS。
4. 调用 `import_dek(00...00)`（32 字节全零），返回值即 keystream `S`。
5. 取备份接口返回的 `enc_dek`，计算 `old_dek = enc_dek XOR S`。
6. 用 `old_dek`、`nonce`、`tag` 对 `enc_data` 做 AES-GCM 解密，校验 tag 通过后得到明文。

## PoC

```python
from Crypto.Cipher import AES

# 1) KMS 对全零 DEK 做 CTR 加密，返回 keystream
keystream = kms_import_dek(bytes(32))

# 2) 备份接口返回的包装 DEK
enc_dek = bytes.fromhex(snapshot["enc_dek"])
old_dek = bytes(a ^ b for a, b in zip(enc_dek, keystream))

# 3) AES-GCM 解密备份
cipher = AES.new(old_dek, AES.MODE_GCM, nonce=bytes.fromhex(snapshot["nonce"]))
plain = cipher.decrypt_and_verify(bytes.fromhex(snapshot["enc_data"]),
                                  bytes.fromhex(snapshot["tag"]))
print(plain)
```

```text
SSRF 绕过示例：
GET /health_check?url=http://2130706433:5000/api/v1/import_dek?dek=0000000000000000000000000000000000000000000000000000000000000000
```

无真实目标 PoC：原文为 CTF 环境，接口路径、字段名、nonce/密钥需按源码确认；核心是“零明文取 keystream + XOR 还原 DEK”。

## 变体与关联

- **流式模式复用**：AES-CTR、ChaCha20、RC4 等在固定 key/nonce 下都会复用密钥流；AES-GCM 的 nonce 复用还会泄露 GHASH 子密钥。
- **KMS oracle**：`wrap`/`unwrap`/`encrypt`/`decrypt` 接口若允许任意输入并返回结果，可构造 chosen-plaintext 攻击；零明文是最直接的 keystream 提取。
- **SSRF 绕过**：整数 IP、八进制/十六进制、IPv6 映射、DNS 重绑定、302 跳转；白名单只做字符串匹配时尤其有效。
- **路径穿越**：Apache 2.4.49 `.%2e`、Nginx 编码斜杠、Go ServeMux `%2F` 双视图；用于读源码/配置。
- **关联**：AES-CTR/GCM nonce 复用、KMS 密钥包装、SSRF 内网访问、Apache 路径穿越。

## 检测与防御

- **密钥包装**：每次包装使用随机 nonce/IV，并将 nonce 与密文一起存储；优先使用 AES-KW/AES-GCM-SIV 等专用包装算法；禁止固定 nonce。
- **KMS 接口**：不要向不可信调用方提供任意明文加密/解密 oracle；对 `import_dek` 做认证、授权与输入格式校验；限制返回长度与调用频率。
- **备份加密**：DEK 包装与数据加密分离；GCM nonce 随机且不复用；密钥轮换与版本化。
- **SSRF 防御**：解析 URL 后校验规范化 IP，拒绝私有/回环/链路本地地址；禁止整数/八进制/十六进制等非标准 IP 形式；出站白名单 + 代理。
- **路径穿越**：升级 Apache 至修复版本；`/assets` 别名目录禁用 `..`/编码点段；最小化源码与配置可读性。
- **检测**：监控对 KMS import/wrap 接口的高频/零值请求；监控 SSRF 目标为整数 IP/回环；对备份接口异常访问与 GCM tag 失败告警。

## 可信度与边界

- 原文为 CTF 题，路径穿越、整数 IP SSRF、`import_dek(0)` 取 keystream、XOR 还原 DEK 与 GCM 解密均有源码/请求/结果证据；攻击链完整。
- 具体接口路径、nonce、字段名与密钥为该题实现；真实目标需按源码确认。
- 未在真实目标复跑；卡内不包含题目 flag。
