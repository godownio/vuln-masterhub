---
id: code-analysis-reverse-obfuscation-js-aes-zeropadding-authorization-key
title: 前端 AES 参数复现：key/iv 取 Authorization 后 16 位与 ZeroPadding/PKCS#7 填充对齐
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: js-aes-zeropadding-authorization-key
tags:
- javascript
- reverse
- aes
- cbc
- zeropadding
- pkcs7
- frontend-encryption
- python
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T07:46:49+08:00'
  notes: 已对照原文与10张图核对：key/iv=Authorization后16位、AES-CBC ZeroPadding、与PKCS#7尾块差异、PoC与原文一致；未实环境执行PoC
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-js-aes-zeropadding-authorization-key/
draft: false
kb_aliases:
- AES ZeroPadding
- PKCS7 密文不一致
- Authorization 后16位 key
- 前端加密复现踩坑
- params 解密
- 零填充 AES
---

## 一句话结论

前端用 AES-CBC 加密 `params`，且 key/iv 都取 `Authorization: Bearer <token>` 的后 16 位时，用 Python 复现必须同样使用 ZeroPadding（零字节补齐、已对齐时不额外补块）；若默认用 PKCS#7，末尾会多出一个 `0x10` 填充块，密文末段与系统不一致，改包/重放会失败。

## 原理

- **前端加密形态**：JS 中 `w(e,n,c)` 用 `CryptoJS.AES.encrypt(Utf8.parse(e), Utf8.parse(n), {iv: Utf8.parse(c), mode: CBC, padding: ZeroPadding})`，返回 `Base64(ciphertext)`；请求形如 `/api/...?params=<urlencoded base64>`。
- **key/iv 的来源**：本案例 `n`（key）与 `c`（iv）都取 `Authorization: Bearer <uuid>` 的后 16 位字符串；同一会话内 token 不变，key/iv 就不变。只要能看到请求头（代理、日志、浏览器），就能得到密钥——客户端加密对 token 持有者不构成保密。
- **ZeroPadding 与 PKCS#7 的差异**：
  - PKCS#7：填充 N 个值为 N 的字节；当明文长度正好是块大小整数倍时，仍追加一整块 `0x10 * 16`。
  - ZeroPadding：用 `0x00` 补到块边界，`padding_length = (16 - len % 16) % 16`，已对齐时补 0 字节。
  - 两者对最后一个块的处理不同，导致密文尾块不同；如果系统用 ZeroPadding 而脚本用 PKCS#7，解密方向可能仍能去掉填充，但“重新加密得到的密文”与抓包不一致，签名/比对/重放会失败。
- **解密去零填充**：不能简单 `rstrip(b'\0')`（会误删明文末尾合法的 0 字节），但本案例是 JSON 文本，末尾非 0，按最后一个非零字节截断即可。
- **排查顺序**：密文不一致时依次核对——padding 模式 → mode（CBC/ECB）→ key/iv 来源与长度（16/24/32 字节）→ 明文编码（UTF-8/JSON 序列化顺序）→ URL 编码（`quote/unquote` 是否多做一次）→ Base64 变体（标准/URL-safe/换行）。
- **为什么有效**：前端必须能加密，密钥必然在客户端可见；把算法、padding、key/iv 派生方式复现后，就能在本地解密任意 `params`、修改明文再加密，配合 sqlmap/Burp 做注入与越权测试。

## 触发条件

- 目标接口把参数放在 `params`（或类似字段）中，值为 Base64 密文，前端 JS 使用 AES-CBC。
- 能从请求头/JS 断点确定 key/iv 的来源（本例为 `Authorization` 后 16 位）和 padding（本例为 ZeroPadding）。
- 有一个可正常访问的会话 token，能抓到一组明文-密文对照用于验证。
- 本地有 Python + pycryptodome（或可调用页面 JS 的 Node/PyExecJS）。

## 利用步骤

1. 抓包确认 `params` 为 Base64/URL 编码密文，记录同请求的 `Authorization` 头。
2. DevTools 全局搜索 `encrypt`/`decrypt` 或参数名 `params`，在加密函数下断点；读取 `e`（明文）、`n`（key）、`c`（iv）与 `padding` 配置。
3. 确认 key/iv 的派生：本例 `key = iv = Authorization[-16:]`；记录 token 长度与来源。
4. 用 Python 实现 `zero_pad` + AES-CBC 加密/解密；先用抓到的同一明文加密，与系统密文逐字节对比。
5. 若尾块不一致，优先改 padding（ZeroPadding ↔ PKCS#7）；再检查 mode、编码、URL 编码与 Base64。
6. 对比通过后，建立“解密 params → 修改 JSON → 重新加密/URL 编码”的循环，辅助 sqlmap/Burp 测试。
7. 记录 token 有效期与 key 轮换方式；token 变化后重新取值。

## PoC

```python
from Crypto.Cipher import AES
import base64, json
from urllib.parse import unquote, quote, urlencode

def zero_pad(data: bytes, block=16):
    n = (block - len(data) % block) % block
    return data + b'\0' * n

def zero_unpad(data: bytes):
    i = len(data) - 1
    while i >= 0 and data[i] == 0:
        i -= 1
    return data[:i + 1]

def encrypt(text: str, key: str, iv: str) -> str:
    c = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    return base64.b64encode(c.encrypt(zero_pad(text.encode()))).decode()

def decrypt(b64: str, key: str, iv: str) -> str:
    c = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    return zero_unpad(c.decrypt(base64.b64decode(unquote(b64)))).decode()

if __name__ == '__main__':
    authorization = "Bearer 580ea5db-2205-4f13-b17f-17740feb4513"
    key = iv = authorization[-16:]
    params = input("params: ")
    plain = decrypt(params, key, iv)
    print(plain)
    print(urlencode(json.loads(plain)))
    print("新密文:", quote(encrypt(input("新明文: "), key, iv)))
```

```text
调试要点：先 encrypt 同一明文与抓包密文比对；若仅尾部不同，几乎就是 padding 模式不一致。
```

## 变体与关联

- **padding 变体**：PKCS#7/PKCS#5（补 N 个 N）、ISO10126（随机字节）、ZeroPadding（补 0）、无填充（要求明文对齐）；必须与前端 `padding` 参数一致。
- **key/iv 来源变体**：取 token 后 16 位、token 前 16 位、MD5(token) 前 16/32 位、固定字符串、接口下发；用断点确认而不是猜。
- **格式变体**：IV 前置拼接 `base64(iv||ciphertext)`、URL-safe Base64、密文外层再套 JSON 字段；按抓包拆分。
- **关联**：[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（通用前端 AES-CBC 逆向与 key/iv/iv||密文还原）；[[tools-burp-galaxy-http-hook-dynamic-key-capture]]（动态密钥下用 Burp hook 透明加解密）；[[web-generic-auth-hybrid-rsa-aes-login-bruteforce]]（RSA 包裹 AES 密钥的登录爆破）。
- **边界**：若服务端对密文做 HMAC/签名、一次性 nonce 或 token 绑定，仅复现 AES 仍不能任意改包；ZeroPadding 会丢失明文末尾合法的 0 字节，JSON 文本场景一般无影响。

## 检测与防御

- **根本问题**：key/iv 从 `Authorization` 派生并下发给客户端，token 持有者即可解密/加密任意报文；客户端加密只是提高改包成本。
- **服务端加固**：关键参数服务端二次校验；token 不直接复用为对称密钥（用服务端保存的会话密钥 + HMAC）；一次性 nonce/短时效；敏感操作 MFA；高频重放与参数突变告警。
- **检测**：同一 token 下 `params` 密文长度与明文长度不匹配、短时间内大量相似参数请求、`Authorization` 被复用到异常来源 IP；可结合 WAF 规则。
- **测试侧**：token、key/iv 按敏感信息处理；脚本只在授权测试环境使用。
