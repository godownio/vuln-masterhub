---
id: code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge
title: AES-CBC 固定 key/iv 的 encryptCode 请求体还原与伪造
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: aes-cbc-encryptcode-request-forge
tags:
- web
- aes
- cbc
- javascript-reverse
- api
- encryption
- pentest
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T17:53:36+08:00'
  notes: 已对照全文与 img01-07：img03 搜索命中 umi.js:80 的 ca.encrypt(k,"abcdefghijklmnop","abcdefghijklmnop")，img04 显示 CryptoJS AES、mode.CBC、pad.Pkcs7、iv=rt，img05 两者均为 16 字节，img06/07 CyberChef 输出与抓包一致。核对时发现卡片示例密文首字符误写为数字 1：以 key=iv=abcdefghijklmnop 对 '{}' 做 AES-CBC/PKCS7 实算为 l7QUQz+F/GqCWtNYfktzjg==，且仅 l7 开头可正确解出 '{}'（17 开头填充错误），已把知识卡与 staging 卡中的 17QUQz 全部改为 l7QUQz。原文未给产品/版本信息，未设 affected_versions；PoC 未在目标上复跑。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge/
draft: false
kb_aliases:
- encryptCode 加密逆向
- AES CBC key=iv
- 未授权接口 加密请求
- CryptoJS AES 复刻
- 请求体加密还原
---

## 一句话结论

目标未授权接口的请求体只有 `encryptCode` 一个密文字段时，在 JS 中搜索该字段名即可定位 `ca.encrypt(k, key, iv)`；断点读到 key 与 iv 都是固定字符串 `abcdefghijklmnop`，算法为 CryptoJS AES-CBC + PKCS7 + base64，用同参数复刻即可为任意明文生成合法 `encryptCode`，继续测试未授权接口。

## 原理

- 前端把业务参数对象 `k` 交给 `ca.encrypt(k, key, iv)`；断点进入实现可见 `lo().AES.encrypt(k, Z, {mode: CBC, padding: Pkcs7, iv: rt})`，输出 `toString()` 为 base64，因此可判定为 AES-CBC/PKCS7/base64。
- 本例 key 与 iv 均为 16 字节 ASCII `abcdefghijklmnop`（AES-128），且都硬编码在前端；调用处直接写 `ca.encrypt(k, "abcdefghijklmnop", "abcdefghijklmnop")`，因此密钥视为公开。
- 复刻时把明文按 JSON 序列化（本例明文为 `{}`），用 AES-CBC + PKCS7 加密后 base64；CyberChef 的 AES Encrypt（Key/IV 均 UTF8=`abcdefghijklmnop`、Mode CBC）+ To Base64 输出与抓包 `l7QUQz+F/GqCWtNYfktzjg==` 完全一致。
- 因为加密只是把参数藏起来、没有服务端密钥或签名，攻击者可对任意修改后的业务参数重新加密，构造原本无法手工输入的请求，从而测试未授权接口/越权。

## 触发条件

- 目标接口请求体为单个加密字段（如 `encryptCode`），且前端 JS 可读。
- 加密为对称算法，key/iv 硬编码或可在断点读取；服务端只解密不校验来源/签名。
- 攻击者可访问接口并能触发一次正常请求以定位加密函数。
- 接口本身存在未授权/越权等业务缺陷，加密只是测试门槛。

## 利用步骤

1. 抓取目标请求，确认请求体形如 `{"encryptCode":"l7QUQz+F/GqCWtNYfktzjg=="}`；改动参数会报错，说明需要重新加密。
2. DevTools → Sources 全局搜索 `encryptCode`（少见字段名通常只有一处命中），定位 `encryptCode: ca.encrypt(k, "abcdefghijklmnop", "abcdefghijklmnop")`。
3. 在 `ca.encrypt` 处下断点，触发请求；进入实现确认 `AES.encrypt`、`mode.CBC`、`pad.Pkcs7`、`iv`、返回 `toString()`（base64）。
4. 读取三个参数：明文 `k`、key、iv；本例 key=iv=`abcdefghijklmnop`。
5. 用 CyberChef/Python 复刻加密，先用已知明文验证输出与抓包一致。
6. 修改业务参数为测试目标值，重新加密生成 `encryptCode`，替换请求体发送，观察未授权接口响应。

## PoC

```javascript
// 抓到的调用（umi.js）
encryptCode: ca.encrypt(k, "abcdefghijklmnop", "abcdefghijklmnop")

// ca.encrypt 内部（CryptoJS）
return lo().AES.encrypt(k, Z, {
  mode: lo().mode.CBC,
  padding: lo().pad.Pkcs7,
  iv: rt
}).toString();
```

```python
import base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = b"abcdefghijklmnop"
iv  = b"abcdefghijklmnop"
pt  = json.dumps({}, separators=(",", ":")).encode()
ct  = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(pt, 16))
print(base64.b64encode(ct).decode())  # l7QUQz+F/GqCWtNYfktzjg==
```

## 变体与关联

- 变体：key/iv 不同、长度 16/32 字节、iv 随机并随密文前置；以断点实际值和 `concat` 顺序为准。
- 变体：字段名可能是 `encryptCode`、`content`、`data`；搜索少见字段名比搜 `encrypt` 更快。
- 变体：服务端若用 RSA 加密对称密钥，需在断点读取会话 key，或直接调用页面原函数代签/代加密。
- 边界：服务端有 HMAC/签名绑定会话、密钥每次会话随机下发且不可预测时，单纯复刻固定 key 不成立。
- 关联：[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（AES-CBC key/iv 提取与 iv||密文还原）、[[code-analysis-reverse-frontend-request-response-encryption-automation]]（JS 逆向 + PyExecJS 自动化）、[[web-generic-auth-js-signature-jsrpc-autodecoder]]（运行时调用原函数代签/代加密）。

## 检测与防御

- 检测（测试方）：请求体单字段密文 + JS 中存在 `AES.encrypt`/`mode.CBC`/`pad.Pkcs7`/固定字符串 key；用已知明文复刻验证。
- 防御：前端加密密钥视为公开，不能提供保密或认证；必须使用 TLS；若需请求保护，使用服务端下发会话密钥 + AEAD（AES-GCM）+ HMAC/签名并绑定会话与时间戳。
- 加固：服务端对加密内容解密后仍需做权限校验；不要把“参数已加密”当作信任依据；监控同一会话对未授权接口的异常请求。
