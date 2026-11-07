---
id: code-analysis-reverse-obfuscation-js-config-array-console-aes-key-iv
title: 混淆 JS 加密配置数组控制台求值：提取 AES-CBC key/IV 解密双向业务流量并定位外传 URL
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: js-obfuscation-config-array-console-aes-key-iv
aliases:
- 加密配置数组控制台求值
- PKCS5Padding 定位
- AES-CBC key/iv 提取
- 前端加密流量解密
- 外传 URL 定位
- 混淆 JS 配置泄露
tags:
- javascript
- reverse
- obfuscation
- aes
- cbc
- pkcs5
- key-extraction
- frontend-encryption
- traffic-decrypt
- exfiltration
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:32:51+08:00'
  notes: 已对照原文13张图逐张核对：图01混淆JS、图02 PKCS5Paddi+ng拼接赋值、图03控制台输入_0x2e3b31得到algorithm/mode/padding/output/key/iv、图04请求/响应密文、图05 dirsearch admin.html、图06硬编码admin/admin@123456、图07 flag用户ID均与卡一致；卡聚焦控制台求值配置数组并双向解密定位外传URL，与js-aes-parameter-restore（断点读变量、iv||密文单请求解密）提取方法/产出不同，dedup_review理由成立。未验证点：PoC未本机复跑；CTF环境样本key/域名仅示例；frontmatter无 sources/source_url；无组件版本。
---

## 一句话结论

前端用 AES-CBC 加密请求/响应时，混淆代码只是把变量名换成字符串数组索引，算法、模式、填充、Key、IV 这些字符串常量在运行时仍以明文存在。定位到承载加密配置的数组/对象变量后，在浏览器 DevTools 控制台直接输入该变量名求值，即可一次性打印出 `algorithm/mode/padding/output/key/iv` 全部参数；再用这套参数对抓包得到的 Base64 密文做 AES-CBC 解密，既能还原用户提交的敏感信息，也能从响应明文中提取攻击者的数据接收 URL。

## 原理

- **混淆不改变运行时值**：常见的 JS 混淆（字符串数组 + `_0x...` 索引函数）只替换标识符与常量引用，运行时数组里仍是原始字符串；`'PKCS5Paddi' + 'ng'` 这类拼接只是增加阅读难度，求值后就是 `PKCS5Padding`。
- **加密配置在 JS 中必然可还原**：浏览器要完成加密，AES 的 key/iv/模式/填充必须在客户端存在；除非使用服务端下发的一次性密钥或非对称加密，否则这些参数会以常量或配置对象形式留在 JS 中。
- **数组/对象变量可在控制台直接求值**：混淆代码把配置写入某个全局数组变量（如 `_0x2e3b31[...] = ...`）。该变量本身是普通 JS 对象，在控制台输入变量名即可看到所有键值，不需要逐行去混淆或下断点。
- **双向解密**：请求体与响应体可能都经过同一套 AES-CBC 加密。Base64 解码后用 `key`/`iv` 做 AES-CBC 解密并去 PKCS5/PKCS7 填充，请求明文常包含业务字段（姓名、身份证、银行卡、密码等），响应明文可能包含服务端“转发至某 URL”的提示，从而暴露数据外传地址。
- **为什么能定位外传 URL**：黑灰产站点常把窃取的数据先提交到前端接口，再由服务端转发到攻击者服务器；转发目标常直接写在响应 JSON 的 `message`/`data` 字段里，解密响应即可读到。

## 触发条件

- 目标页面加载混淆 JS，并在浏览器端对请求参数或响应体做对称加密（AES-CBC 等）。
- key/iv 固定或可预测地写在前端（若每次由服务端下发，则需先抓取下发接口）。
- 攻击者可访问页面、打开 DevTools 控制台，并能触发一次业务请求（登录、查询等）。
- 密文以 Base64（或 Hex）传输，填充方式与 JS 配置一致（常见 PKCS5Padding/PKCS7）。

## 利用步骤

1. 打开目标查询/登录页面，确认资源中存在混淆 JS（字符串数组 + `_0x` 索引函数），且网络请求体/响应体为密文。
2. 在 Sources 中搜索 `AES`、`CBC`、`PKCS5`、`Base64` 等特征字符串；找到类似 `_0x...[...] = 'PKCS5Paddi' + 'ng'` 的配置赋值行。
3. 识别承载配置的数组/对象变量名（如 `_0x2e3b31`），在 Console 中输入该变量名并回车，得到完整配置对象（算法、模式、填充、输出编码、key、iv）。
4. 抓取一次业务请求，分别复制请求体与响应体中的密文；用 key/iv 做 Base64 解码 + AES-CBC 解密 + 去填充。
5. 检查请求明文中的敏感字段与响应明文中的 `message/data`，提取服务端转发/外传 URL。
6. 用还原出的参数构造合法请求，复现或扩大数据提交；必要时用同一 key/iv 加密自己的 payload。

## PoC

浏览器控制台直接求值混淆数组（变量名与 key/iv 以目标为准）：

```js
_0x2e3b31
// {
//   algorithm: "AES",
//   mode: "CBC",
//   padding: "PKCS5Padding",
//   output: "Base64",
//   key: "XDcS8sce3c9aPvBJH5uYz2dJT7xm4bLK",
//   iv:  "Qm5c7HNK3aLxP8zW"
// }
```

Python 解密请求/响应密文（key 32 字节即 AES-256，iv 16 字节；PKCS5 对 16 字节分组等价 PKCS7）：

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = b"XDcS8sce3c9aPvBJH5uYz2dJT7xm4bLK"
iv  = b"Qm5c7HNK3aLxP8zW"

def dec(b64):
    ct = base64.b64decode(b64)
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)

print(dec("<请求密文>").decode())
print(dec("<响应密文>").decode())
```

示例明文（结构）：请求为 `{"grokname":"credit_query","userInfo":{"realName":...,"idCard":...,"bankCard":...,"bankPassword":...},"timestamp":...}`；响应中出现 `"转发至http://asfiag.1823amgaf.com/api/Content"` 之类的转发地址。上述 key/iv 与域名是原文样本值，实战需替换为目标自身的配置。

## 变体与关联

- **断点式提取**：[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]] 在混淆 JS 中对 `encrypt` 下断点读取 key/iv；本卡用控制台直接求值配置数组，适合配置被集中存放在一个对象里的场景。
- **CryptoJS WordArray**：[[code-analysis-reverse-obfuscation-cryptojs-wordarray-key-restore]] 处理 key/iv 以数值数组（`words`/`sigBytes`）形式存在的情况。
- **固定 key/iv 请求伪造**：[[code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge]] 展示提取后如何构造合法加密请求。
- **请求/响应双层加密自动化**：[[code-analysis-reverse-frontend-request-response-encryption-automation]] 覆盖更复杂的多层加密与 PyExecJS 自动化。
- **边界**：服务端每次下发随机密钥、使用非对称加密、或对请求做 HMAC/签名绑定时，仅提取 AES key/iv 不足以伪造请求；需继续分析密钥协商与签名逻辑。

## 检测与防御

- 防御：不要在 JS 中硬编码长期固定的对称密钥；使用服务端下发的一次性会话密钥并配合 HMAC/签名；对敏感字段使用非对称加密或端到端方案。
- 防御：混淆/压缩不能替代密钥保护；可定期轮换密钥、对前端代码做完整性校验，并限制加密接口的调用频率与来源。
- 检测：监控异常高频的查询/登录请求、同一 IP 对加密接口的自动化重放；对响应中出现可疑外部转发域名（如随机子域、非常规 TLD）进行告警与阻断。
- 响应：封禁外传域名、排查前端是否被植入恶意转发逻辑、评估已泄露的敏感字段范围。
