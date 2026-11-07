---
id: tools-burp-encrypted-api-proxy-decrypt-resign
title: 加密 API 测试代理链：上下游 mitmproxy 透明解密/重签，绕过防重放与 AES 参数加密
type: scenario
domain: tools
path: tools/burp
technique: encrypted-api-testing-upstream-downstream-proxy-decrypt-resign
tags:
- burp
- mitmproxy
- proxy
- encryption
- signature
- anti-replay
- api-testing
- aes
- rsa
- tooling
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V137
  verified_at: '2026-11-06T05:36:41+08:00'
  notes: 已对照原文与27张图核对：上下游代理架构（图01）、端口8081/8080/8082（图26）、random=RSA(timestamp)前端逻辑（图15 JS）及改random=test仍success:true/Login Success（图20）、AES固定Key/IV=1234567890123456 CBC/Pkcs7（图23 JS）、上游解密后Burp见明文（图27），均与卡片一致。未验证点：未在本机运行EasyDecrypt/mitmproxy，PoC为规则配置非可执行脚本；原文无CVE与受影响版本，故未设affected_versions；卡片关联段含一条标注不相关的firmware链接（不影响技术内容）。
url: /docs/tools/burp/tools-burp-encrypted-api-proxy-decrypt-resign/
draft: false
kb_aliases:
- EasyDecrypt
- 加解密代理
- 上下游代理
- random=RSA(timestamp)
- encryptedData
- AES固定Key
- 防重放绕过
- 加密接口改包
---

## 一句话结论

对请求/响应加密且带签名、时间戳或 nonce 的接口，用 mitmproxy 搭建上游（浏览器/小程序↔Burp）与下游（Burp↔服务器）双代理，按规则自动解密/加密并重算动态字段，Burp 中始终看到并修改明文，而服务端仍能通过密文与签名校验；像 `random = RSA(timestamp)` 这类防重放字段，在每次发送前按同一算法重新生成即可绕过。

## 原理

- **测试困境**：接口对业务参数做 AES/SM4/RSA 加密，并对 Sign/Nonce/Timestamp 做校验。Burp 只能看到密文，改包后签名或密文校验失败，重放还会被 nonce/时间戳拦截。
- **双代理分层**：把“业务明文”和“协议密文”拆到两个边界上处理。
  - 上游代理：接收浏览器/小程序请求，按规则解密 `encryptedData` 等字段并还原结构后交给 Burp；Burp 修改后的明文响应再加密回给客户端。
  - 下游代理：接收 Burp 修改后的明文请求，按规则重新加密并生成签名后发往服务器；服务器响应解密后交回 Burp。
  - 这样 Burp 位于两个代理之间，看到的始终是明文，修改的也是明文。
- **规则函数链**：工具把处理逻辑抽象为“函数选择 + 输入/输出变量”的节点链，常用节点包括 `GetParams`（取 GET/POST/Header/Body 字段）、`Time`（时间戳）、`Encrypt/Decrypt`（AES/SM4/DES/RSA）、`Hash/Hmac`、编码转换与 `SetParams`（写回字段）。例如防重放规则链为：`time = Time('时间戳(毫秒)')` → `random = RSAEncrypt(time)` → `POST(random) = random`。
- **为什么防重放能被绕过**：服务端校验的是“`random` 是否为本次请求时间戳的 RSA 加密结果”，但 RSA 公钥与生成逻辑就在前端 JS 中（`random = rsaEncrypt(Date.now(), publicKey)`），代理用同一公钥对当前时间戳重新加密，服务端无法区分是客户端还是代理生成；若服务端没有把 nonce 与一次性会话记录绑定，重放/改包即可通过。
- **为什么 AES 改包能通过**：固定 Key/IV 硬编码在前端（案例为 `1234567890123456`，CBC/Pkcs7），代理用同一 Key/IV 解密和重新加密，密文在服务端看来完全合法。客户端加密本质上无法作为完整性/机密性边界。
- **价值**：把“不可测”的加密接口变成可读可改的明文接口，从而测试越权、Mass Assignment、业务逻辑绕过等真实漏洞。

## 触发条件

- 客户端（Web/小程序/App）的加解密与签名逻辑可在前端还原，密钥/公钥/IV 可获取（固定 Key、JS 内置公钥、白盒等）。
- 服务端只校验客户端计算出的密文、签名、时间戳/nonce，没有服务端一次性挑战或会话绑定。
- 测试端能安装 mitmproxy CA 证书，并可配置浏览器/小程序与 Burp 的代理链。
- 目标接口的加密字段与动态校验字段可定位（`encryptedData`、`random`、`sign`、`timestamp` 等）。

## 利用步骤

1. 抓包确认哪些字段被加密、哪些是防重放/签名字段；案例中 `random` 每次不同，`encryptedData` 为 AES 密文。
2. 分析前端 JS，得到算法、模式、Key/IV、公钥与字段生成方式（案例：`random = RSA(timestamp)`；`encryptedData = AES(JSON.stringify(formData))`，CBC/Pkcs7）。
3. 配置上游规则：`encryptedData = GetParams(POST[encryptedData])` → `iv/key = '...'` → `decdata = AESDecrypt(encryptedData)` → `POST(encryptedData) = decdata`；响应方向按需反向加密。
4. 配置下游规则：`time = Time('时间戳(毫秒)')` → `random = RSAEncrypt(time)` → `POST(random) = random`；若 Burp 修改了明文，再对明文 AES 加密后写回。
5. 启动上游监听 8081、Burp 监听 8080、下游监听 8082；浏览器下一跳指向 8081，Burp 上游代理指向 127.0.0.1:8082，并安装 mitmproxy CA。
6. 在 Burp 中直接修改明文参数并重放，服务端返回成功即完成加密接口的可测化。

## PoC

```text
# 案例一：防重放字段重算（encrypt-labs /encrypt/norepeater.php）
time   = Time('时间戳(毫秒)')
random = RSAEncrypt(time)
POST(random) = random
# 效果：Burp 中把 random 改成 test 后重放，仍返回 success:true / Login Success

# 案例二：AES 固定 Key 参数篡改（encrypt-labs /encrypt/aes.php）
encryptedData = GetParams(POST[encryptedData])
iv  = '1234567890123456'
key = '1234567890123456'
decdata = AESDecrypt(encryptedData)
POST(encryptedData) = decdata
# 上游解密后 Burp 看到 {"username":"admin","password":"123456"}，可任意修改；
# 下游用同一 key/iv 重新 AES 加密后发送，服务端校验通过。
```

```javascript
// 前端逻辑（案例）：random = RSA(timestamp)，公钥硬编码在 JS
const timestamp = Date.now();
const encryptedTimestamp = rsaEncrypt(timestamp, publicKey);
// encryptedData = CryptoJS.AES.encrypt(JSON.stringify(formData), key,
//   { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 }).toString();
```

## 变体与关联

- 加密方案变体：AES 固定 Key、AES 服务端获取 Key、RSA、AES+RSA、DES 规律 Key、明文加签、加签 Key 在服务端；工具内置对应函数节点。
- 代理位置变体：只改请求用下游代理即可；需要查看/修改响应时再加上游代理；也可只用单侧规则。
- 字段变体：`sign` 由多个参数排序拼接后 Hash/Hmac，规则链需按前端顺序拼接后重算；nonce 为随机串时直接 `randomStr` 生成。
- 关联：[[code-analysis-reverse-firmware-qemu-system-mipsel-router-httpd]] 不相关；移动端加密逻辑还原可结合 Frida 类卡片；Burp 工具链另见 [[tools-burp-hermes-mcp-wsl-sse-integration]]。

## 检测与防御

- **服务端防御**：不要信任客户端加密与签名；防重放应使用服务端签发的一次性 nonce/挑战并绑定会话，校验后立即失效；时间戳窗口收窄；敏感操作在服务端重新鉴权与校验业务规则。
- **检测**：同一 nonce/时间戳被重复使用；时间戳与服务器时间偏差异常；同一账号短时间大量请求且签名合法但业务参数异常；客户端密钥/公钥硬编码应视为公开信息，不能作为信任依据。
- **客户端加固的边界**：代码混淆/白盒只能提高还原成本，无法阻止代理重算；真正的防护必须落在服务端授权与一次性挑战上。
