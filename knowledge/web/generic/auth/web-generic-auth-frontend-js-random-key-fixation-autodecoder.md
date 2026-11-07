---
id: web-generic-auth-frontend-js-random-key-fixation-autodecoder
title: 前端加密流量测试：中间人替换 JS 固定随机 AES 密钥并用 autoDecoder 解密
type: scenario
domain: web
path: web/generic/auth
technique: frontend-js-random-key-fixation
aliases:
- JS 随机数固定
- Math.random 替换
- 前端加密密钥固定
- autoDecoder 固定密钥
- Burp 响应体替换 JS
- 公众号加密流量测试
tags:
- javascript
- frontend-encryption
- aes
- rsa
- autodecoder
- burp
- mitm
- pentest
- key-fixation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:33:42+08:00'
  notes: 已对照原文与4张图核对；图02为Response body替换r=16*Math.random()|0→*0，图03 autoDecoder AES/ECB/PKCS5Padding+32个0 Hex密钥，图04解密回显一致；原文未标注组件版本，PoC未复跑
---

## 一句话结论

当 H5/公众号 的请求体由前端随机生成 AES 密钥、用 RSA 包裹密钥并用 MD5 签名时，不必完整逆向加密算法：用 Burp 的响应体 Match/Replace 把 JS 中生成随机密钥的表达式改成恒为 0，使 AES 密钥固定为全零；再用 autoDecoder 配同一密钥即可解密查看，改包时按前端同样的签名公式重算 `sign`。

## 原理

- 典型“加密三件套”请求体：`key` 是 RSA 公钥加密后的随机 AES 密钥，`content` 是用该 AES 密钥加密的业务数据（常见 ECB + PKCS7 + Base64），`sign = md5(content + appSecret)` 用于防篡改。
- 客户端必须持有明文 AES 密钥才能加密业务数据，服务端用 RSA 私钥解出同一密钥；因此密钥的安全性取决于客户端生成过程。若前端用 `Math.random()` 逐字符生成密钥，只要改变这行代码，就能让密钥变成可预测的固定值，而无需破解 RSA。
- 原文的密钥生成函数把 32 个 `x` 替换为 `(16*Math.random()|0).toString(16)`；把表达式改成 `16*Math.random()*0` 后每次结果都是 0，32 位密钥就固定为 `00000000000000000000000000000000`。
- Burp 的 `Match and Replace` 可在响应方向改写 JS 文件，浏览器/微信重新加载后执行被篡改的逻辑；autoDecoder 插件再以该固定密钥对 `content` 做 AES 解密/重加密，从而在 Burp 中看到明文并修改请求。
- 为什么成立：前端代码在用户端执行且 JS 没有完整性校验（SRI/签名），中间人可任意改写；客户端加密只提高分析成本，不构成服务端信任边界。

## 触发条件

- 目标 H5/公众号 请求使用前端对称加密，密钥在客户端生成并用 RSA/公钥包裹；
- 能在浏览器中直接打开 H5 页面并查看 JS（无需在微信内调试）；
- 测试端可对目标做 TLS 中间人（Burp CA 受信），并能修改 JS 响应；
- JS 没有 SRI、签名校验或 CSP 等完整性保护，或保护可绕过；
- 改包场景还需能取得 `appSecret` 并按 `md5(content + appSecret)` 重算签名（若后端校验签名而工具不自动处理，只固定密钥只能解密、不能直接改包）。

## 利用步骤

1. 抓包识别字段结构（`key`/`content`/`sign`），判断是否为 RSA + AES + MD5 组合；记录加密模式、填充与密文编码。
2. 从 Burp 历史找到 H5 入口（如 `/h5/index.html`），在浏览器打开，F12 搜索 `Math.random`、`uid`、`aes.encrypt`、`rsa.encrypt`，确认密钥生成与加密参数。
3. 在 Burp `Proxy → Options → Match and Replace` 新增规则：Type 选 `Response body`，Match 填实际随机数表达式（如 `r=16*Math.random()|0;`），Replace 填恒 0 表达式（如 `r=16*Math.random()*0;`），必要时勾选 Regex 适配压缩/变体。
4. 重启微信或强制刷新页面，确保加载被替换后的 JS；抓包检查每次请求的 `key` 字段是否相同，确认固定成功。
5. 安装 autoDecoder，按加密参数配置：AES/ECB/PKCS5Padding、Ciphertext Base64、Key 为固定密钥（如 32 个 0，按 Hex 输入），请求与响应各添加一条加解密方法；保存配置后重放请求即可看到 `content` 明文。
6. 需要修改业务参数时，修改明文后重新加密，并按前端公式重算 `sign`（`appSecret` 同样可从 JS 获取）；若工具不支持签名，可配合自定义脚本或 JSRPC 调用前端签名函数。
7. 验证：服务端正常返回业务数据，说明客户端加密已被绕过；记录固定密钥、加密参数与签名公式以便复现。

## PoC

```javascript
// 原始密钥生成
var r = 16 * Math.random() | 0;
return r.toString(16);

// Burp Match/Replace 后：每次 r 都为 0，32 位密钥变成全 0
var r = 16 * Math.random() * 0;
return r.toString(16);
```

```text
请求体结构：
{"encrypt":2,"key":"<RSA(AES key)>","content":"<AES(data)>","sign":"<md5(content+salt)>"}

autoDecoder：
AES / ECB / PKCS5Padding / Base64
key = 00000000000000000000000000000000   (Hex，32 个 0)
```

## 变体与关联

- 变体：若密钥由 `crypto.getRandomValues()` 或 `wx.getRandomValues()` 生成，改为替换密钥赋值处（如固定返回常量）而不是 `Math.random`。
- 变体：只固定密钥但不改包时，仅能解密查看；要改包必须同步重算 `sign`，否则会被服务端签名校验拒绝。
- 关联：[[web-generic-auth-js-signature-jsrpc-autodecoder]]（JSRPC + autoDecoder 动态代签）、[[crypto-prng-math-random-sharekey-recovery]]（通过 hook Math.random 恢复密钥，而非固定）、[[code-analysis-reverse-frontend-request-response-encryption-automation]]（完整 JS 逆向与 PyExecJS 自动化）、[[web-generic-auth-cas-aes-cbc-login-encryption-reverse]]（登录参数前端加密逆向）、[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]（小程序国密协议透明加解密）。

## 检测与防御

- 检测：同一客户端会话的 `key` 字段重复不变、RSA 密文相同、请求体 `content` 长度/模式异常；JS 响应被中间人改写（内容哈希与发布版本不一致）；短时间大量重放与参数变更。
- 防御：JS 使用 SRI 与 CSP，发布包做签名/哈希校验；不要把 `appSecret` 和加密逻辑当作安全边界；关键签名与加密放到服务端或使用服务端下发的短期密钥；对固定 `key`、异常重放与参数篡改做服务端风控；对敏感操作增加服务端二次校验。
- 注意：前端加密只能增加攻击成本；在授权测试中固定密钥后仍需关注后端是否真正校验签名/权限，避免把“能解密”误判为“能越权”。
