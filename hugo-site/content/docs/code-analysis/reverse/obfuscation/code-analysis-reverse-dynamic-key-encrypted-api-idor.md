---
id: code-analysis-reverse-dynamic-key-encrypted-api-idor
title: 动态密钥前端加密接口的越权测试：断点固定 generateKey 并复用页面加解密函数
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: dynamic-key-frontend-encryption-idor-test
tags:
- javascript
- reverse
- frontend-encryption
- idor
- devtools
- breakpoint
- api-testing
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V61
  verified_at: '2026-11-05T12:48:25+08:00'
  notes: 已对照原文与图01-11核对：银行登录/注册(图01/02)、app.2a3bf09e.js 接口与 QUERY_NOTICE_USER_URL(图03/04)、sigin 构造处断点与租户 paramKeys(图05)、AresCrypto.encrypt(i.publicKey,i.privateKey,e,f()(t.data))(图06)、generateKey 结果被固定为 e(图07)、decrypt(t.config.encryptKey,e.body)(图08/09)、构造 {"loading":"true","pageNo":1,"pageSize":10000} 加密请求并解密响应得到 certNo/地址等字段(图10/11)，与卡一致。未验证点：原文接口/字段大量脱敏，未展示具体替换哪个用户标识，“越权”实际以 pageSize 放大批量拉取为主；固定 key 与服务端 encryptKey 的对应关系原文未展开；PoC 未本机复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-dynamic-key-encrypted-api-idor/
draft: false
kb_aliases:
- 动态密钥固定
- AresCrypto 加解密
- generateKey 断点
- 前端加密接口越权
- encryptKey 固定
- 加密参数重放
---

## 一句话结论

当 SPA 对每个请求动态生成加密密钥（如 `AresCrypto.generateKey()`）并同时加密请求体、解密响应体时，可在 DevTools 中把密钥固定、直接调用页面自身的 `encrypt`/`decrypt` 函数构造请求与解析响应，再修改分页/用户等业务参数，测试并利用接口越权（如 `pageSize=10000` 批量拉取他人身份证、住址等敏感信息）。

## 原理

- 前端加密不是服务端授权：密钥、算法和签名逻辑都在浏览器里，攻击者持有合法会话后可以在运行时复用它们。动态密钥只是把“重放固定密文”变成“每次重新加密”，并不能阻止有浏览器调试能力的测试者。
- 典型实现：`key = AresCrypto.generateKey()` 每个请求/响应不同；请求 `t.data = AresCrypto.encrypt(publicKey, privateKey, key, sign(data))`；响应 `data = AresCrypto.decrypt(config.encryptKey, body)`。服务端用同一 key 解密请求、加密响应。
- 测试方法：在 `generateKey()` 返回处或 `encrypt` 调用前下断点，把返回值改成固定字符串（或直接在 Console 调用页面函数并传入固定 key），使请求与响应的 key 一致；然后用页面的加密函数构造任意业务参数，发送后用页面的解密函数还原响应。
- 越权发生在业务层：接口按请求参数（`pageNo`、`pageSize`、用户标识、查询条件）返回数据，但未校验当前会话是否有权访问这些对象/范围；把 `pageSize` 放大到 10000 或替换用户标识，即可批量获取他人数据。
- 之所以成立：加密解决的是传输机密性/完整性，不解决“谁能看哪些数据”；客户端加密反而让测试者必须借用页面函数，但一旦复用成功，服务端的授权缺口就暴露出来。

## 触发条件

- 目标为 SPA/前端框架应用，接口请求体或参数由 JS 加密，响应体也可能加密。
- 攻击者可注册/持有普通账号，能访问页面并使用 DevTools 断点/Console。
- 加密密钥在运行时由 JS 生成（动态 key）或硬编码，但总能通过页面函数复现。
- 业务接口存在对象级/数据级授权缺失，或分页/查询参数未做服务端限制。
- 接口无严格频控/风控，允许批量拉取。

## 利用步骤

1. 注册普通账号，浏览功能，抓取目标接口，记录 URL、请求头、加密字段（如 `data`、`sigin`、`X-GW-DATA-ENCRYPT-ID`）。
2. 在 Sources 中搜索加密函数（`AresCrypto.encrypt`、`decrypt`、`generateKey`）或按 URL 下 XHR/fetch 断点，定位参数构造与加密位置。
3. 在 `generateKey()` 返回处下断点，把动态 key 固定为已知值；或在 Console 中直接调用 `AresCrypto.encrypt(...)`/`decrypt(...)`，传入固定 key。
4. 用页面函数构造正常请求并发送，确认响应能用对应 key 解密，建立“可控加密通道”。
5. 修改业务参数：替换用户 ID/查询条件、放大 `pageSize`、调整 `pageNo`、去掉范围过滤，重新加密发送。
6. 解密响应，检查是否返回其他用户/全量数据（身份证号、住址、手机号等），并评估影响范围。

## PoC

页面加密函数调用形态（字段名按目标替换）：

```javascript
// 固定动态 key（或在 generateKey 断点处改返回值）
const key = "0123456789abcdef";
const payload = {"loading": "true", "pageNo": 1, "pageSize": 10000};
// 直接调用页面已加载的加密函数
const enc = AresCrypto.encrypt(appId.publicKey, appId.privateKey, key, JSON.stringify(payload));
// 发送 enc 后，用同一 key 解密响应
const dec = AresCrypto.decrypt(key, response.body);
```

说明：原文在银行保险票务平台注册普通用户后，通过断点固定 `AresCrypto.generateKey()` 的动态 key，构造 `{"loading":"true","pageNo":1,"pageSize":10000}` 的加密请求并解密响应，获取大量个人身份证、住址等敏感信息；原文对具体接口与参数做了脱敏，PoC 未在本会话执行。

## 变体与关联

- **静态/硬编码 key**：直接从 JS 提取 key/iv 即可，无需断点；见前端加密逆向自动化卡。
- **仅签名不加密**：还原 `sign = md5(salt + ts + page)` 后直接构造请求；动态时间戳/一次性 nonce 需实时生成。
- **自动化**：把页面的 encrypt/decrypt 扣成 Node/PyExecJS 函数，批量枚举分页与用户 ID；或使用 JSRPC 把浏览器函数暴露给 Burp。
- **越权类型**：水平越权（替换用户 ID）、垂直越权（普通用户调用管理接口）、批量数据泄露（pageSize 放大、导出接口无限制）。
- 关联：[[code-analysis-reverse-frontend-request-response-encryption-automation]]（通用前端加密逆向与自动化）、[[web-generic-auth-authenticated-change-password-idor]]、[[pentest-recon-frontend-js-aes-key-encrypted-credential-mqtt-validation]]。

## 检测与防御

- **检测**：同一会话出现异常大的 `pageSize`/导出请求、短时间遍历大量对象 ID；前端加密接口的请求体模式异常（固定 key 复用、重放）；同一账号访问不属于自己的数据。
- **防御**：服务端对每个对象做归属校验（不要信任请求里的用户 ID/范围参数），按当前会话过滤数据；限制 `pageSize`/分页深度/导出数量并做频控；不要把前端加密当作授权或防重放机制；对敏感字段做脱敏与访问审计；监控批量查询与越权访问告警。
