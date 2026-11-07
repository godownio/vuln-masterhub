---
id: mobile-miniprogram-sm-crypto-protocol-burp-transparent
title: 微信小程序 SM2/SM3/SM4 通信协议逆向与 Burp 透明加解密
type: scenario
domain: mobile
path: mobile
technique: miniprogram-sm-crypto-protocol-interception
tags:
- mobile
- miniprogram
- wechat
- reverse
- sm2
- sm3
- sm4
- burp
- mitm
- hook
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T12:19:25+08:00'
  notes: 已对照原文与图01-05/07核对：wxapkg 主包+分包、app-service.js 约1.6MB、webpack chunk3/module10 与 chunk1/module63/144/834/838/839、SM2 公钥加密 shareKey→SM4-CBC 加密业务体→SM3 签名、响应 retData/retSign、MCP 127.0.0.1:4554/sse、appservice context_id=4、_jmWx7e16 防递归标记、Galaxy 透明加解密指标均一致。原文协议摘要图写 C1C3C2 而代码 mode=0 返回 C1+C2+C3 的矛盾已在卡内标注；原文‘确认 SM4-ECB 模式’结论有误（代码为 mode:cbc，固定 IV 下 CBC 同样确定性），卡内未沿用该错误。PoC 为结构化复现，未在本机执行。
url: /docs/mobile/mobile-miniprogram-sm-crypto-protocol-burp-transparent/
draft: false
kb_aliases:
- 小程序国密协议
- wxapkg 反编译
- app-service.js webpack 模块定位
- MCP 注入 appservice
- Burp 透明加解密
- Galaxy Hook 小程序
---

## 一句话结论

反编译小程序 wxapkg 得到 `app-service.js`，按 webpack 模块定位 SM2/SM4/SM3 封装与请求编排，可还原出自研国密协议：客户端生成 32 位 shareKey → SM2 公钥加密为 secretKey → SM4-CBC 加密业务体 → SM3 签名；通过微信开发者工具 CDP/MCP 向 appservice 注入 hook 恢复 shareKey 后，即可在 Burp 中透明解密请求/响应、修改后重新加密并重算签名。

## 原理

- 小程序包结构：主包 `__APP__.wxapkg` 加多个分包（如 `_pages_inspection_`、`_pages_toPay_`、`_pages_marketing_`），反编译后得到约 1.6MB 的 `app-service.js` 及子包 JS。
- 代码由 webpack 打包，模块通过 `wx.webpackJsonp.push([[chunkId], {moduleId: function(require,exports,module){...}}])` 注册。通过 CDP 访问 `wx.webpackJsonp` 可枚举 chunk/module：请求编排在 chunk 3/module 10；加密封装在 chunk 1/module 63；module 144 导出 `{sm2: n(834), sm3: n(838), sm4: n(839)}`，分别对应 SM2/SM3/SM4 实现。
- 协议流程：
  1. 客户端生成 shareKey：32 个十六进制字符（16 字节），由 32 次 `Math.random()` 逐字符选取；
  2. `secretKey = SM2_encrypt(shareKey, serverPublicKey)`，公钥为带 `04` 前缀的 130 hex 字符未压缩点，密文带 `04` 前缀、约 258 hex 字符；
  3. `data = SM4_CBC_encrypt(JSON.stringify(body), shareKey, iv)`，密钥为 shareKey（16 字节），IV 从本地存储 `SM_ENC_DATA` 读取，PKCS#7 填充；
  4. `smSign = SM3("data=<data>&secretKey=<secretKey>&shareKey=<shareKey>")`；
  5. POST `{secretKey, data, smSign}`；
  6. 服务端用 SM2 私钥解出 shareKey，SM4 解密 data，SM3 验签；
  7. 响应 `{retData, retSign}`：`retData = SM4_CBC(responseBody, shareKey, iv)`，`retSign = SM3("retData=<retData>&shareKey=<shareKey>")`。
- 为什么可拦截：shareKey 由客户端生成且明文参与 SM3，客户端必须持有它；只要能在 appservice JS 上下文注入代码，就能在请求发出前读出密钥并解密流量。加密层本身不构成不可逾越的边界，密钥管理才是。
- 原文代码中 `doEncrypt(t,e,n)` 在 `n===0` 时返回 C1+C2+C3，而协议摘要图写的是 C1C3C2；两者存在矛盾，实际应以客户端代码或抓包逐字节验证为准（见变体）。
- 透明加解密架构：请求方向在 `wx.request` 前拦截 → 解密展示到 Burp → 修改后重新加密发送；响应方向解密展示 → 重新加密返回客户端。用标记字段（如 `_jmWx7e16`）避免 hook 递归；请求体未变化时可复用原始 secretKey，绕过 SM2 重新加密与服务端的兼容性问题。

## 触发条件

- 目标小程序可在微信开发者工具中打开并启用调试，CDP/MCP 接口可访问（原文 MCP SSE 端点 `http://127.0.0.1:4554/sse`，appservice context_id=4）。
- 加密逻辑在 JS 层（`app-service.js`），未被完全虚拟化或下沉到原生插件/WASM。
- 能反编译 wxapkg 并定位 webpack 模块；能向 appservice 注入 JS。
- 授权测试范围内，允许对流量做中间人解密与重放。

## 利用步骤

1. 提取并反编译 wxapkg：主包 + 分包，得到 `app-service.js`、`app-config.json` 等。
2. 通过 CDP 枚举 `wx.webpackJsonp` 的 chunk/module，定位请求编排（module 10）与加密封装（module 63、144、834/838/839）。
3. 阅读封装函数，确认 SM2 模式、SM4 模式/IV 来源/填充、SM3 签名字符串格式与 hex 大小写。
4. 建立 CDP WebSocket / MCP SSE 连接，向 appservice 注入 hook：包装 `Math.random` 记录随机值，包装 `wx.request` 记录请求时的调用计数与请求体。
5. 触发业务请求，按请求前最后 32 个 `Math.random()` 值恢复 shareKey（详见 [[crypto-prng-math-random-sharekey-recovery]]）。
6. 用 shareKey + IV 做 SM4-CBC 解密，验证业务 JSON；实现 SM3 签名与 SM4 重加密。
7. 接入 Burp（如 Galaxy Hook 架构）：请求解密展示、修改、重新加密；响应解密展示、重新加密回客户端；必要时复用原始 secretKey。
8. 验证：解密正确率、重加密后服务端验签、客户端对响应签名的校验均通过。

## PoC

webpack 模块定位（概念）：

```javascript
// 枚举 chunk 与模块，定位加密封装
// chunk 3 -> module 10：请求加密编排
// chunk 1 -> module 63：{sm2, sm3, sm4} 封装
// chunk 1 -> module 144：{sm2: n(834), sm3: n(838), sm4: n(839)}
```

协议复现（Python，gmssl）：

```python
from gmssl import sm4

def sm4_cbc_encrypt(key_hex, iv_hex, plaintext):
    crypt = sm4.CryptSM4()
    crypt.set_key(bytes.fromhex(key_hex), sm4.SM4_ENCRYPT)
    return crypt.crypt_cbc(bytes.fromhex(iv_hex),
                           plaintext.encode("utf-8")).hex().lower()

def sm4_cbc_decrypt(key_hex, iv_hex, cipher_hex):
    crypt = sm4.CryptSM4()
    crypt.set_key(bytes.fromhex(key_hex), sm4.SM4_DECRYPT)
    return crypt.crypt_cbc(bytes.fromhex(iv_hex),
                           bytes.fromhex(cipher_hex))
```

签名与请求体（示意）：

```python
sm_sign = sm3_hash(f"data={data}&secretKey={secretKey}&shareKey={shareKey}")
body = {"secretKey": secretKey, "data": data, "smSign": sm_sign}
```

appservice 注入（Math.random + wx.request 双 hook，节选）：

```javascript
var origRandom = Math.random, origRequest = wx.request;
Math.random = function () {
  var v = origRandom();
  globalThis.__randomLog.push(v);
  return v;
};
Object.defineProperty(wx, 'request', {
  configurable: true, enumerable: true, writable: true,
  value: function (options) {
    globalThis.__lastReq = { url: options.url, data: options.data,
                             calls: globalThis.__randomLog.length };
    return origRequest.call(this, options);
  }
});
```

说明：PoC 为原文流程的结构化复现，未在本机执行；SM2 部分需按客户端实际模式（C1C2C3/C1C3C2）与公钥前缀处理。

## 变体与关联

- 变体：SM2 密文模式与公钥前缀在不同库/语言间不一致（C1C2C3 vs C1C3C2、`04` 前缀、ASN.1 编码）；原文代码与协议摘要图对模式的描述互相矛盾，需以抓包和客户端实现验证。
- 变体：请求体未变化时复用原始 secretKey，避免重新做 SM2 加密；只有修改请求体时才需要重新生成 shareKey 并重算 secretKey。
- 变体：加密逻辑下沉到原生插件/WASM 时，JS hook 失效，需要 Frida/native hook 或直接分析 WASM 导出函数。
- 变体：响应方向需要重新计算 `retSign`，否则客户端会拒绝展示；重加密必须使用同一 shareKey 与 IV。
- 关联：[[crypto-prng-math-random-sharekey-recovery]]（shareKey 的可预测性与恢复细节）；[[crypto-implementation-gmssl-sm2-publickey-lstrip-hex-case]]（gmssl 复现坑点）；[[pentest-recon-wechat-builtin-browser-debug-access]]（微信内置浏览器调试入口）。
- 边界：小程序启用强反调试/代码虚拟化、CDP/MCP 不可用、使用原生加密或证书固定且无法绕过时，本链不成立；解密只解决"看得见"，业务漏洞仍需单独测试。

## 检测与防御

- 检测：客户端出现 `Math.random` 派生密钥、固定 IV 从本地存储读取、SM3 签名串直接拼接密文与密钥；同一账号短时间大量重放/修改请求。
- 防御：密钥由服务端生成并绑定会话，客户端不持有可推导的会话密钥；使用 CSPRNG；签名覆盖请求上下文（时间戳、nonce、路径、设备指纹）并做服务端重放校验。
- 加固：对小程序代码做混淆/虚拟化/完整性校验，启用反调试；对敏感接口做证书固定与请求频率限制；不要把"传输加密"当作唯一防线。

