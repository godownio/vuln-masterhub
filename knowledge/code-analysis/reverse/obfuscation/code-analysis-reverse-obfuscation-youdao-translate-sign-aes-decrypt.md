---
id: code-analysis-reverse-obfuscation-youdao-translate-sign-aes-decrypt
title: 有道翻译 webtranslate 签名与响应解密：md5(client&mysticTime&product&key) + ydsecret 硬编码 key/iv 的 AES 解密密文
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: youdao-translate-sign-md5-aes-decrypt
aliases:
- 有道翻译 sign 逆向
- 有道 webtranslate 接口
- ydsecret://query/key
- ydsecret://query/iv
- mysticTime 时间戳签名
- 翻译接口响应解密
- fanyideskweb webfanyi
tags:
- javascript
- reverse
- frontend-signature
- md5
- aes
- api-automation
- youdao
- translate
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V528
  verified_at: '2026-11-11T15:09:39+08:00'
  notes: '已对照原文与截图核对：img32 key接口返回secretKey/aesKey/aesIv三值、img36 sign: k(o,e) 的md5拼接与ydsecret key常量、img37 createDecipheriv(aes-128-cbc,...)解密处及local scope中key/iv均与卡片一致；卡片已修正原文代码实参顺序含糊问题。未验证点：AES key派生/IV拆分原文未给全，未本地解密复现（confidence medium已注明）。dedup候选为不同产品/通用流程卡，非重复。'
---

## 一句话结论

有道翻译网页版一次翻译会依次请求 `key`、`webtranslate` 等接口，变化的只有 `sign`（32 位十六进制，MD5）与 `mysticTime`（时间戳）；签名算法为 `md5("client=fanyideskweb&mysticTime=<ts>&product=webfanyi&key=<ydsecret key>")`，key 是 JS 中硬编码的 `ydsecret://query/key/...` 字符串；响应体为 AES 密文，需用该 key 与硬编码的 `ydsecret://query/iv/...` 解密后才能拿到翻译结果。

## 原理

- **接口序列**：一次翻译产生三个 XHR：第一个 `key` 请求携带 `sign`/`mysticTime`，响应固定的三个值 `{secretKey:"fsdogkndofkasdnosa", aesKey:"ydsecret://query/key/B*RG...", aesIv:"ydsecret://query/iv/C@lZe..."}`；第二个 `webtranslate` 请求同样只带 `sign`/`mysticTime`，响应加密后的翻译结果（base64 字符串）；第三个请求携带翻译内容、响应 OK。
- **定位签名**：`sign` 长度 32 且随请求变化，按 MD5 特征在 Sources 全局搜索 `md5`/`createHash`，很快命中签名函数；断点后可见 `o = (new Date).getTime()`（即 `mysticTime`），固定常量 `e = "ydsecret://query/key/B*RGygVywfNBwpmBaZg*WT7SIOUP2T0C9WHMZN39j^DAdaZhAnxvGcCY6VYFwnHl"`。
- **签名构造**：`sign = md5("client=fanyideskweb&mysticTime=" + o + "&product=webfanyi&key=" + e)`；`client`/`product` 是硬编码串，key 是 ydsecret 字面量（不是先请求 key 接口得到的值——key 接口的三个值用于后续加解密）。
- **响应解密**：`webtranslate` 返回密文；JS 截图显示使用 `crypto.createDecipheriv("aes-128-cbc", key, iv)`，key/iv 来自 `key` 接口返回的 `aesKey`/`aesIv` 字段（即硬编码的 ydsecret 字面量），密文为 base64。原文未给出完整 key 派生与 IV 拆分代码，复现时需在 DevTools 中确认 key 是否经 MD5 截断、IV 是否取自密文前 16 字节。
- **为什么可复现**：MD5 与常量都在前端 JS，服务端只校验 sign、时间窗口与 key 的正确性；Node `crypto` 可直接生成相同 MD5。注意原文代码片段把 `sign(e,t)` 的实参顺序写得含糊（`e` 被定义成 iv 字符串又作为第一个参数），按正文语义正确顺序应为 `sign(mysticTime, key)`。
- **边界**：`mysticTime` 若被服务端校验时间窗口，则需使用当前时间；key 接口返回的三个固定值可能与响应解密算法绑定，换时间/会话后需重新获取。

## 触发条件

- 有道翻译网页版接口可从浏览器正常请求，DevTools 可断点调试（原文 2024-02-24 版本）。
- 服务端未使用一次性 nonce、设备指纹或强制验证码；`mysticTime` 只做时间窗口校验。
- 前端 JS 中可定位 MD5 签名函数与硬编码 ydsecret 常量（未放入 WASM/服务端）。
- 需要登录态或匿名可用（原文未说明登录要求）。

## 利用步骤

1. 抓一次翻译，确认三个 XHR 的顺序与参数：`key` 请求的 `sign`/`mysticTime`、`webtranslate` 的 `sign`/`mysticTime`、内容请求。
2. 多次请求确认只有 `sign`（32 hex）与 `mysticTime` 变化；在 Sources 搜索 `md5`/`createHash` 定位签名函数并下断点。
3. 断住后记录：时间戳参数、`client=fanyideskweb`、`product=webfanyi`、硬编码 key 常量 `ydsecret://query/key/...`，确认拼接顺序。
4. 用 Node `crypto.createHash("md5")` 复刻签名，与抓包值比对；时间戳取当前毫秒。
5. 调用 `key` 接口获取三个 key 值，再带新 `sign`/`mysticTime` 请求 `webtranslate` 得到密文。
6. 在 JS 中步入密文处理位置，确认 AES 模式/填充与 key/iv 用法（截图为 `aes-128-cbc`，key/iv 来自 `aesKey`/`aesIv`），在本地解密响应，解析翻译结果。

## PoC

```javascript
const crypto = require('crypto');
const u = "fanyideskweb", d = "webfanyi";
const KEY = "ydsecret://query/key/B*RGygVywfNBwpmBaZg*WT7SIOUP2T0C9WHMZN39j^DAdaZhAnxvGcCY6VYFwnHl";
const IV  = "ydsecret://query/iv/C@lZe2YzHtZ2CYgaXKSVfsb7Y4QWHjITPPZ0nQp87fBeJ!Iv6v^6fvi2WN@bYpJ4";

function md5(s) { return crypto.createHash("md5").update(s, "utf8").digest("hex"); }

// 正确顺序：mysticTime 在前、key 在后（原文片段实参命名有误，此处按正文语义修正）
function sign(mysticTime, key) {
    return md5(`client=${u}&mysticTime=${mysticTime}&product=${d}&key=${key}`);
}

const ts = Date.now();
console.log(sign(ts, KEY));   // 与抓包 sign 比对
```

```text
# 三个 XHR 的用途：
# 1) key 请求：sign + mysticTime -> {"secretKey":"fsdogkndofkasdnosa",
#      "aesKey":"ydsecret://query/key/B*RG...","aesIv":"ydsecret://query/iv/C@lZe..."}
# 2) webtranslate：sign + mysticTime -> 返回 base64 AES 密文
# 3) 内容请求：携带翻译内容 -> OK
# 解密：crypto.createDecipheriv("aes-128-cbc", aesKey, aesIv)，key 派生/IV 拆分按 JS 实际调用确认
```

## 变体与关联

- 变体一：同站的 key 常量/iv 常量可能随版本更换，逆向时以实际 JS 为准，不要硬套本文值。
- 变体二：响应解密若走 CryptoJS，常见为 `CryptoJS.AES.decrypt(cipher, key, {iv, mode: CBC, padding: Pkcs7})`；key 的编码方式（Utf8/Latin1/Base64）必须以 JS 为准。
- 关联：[[code-analysis-reverse-obfuscation-baidu-translate-v2transapi-sign-restore]]（同文章另一签名案例）、[[code-analysis-reverse-frontend-request-response-encryption-automation]]（前端签名/响应解密的通用流程与 PyExecJS 自动化）。
- 边界：若服务端校验 `mysticTime` 时间窗口过短或绑定一次性 nonce，本地签名需与实时请求同步；AES 模式/填充/编码信息原文未给全，复现前必须在 DevTools 中确认。

## 检测与防御

- 检测：同一会话高频翻译请求、sign 合法但请求节奏与浏览器不一致；mysticTime 与服务器时间偏差异常；无浏览器指纹的自动化客户端。
- 防御：签名加入一次性 nonce 与服务端时间窗口、会话绑定；对翻译接口做频控、配额与风控验证码。
- 加固：前端加密/签名只提高成本，不是安全边界；敏感数据不要下发到客户端；响应加密的 key 定期轮换并绑定会话。
