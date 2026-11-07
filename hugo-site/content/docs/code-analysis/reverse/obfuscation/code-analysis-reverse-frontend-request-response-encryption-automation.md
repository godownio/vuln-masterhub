---
id: code-analysis-reverse-frontend-request-response-encryption-automation
title: 请求与响应双层加密 API 的 JS 逆向与 PyExecJS 自动化
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: frontend-request-response-encryption-automation
tags:
- javascript
- reverse
- frontend-encryption
- aes
- md5
- sha256
- pyexecjs
- obfuscation
- api-automation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:32:15+08:00'
  notes: 已对照原文与 54 张图核对：三种定位方法（全局搜索/XHR 断点/Initiator）、案例一 sign=md5('tuling'+ts+page)、案例二 xl=AES-CBC hex、案例三 s/tt 与响应 r 的 AES 解密、案例四无限 debugger+ob 混淆、实战案例 EncryptNew 的 Latin1.parse 用法与 AES-192 关系均一致；卡片还正确标注了原文 get_sign 不返回值、响应字段 r/t 差异等需修正点；未实际运行脚本
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-frontend-request-response-encryption-automation/
draft: false
kb_aliases:
- 前端请求响应加密逆向
- 双层加密 API 逆向
- XHR 断点定位加密
- PyExecJS 自动化请求
- 自定义 MD5 签名还原
- AES 响应解密
- 前端加密扣 JS
---

## 一句话结论

当接口的请求参数/请求头被前端签名或加密、响应体又被整体加密时，全局搜索参数名往往失效；此时用 XHR/fetch 断点按 URL 路由断住发送点，再通过 Initiator/调用栈定位 JS，扣出签名与加解密函数，最后用 Node 或 PyExecJS 在本地复现，即可自动化构造合法请求并解密响应。

## 原理

- 前端加密/签名不是安全边界：浏览器必须能拿到 key、iv 和签名算法，因此它们一定存在于 JS 中，或可在浏览器运行时调用。逆向的目标不是“破译密码”，而是“复用浏览器已有的计算”。
- 定位加密点的三种常用方法：
  1. 全局搜索参数名（`sign`、`xl`、`m`、`ts`、`r`、`bodyData`），在赋值/调用处下断点；
  2. XHR/fetch 断点：Sources → XHR/fetch Breakpoints → 添加 URL 子串（如 `api/problem-detail/4/data/`），刷新后会在发送请求的位置断住；
  3. 从 Network → Initiator/Request call stack 入手，点击调用栈中的 JS 文件跳到发送函数。
- 当请求参数和响应体都被加密时，参数名可能只出现在发送函数里（如 `body: JSON.stringify({xl: encryptedQuery})`），全局搜索结果会落在无关的压缩代码上；XHR 断点和 Initiator 更可靠。
- 常见多层结构：
  - 请求头签名：`m = MD5(salt + timestamp)`、`ts = timestamp`、URL 参数 `x = SHA256(m + salt2)`；服务端用同样算法校验时间窗口与完整性。
  - 请求体加密：把 JSON 序列化后 AES-CBC/PKCS7 加密，再 Hex 或 Base64 编码，作为 `xl`/`bodyData` 等字段。
  - 响应体加密：服务端返回 `{r: "<hex>"}`，前端在 `$.addResponseInterceptor` 或 `.then(data => JSON.parse(decrypt(data.r)))` 中解密。
- 自定义 MD5：站点可能把标准 MD5 重写成 `window.md5`/`window.xxoo`；算法本身可能仍是标准 MD5，但拼接顺序、盐值、大小写、输出编码必须完全一致。逆向时直接扣原函数最稳，避免自己实现时细节不一致。
- PyExecJS 通过本地 Node/JavaScript 运行时执行扣出的 JS，Python 负责发请求、解密响应和分页；也可以改用 JSRPC 把浏览器里的原函数暴露给 Burp（见关联卡）。

## 触发条件

- 目标接口的请求参数/请求头由前端 JS 生成签名或加密，响应体也可能被加密。
- 攻击者能访问页面、加载 JS、使用 DevTools 断点/Console，并持有合法会话（Cookie/Token）。
- key/iv/算法存在于 JS 或浏览器运行时；服务端未使用无法复现的硬件绑定/一次性 nonce（若有一次性的 nonce，需要同步获取）。
- 接口本身允许被自动化访问（无验证码、频控或风控可接受）。

## 利用步骤

1. 抓一个正常请求，标记可疑字段：`sign`、`_ts`、`xl`、`m`、`ts`、`x`、`r`、`bodyData`。
2. 优先用全局搜索定位参数名；若无结果或结果无关，改用 XHR/fetch 断点（URL 子串）或 Network → Initiator。
3. 断住后查看调用栈和 Local 变量，确认：
   - 加密算法（AES/DES/RC4 等）、模式（CBC/CFB/GCM）、填充（PKCS7/NoPadding）；
   - key/iv 的来源（硬编码字符串、`WordArray`、`Latin1.parse`、`Utf8.parse`）；
   - 输入拼接顺序（盐值、时间戳、页码、JSON 序列化方式）。
4. 若代码被 ob 混淆，用 DevTools 的“显示用法”、Console 求值或在线反混淆工具还原；重点保留函数语义，不必完全还原变量名。
5. 扣 JS：把加密/解密函数及其依赖（MD5/SHA256/AES 实现、工具函数）复制到独立 `.js` 文件，用 `node` 运行，逐个补齐 `ReferenceError` 的函数，直到能输出预期结果。
6. 把 `get_sign`/`encrypt`/`decrypt` 改成返回值的函数，供 Python 调用；用 PyExecJS `execjs.compile(js).call(...)` 调用。
7. Python 用 `requests` 发请求，带上生成的签名/加密参数和 Cookie；拿到响应后调用 JS 解密函数，`json.loads` 解析。
8. 遍历分页/枚举参数，累计结果或提取敏感字段。

## PoC

扣出的 JS 骨架（签名 + 响应解密）：

```javascript
// window.md5 / window.xxoo 为站点自带的 MD5 实现，需从目标 JS 原样扣出
function get_sign(pageNumber) {
  const ts = new Date().getTime();
  const sign = window.md5("tuling" + ts + pageNumber); // 盐值、拼接顺序按目标改
  return { sign, ts };
}

const CryptoJS = require("crypto-js");
const AES_KEY = CryptoJS.enc.Utf8.parse("xxxxxxxxoooooooo"); // 按目标 key 改
const AES_IV  = CryptoJS.enc.Utf8.parse("0123456789ABCDEF"); // 按目标 iv 改

function decrypt_response(hexCipher) {
  const ct = CryptoJS.enc.Hex.parse(hexCipher);
  const pt = CryptoJS.AES.decrypt({ ciphertext: ct }, AES_KEY, {
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
    iv: AES_IV,
  });
  return pt.toString(CryptoJS.enc.Utf8);
}
```

Python + PyExecJS：

```python
import execjs, requests, json

with open("crypto.js", "r", encoding="utf-8") as f:
    ctx = execjs.compile(f.read())

headers = {"User-Agent": "Mozilla/5.0", "Referer": "https://target/problem-detail/4/"}
cookies = {"sessionid": "<valid>"}
total = 0

for page in range(1, 21):
    r = ctx.call("get_sign", page)          # {"sign": "...", "ts": ...}
    resp = requests.get(
        "https://target/api/problem-detail/4/data/",
        headers=headers, cookies=cookies,
        params={"page": page, "sign": r["sign"], "_ts": r["ts"]},
    )
    data = resp.json()
    total += sum(data["current_array"])
print("sum =", total)
```

响应加密场景：

```python
resp = requests.get(url, headers=headers, cookies=cookies, params={"page": 1})
cipher_hex = resp.json()["r"]               # 原文案例中字段为 r
plain = ctx.call("decrypt_response", cipher_hex)
obj = json.loads(plain)
print(obj["current_array"])
```

自定义 MD5 的两种处理方式：

```javascript
// 方式一：直接扣站点实现（推荐，保证盐值/拼接/编码一致）
window = this;
(function (n) { /* 站点自带的 MD5 压缩函数与 window.md5 赋值，原样复制 */ })();

// 方式二：确认是标准 MD5 后，用 Node crypto 实现
const crypto = require("crypto");
function md5(s) { return crypto.createHash("md5").update(s, "utf8").digest("hex"); }
```

说明：

- 原文案例中 `get_sign` 只 `console.log` 不返回值、Python 却读取 `result["sign"]`/`result["ts"]`，直接照抄会失败；应改成 `return {sign, ts}`。
- 原文案例中请求体 `xl` 是 JSON 字符串经 AES-CBC 加密后的 Hex；响应字段在不同题目中是 `r` 或 `t`，以实际抓包为准。
- 真实案例中 `EncryptNew` 使用 `g.enc.Latin1.parse(key)` 与 `Latin1.parse(iv)`：key 字符串 `eHwvBmaIKWkTYyMBDKEHqQ==` 按 Latin1 解析为 24 字节（AES-192），iv `e33e6370750c37d9` 为 16 字节；复现时必须使用相同的解析方式，不能想当然做 Base64 解码。

## 变体与关联

- 变体：仅有请求签名（无响应加密）时，只需复现签名函数；见 [[web-generic-auth-js-signature-jsrpc-autodecoder]] 的 JSRPC 运行时代签方案。
- 变体：单字段 AES 加密（`content`）、key/iv 提取与 `iv||密文` 拆分，见 [[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]。
- 变体：key/iv 以 CryptoJS `WordArray` 数值数组传递，见 [[code-analysis-reverse-obfuscation-cryptojs-wordarray-key-restore]]。
- 变体：无限 `debugger` 反调试，见 [[code-analysis-reverse-anti-debug-js-infinite-debugger-bypass]]。
- 变体：响应加密的定位点在 `$.addResponseInterceptor`、axios 响应拦截器或 `.then(data => decrypt(data))`；先搜 `decrypt`、`AES`、`Hex.parse`。
- 边界：服务端使用一次性 nonce、设备指纹、mTLS 或把密钥放到 WebAssembly/原生层时，单纯扣 JS 可能不够，需要运行时 hook/JSRPC 或动态调试。

## 检测与防御

- 防御：前端加密/签名只能提高自动化成本，不能作为保密或身份认证；传输安全依赖 TLS。
- 防御：服务端对关键接口做身份、对象级权限和业务规则校验，不能因为“参数已加密/签名正确”就信任内容。
- 防御：签名加入服务端 nonce（一次性）、时间窗口、会话绑定和设备指纹；对高频、参数递增的请求做频控/风控/验证码。
- 检测：同一会话在短时间内大量请求，签名全部合法但参数呈枚举特征；请求头/参数顺序与正常前端不一致；来自自动化客户端（无浏览器指纹、TLS 指纹异常）的请求。
- 检测：前端 bundle 中出现硬编码 AES key/iv、`CryptoJS.AES.decrypt`、`Hex.parse`、自定义 MD5 与固定盐值；服务端可对这些特征做资产排查，但不应依赖隐藏密钥。
