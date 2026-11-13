---
id: code-analysis-reverse-obfuscation-jquery-ajax-rsa-aes-keyscript-automation
title: jQuery $.ajax 自动加密逆向：RSA 长文本+AES-ECB 嵌套 keyScript、动态公钥取明文与 execjs 自动化
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: jquery-ajax-rsa-aes-keyscript-reverse-automation
aliases:
- keyScript 加密
- RSA+AES 嵌套加密
- jQuery ajax 加密 hook
- JSEncrypt encryptLong 分段
- 动态公钥获取
- autoDecoder 注入 console.log 取明文
- execjs 复刻前端加密
- 前端加密接口自动化越权
tags:
- javascript
- reverse
- frontend-encryption
- rsa
- aes
- jquery
- jsencrypt
- execjs
- obfuscation
- api-automation
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V524
  verified_at: '2026-11-11T14:43:38+08:00'
  notes: 已对照原文与14张截图核对（全部经img_small降采样JPEG读取成功）：Burp可见keyScript密文请求；DevTools在login.js/common.js/encryptUtils.min.js定位；encryptUtils.min.js中failedList.length<460时RsaEncrypt→AesEncrypt→#keyScript；核心代码opt.data.keyScript=AesEncrypt(RsaEncrypt(JSON.stringify(isEncrypt)))、>460字段走noEncrypt；JSEncrypt加密库与encryptLong分段(byteNo%117/114阈值)在断点处得到hex→hex2b64；VM脚本中RsaEncrypt(window.publicKey)+AesEncrypt(CryptoJS ECB/Pkcs7)；公钥接口返回PEM body；autoDecoder Response body Literal替换var k=this.getKey();注入console.log(string)后控制台打印{"accountNo":"..."}明文；wt-js验证密文长度140845(约14万)与wk卡描述一致；execjs+Python脚本(JSEndec AES ecb/pkcs7/base64)与卡片自动化步骤一致。原文两个越权漏洞明确未展开，worker已在cards.json skipped说明并未拆卡，卡片边界亦声明未展开，合理。dedup：最高候选code-analysis-reverse-frontend-request-response-encryption-automation为通用XHR断点+请求响应加解密自动化方法论，非同链；hybrid-rsa-aes-login-bruteforce、rsa-oaep-dom-public-key-parameter-forge等均不同；全库dup-scan无本卡pair。原文无版本信息，未设affected_versions合理；卡片原子、无重复，保留并verified。
---

## 一句话结论

当 jQuery 站点重写 `$.ajax`，把请求中较短的字段先 RSA（`JSEncrypt.encryptLong` 分段）再 AES-ECB 加密成一个 `keyScript` 字段提交、RSA 公钥由独立接口动态下发时，可通过还原 eval packer 混淆定位加密函数、用代理改响应 JS 注入 `console.log` 打印加密前明文，再扣出 JSEncrypt/AES 函数用 execjs+Python 复刻加密，从而自动化构造合法请求测试越权。

## 原理

- **前端加密必然可复现**：浏览器要能加密，公钥、对称 key、算法与拼接顺序就都在 JS 或运行时中；逆向目标是复用浏览器的计算，而不是破解 RSA 本身（无私钥只能加密不能解密，所以目标是拿到加密前的明文与可重复的加密函数）。
- **ajax 全局 hook**：站点在 jQuery 层重写 `$.ajax`，每个请求的 `opt.data` 都会被处理——遍历字段，值长度超过阈值（原文 460）的字段放入 `noEncrypt` 原样提交（通常是大文本/文件类字段），其余放入 `isEncrypt`；最后 `opt.data.keyScript = AesEncrypt(RsaEncrypt(JSON.stringify(isEncrypt)))`，即先 RSA 加密整段 JSON 字符串，再把结果做 AES-ECB 加密，作为新字段 `keyScript` 提交，原短字段不再明文出现。
- **动态公钥**：`dynamicKey()` 在 `window.publicKey` 为空时发起同步 GET 请求，取响应 `data.body` 作为 PEM 公钥；由于页面初始化或每次加密都会触发公钥获取请求，抓包时能看到额外的 GET，复刻时可直接复用该响应。
- **RSA 长文本分段**：`JSEncrypt.prototype.encryptLong` 按 UTF-8 字节数每约 117 字节（1024 位 key 的块上限余量）切分子串，逐段 `encrypt` 后拼接十六进制再 `hex2b64`，因此长 JSON 也能一次 RSA 加密，最终输出长度固定比例放大（原文示例密文约 14 万字符）。
- **为什么能拿明文**：加密函数入参就是 `JSON.stringify(isEncrypt)` 的明文；在 `encryptLong` 的 `var k=this.getKey();` 之后打印 `string`，即可在 Console 看到完整业务明文，无需解密 RSA。
- **混淆还原**：入口 JS 用 Dean Edwards 式 `eval(function(p,a,c,k,e,r){...})` packer 压缩，字符串表替换后语义可读；格式化后在 Sources 中按 `keyScript`/`encryptLong`/`AesEncrypt` 等关键字定位，或直接在 VM 脚本中下断点跟进。

## 触发条件

- 目标站点基于 jQuery，抓包可见 `keyScript`（或类似）字段承载加密数据，且原业务字段在请求体中消失。
- 多段加密逻辑存在于可读/可解包的 JS 中；AES key 硬编码于 JS，RSA 公钥由接口下发且无一次性绑定。
- 攻击者可访问页面并持有普通账号/合法会话；接口本身允许自动化访问（验证码、风控可接受）。
- 目标业务接口存在对象级/数据级授权缺失（越权是加密之外的问题）。

## 利用步骤

1. 抓登录/业务请求，确认 `keyScript` 参数与额外公钥 GET 请求；全局搜索 `keyScript` 定位混淆的加密工具 JS（如 `encryptUtils.min.js`）。
2. 用格式化/在线 packer 解包或断点步过，找到 `$.ajax` 重写、`RsaEncrypt`、`AesEncrypt`、`dynamicKey`，确认：分流阈值（>460 明文）、嵌套顺序（先 RSA 后 AES）、AES 模式与 key。
3. 取明文：在 `JSEncrypt.prototype.encryptLong` 中 `var k=this.getKey();` 后插入 `console.log(string);`。无需改本地文件——用 Burp 的 autoDecoder（或代理）把 Response body 中该行替换为注入版本，刷新页面后 Console 即打印 `{"accountNo":"..."}` 等明文。
4. 取 RSA 公钥：读取公钥接口响应 body（`-----BEGIN PUBLIC KEY-----...`），或直接在 Console 打印 `window.publicKey`。
5. 本地扣 JS：拷贝站点 JSEncrypt 文件，首行加 `window = this; navigator = this;` 防报错，定义 `RsaEncrypt(message)` 并贴入公钥，用 node/wt-js 验证输出与抓包长度/格式一致。
6. 自动化：Python 用 `execjs.compile(js)` 加载扣出的 JS，循环 `context.call("RsaEncrypt", payload_json)` 得到 RSA 结果；AES-ECB/PKCS7/Base64 可用 Python 密码库（如 jsencdec/Crypto）复刻，或同样放进 JS；`requests` 携带 `keyScript` 与 Cookie 发请求。
7. 构造越权/枚举 payload（替换用户标识、放大分页、遍历 ID），批量发送并比对响应差异。

## PoC

扣出的 JS 骨架（公钥、AES key 按目标替换）：

```javascript
window = this;
navigator = this;
/* 原样粘贴站点的 jsencrypt.js / JSEncrypt 实现 */

function RsaEncrypt(message) {
    var encrypt = new JSEncrypt();
    encrypt.setPublicKey("-----BEGIN PUBLIC KEY-----\n<server-public-key>\n-----END PUBLIC KEY-----");
    return encrypt.encryptLong(message).toString();  // 长文本分段 RSA -> hex2b64
}

function AesEncrypt(message) {
    var key = CryptoJS.enc.Utf8.parse("<hardcoded-aes-key>");
    var srcs = CryptoJS.enc.Utf8.parse(message);
    return CryptoJS.AES.encrypt(srcs, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    }).toString();
}
```

Python + execjs 自动化骨架：

```python
import execjs, requests, json

js_code = open("crypto.js", "r", encoding="utf-8").read()
ctx = execjs.compile(js_code)

for uid in range(10001, 10010):
    plain = json.dumps({"id": str(uid)}, separators=(",", ":"))
    rsa_out = ctx.call("RsaEncrypt", plain)          # 分段 RSA 后 base64
    key_script = ctx.call("AesEncrypt", rsa_out)     # AES-ECB + PKCS7 + base64
    data = {"keyScript": key_script}
    r = requests.post("https://target/api/xxx", data=data,
                      cookies={"<session>": "<valid>"}, verify=False)
    print(uid, r.text)
```

Burp autoDecoder 注入明文（Response body，Literal 替换）：

```text
匹配: var k=this.getKey();
替换: var k = this.getKey();console.log(string);
```

说明：原文在真实站点上通过上述注入在 Console 打印出 `{"accountNo":"..."}` 完整明文，随后用 execjs + Python 复刻 RSA/AES 加密实现自动化测试，最终发现两个越权（原文未展开具体接口与参数）。以上域名、key、字段均为占位符，未在本会话执行。

## 变体与关联

- 变体：若 AES key 与 RSA 公钥都硬编码，可跳过动态获取，直接从 JS 提取常量和公钥即可。
- 变体：若只有 RSA（无外层 AES），只需复刻 `encryptLong`；若只有 AES，可直接用任意运行时实现，见 [[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]。
- 变体：响应体也被加密时，定位 `decrypt` 函数并用同一套扣 JS 流程还原，见 [[code-analysis-reverse-frontend-request-response-encryption-automation]]。
- 关联：[[code-analysis-reverse-dynamic-key-encrypted-api-idor]]——动态对称 key + 越权测试；本卡是动态 RSA 公钥 + 嵌套加密的另一形态。
- 关联：[[code-analysis-reverse-obfuscation-vjstools-plaintext-hook-encryption-locate]]、[[code-analysis-reverse-obfuscation-devtools-scope-edit-plaintext-before-encrypt]]——明文点定位/改值的其他手法；[[code-analysis-reverse-obfuscation-mcp-skill-jsrpc-autodecoder-automation]]——autoDecoder/JSRPC 自动化。
- 边界：公钥接口有一次性 nonce/设备绑定、AES key 在 WebAssembly/原生层、或站点对请求做 TLS 指纹校验时，单纯扣 JS 需配合运行时 hook；分流的 >460 大字段时间接明文提交，测试时注意该字段绕过加密直接传参。

## 检测与防御

- 防御：前端加密/签名只提高自动化成本，不构成授权；服务端必须对每个对象做归属校验，不能因 `keyScript` 合法就信任内容。
- 防御：RSA 公钥接口加会话绑定与频控；AES key 不硬编码在 JS（但仅隐藏密钥不足以防御）；分页与导出限制上限，敏感字段脱敏并审计。
- 检测：同一会话短时间遍历递增 ID/放大分页；请求中 `keyScript` 长度与结构异常（重放或固定公钥加密）；公钥接口被高频轮询；自动化客户端 TLS/浏览器指纹异常。
- 响应：发现越权后修复服务端对象级鉴权，评估已泄露数据范围，轮换相关会话与密钥。
