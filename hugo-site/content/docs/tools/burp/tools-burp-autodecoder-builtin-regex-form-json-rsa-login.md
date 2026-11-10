---
id: tools-burp-autodecoder-builtin-regex-form-json-rsa-login
title: autoDecoder 内置加解密主体 + 正则提取：表单与 JSON 两种密文载体的配置差异，覆盖固定 AES key、服务端下发不变 key、RSA 公钥单向加密三类登录爆破
type: scenario
domain: tools
path: tools/burp
technique: autodecoder-builtin-regex-carrier-rsa-oneway-bruteforce
tags:
- burp
- autodecoder
- frontend-encryption
- aes
- rsa
- regex-extraction
- bruteforce
- login
- tooling
- burp-extension
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-6
  verified_at: '2026-11-08T01:55:23+08:00'
  notes: 已对照原文核对；三类场景（固定 AES key、服务端下发不变 key、RSA 公钥单向）的 key/iv 取值、表单与 JSON 两种载体正则写法、AES/CBC/PKCS5Padding 与 key/iv 编码选 Base64、RSA 仅配加密方向，均与正文代码块及截图一致；截图另佐证「插件报解密错误但服务端 success:true」这一点，卡内已写明。未验证点：autoDecoder 面板按钮名（保存配置等）按截图归纳，未在工具内实测；原文爆破字典仅 4 条，命中率普适性未验证。dedup 最近候选为 Flask 脚本路线卡，与本卡内置配置路线互补，非同一条链。
url: /docs/tools/burp/tools-burp-autodecoder-builtin-regex-form-json-rsa-login/
draft: false
kb_aliases:
- autoDecoder 内置加解密
- autoDecoder 正则提取
- 加解密主体配置
- Sessionkey Ivparameter
- 前端加密登录爆破
- AES 固定 key 爆破
- 服务端下发 key 爆破
- RSA 公钥加密爆破
---

## 一句话结论

前端加密登录并不需要每次都写加解密脚本：autoDecoder 的“加解密主体”能直接选算法/模式/填充并填 `Sessionkey`/`Ivparameter`，再用一条正则从原始报文里把密文抠出来；真正决定能不能跑通的是**密文载体形态**（`encryptedData=<ct>` 的表单体 vs `{"encryptedData":"<ct>"}` 的 JSON 体，正则写法完全不同）、**key 材质的编码**（UTF-8 字符串 vs Base64 解析后的原始字节）、以及**加密方向**（AES 是双向可解密，RSA 只有公钥时只能构造密文、靠猜明文结构）。三者配对成功后即可在 Intruder 里用明文口令字典直接爆破前端加密的登录接口。

## 原理

- **为什么不写脚本也能做**：客户端必须持有 key/iv 才能加密，因此 key/iv 一定在 JS 里（硬编码）或在可访问的接口里（服务端下发）；`CryptoJS.AES.encrypt(jsonData, key, {iv, mode, padding}).toString()` 这一套参数是标准化的，autoDecoder 的内置实现可以直接等价复现，无需把整个 JS 算法搬进 Python。
- **三类场景的差别只在 key 来源**：
  1. **固定 key**：JS 里 `CryptoJS.enc.Utf8.parse("1234567890123456")` 直接给 key 与 iv（各 16 字节）。配置里把 16 字符原样填进 `Sessionkey`/`Ivparameter`，算法 `AES`、模式 `CBC`、填充 `PKCS5Padding` 即可双向转换。
  2. **服务端下发、但每次相同**：JS 先 `fetch(".../server_generate_key.php")` 拿 `{"aes_key":"...","aes_iv":"..."}`，再 `CryptoJS.enc.Base64.parse(...)` 得到 `WordArray`。关键点是**下发的 key/iv 是常量**——多次刷新页面拿到的 Base64 完全相同，于是把 Base64 解出的原始字节填进配置（工具里 key/iv 的编码选项要选 `Base64`，而不是把 Base64 字符串当 UTF-8 文本填进去），就能固定下来。
  3. **RSA 公钥单向**：JS 用 `JSEncrypt().setPublicKey(publicKey).encrypt(JSON.stringify({username,password}))`，页面里给的是公钥。只有公钥时无法解密，但攻击方向本来就只需要**加密**：把明文结构（`{"username":"...","password":"..."}`）复刻出来，让工具把明文换成密文再发出。此时“解密”只是可选的调试手段（能解出来更好，解不出来只要明文结构对就能打）。
- **正则提取是真正的配置难点**：autoDecoder 需要先从原始报文里定位密文子串，再做解密/加密替换，因此正则必须精确匹配载体：
  - 表单体：`encryptedData=nArXfVdnoe67...%2B...`（值做过 URL 编码），正则用 `encryptedData=(.*)`，提取到的串保留百分号编码；若服务端要求原文密文，需注意 `decodeURIComponent` 与 Base64 的 `+`/`/`/`=` 会被编码成 `%2B`/`%2F`/`%3D`。
  - JSON 体：`{"encryptedData":"/TU3Mh8yKqNBcTcVG..."}`，值里含 `/`、`+`、`=`，正则必须写成 `"encryptedData":"(.*)"`（带引号），否则会把后面的 `}` 一起吞掉或漏掉引号导致解密失败。
  - 正则写错或 key 编码选错时，插件只会返回“解密错误，请确认选项无误”，不会指出哪一项错了——所以要先在“加解密主体”面板里用手工粘贴的密文点一次 `decrypt>` 验证，再去配请求/响应方向。
- **爆破为什么可行**：加密只是把明文包一层，服务端解密后仍按明文比对用户名/口令。只要工具能把 Intruder 的 payload（明文口令）实时加密成合法密文，登录接口的失败/成功判据与明文登录完全一致，弱口令字典照常有效。原文用 `123456` 一击命中，响应出现 `{"success":true}`，其余错误口令返回“解密成功但登录失败/解密错误”的差异响应。
- **判据要看解密后的响应**：响应若也被加密，需要在响应方向也配一条解密规则，否则 Intruder 只能看到密文长度差异；原文的案例响应为明文 JSON（含 `success` 字段），所以只在请求方向配加密即可，响应直接按 `success` 与响应长度区分。

## 触发条件

- 登录（或其它敏感接口）的请求体经过前端对称/非对称加密，且密文以单一字段承载（`encryptedData`、`data`、`content` 等）。
- 已能从 JS 得到算法、模式、填充与 key 材质：固定 key/iv 的字符串，或服务端下发接口返回的 Base64 key/iv，或 RSA 公钥（至少能得到明文结构）。
- Burp 已安装 autoDecoder，且能正常代理目标流量。
- 服务端未对同一账号/同一 IP 做严格失败次数限制、验证码或设备指纹（否则爆破侧仍需绕过这些）。
- 仅用于授权测试。

## 利用步骤

1. **抓一次登录包，确认载体**：看 body 是 `encryptedData=<urlencoded ct>` 还是 `{"encryptedData":"<ct>"}`，据此决定正则。
2. **在 JS 里定位加密逻辑**：登录按钮处下断点或搜索 `encryptedData`/`AES.encrypt`/`setPublicKey`，读出算法、模式、填充、key/iv 来源。
3. **区分 key 形态**：`CryptoJS.enc.Utf8.parse(...)` 说明 key 是 16/24/32 字节的 UTF-8 文本，原样填；`CryptoJS.enc.Base64.parse(...)` 说明是 Base64 包装的原始字节，配置里 key/iv 编码选 `Base64` 并把 `aes_key`/`aes_iv` 字符串粘进去。
4. **先在主体面板验证**：把抓到的密文粘进 `Ciphertext(密文)`，点 `decrypt>`，`Plaintext(明文)` 出现 `{"username":"admin","password":"123"}` 才继续；失败就依次改 算法/模式/填充/key 编码/iv。
5. **配请求方向规则**：`添加为请求包加解密方式`，正则框填对应载体正则（表单 `encryptedData=(.*)`，JSON `"encryptedData":"(.*)"`），并点 `提取` 确认右侧预览正好是密文本体（不含 `}`、不含外层引号）。
6. **配响应方向（按需）**：若响应也是密文，用同样的方式加一条响应解密规则；响应为明文则跳过。
7. **保存并重放**：点 `保存配置`（不点不生效），Repeater 里重发一次，确认请求体已被自动加密、响应可读。
8. **转 Intruder 爆破**：把 `password` 明文位置的密文替换成占位（或让插件在发送前加密整个明文包），payload 位置设为明文口令字典；判据用 `success` 字段、响应长度或状态码组合，注意先跑一个正确口令确认判据有效。
9. **RSA 场景**：只配“请求加密”（填公钥或用工具内置 RSA 公钥），明文结构按 JS 的 `JSON.stringify` 顺序复刻；不追求解密响应。
10. **收尾**：记录 key/iv/算法/正则/明文结构，配置可复用到同站其它加密接口（换正则与 URL 即可）。

## PoC

三类场景的 autoDecoder 内置配置要点（均为配置参数，非攻击 payload）：

```text
场景 A：AES 固定 key
  Encrypt=AES, Vector=CBC, Padding=PKCS5Padding
  Sessionkey=1234567890123456        (16 字节 UTF-8)
  Ivparameter=1234567890123456       (16 字节 UTF-8)
  载体: encryptedData=nArXfVdnoe67UzojAPP2X%2B6qSiznLMBAI3a5Bi...
  正则: encryptedData=(.*)

场景 B：服务端下发、但不轮换的 key
  Encrypt=AES, Vector=CBC, Padding=PKCS5Padding
  key/iv 编码=Base64
  Sessionkey=kKdgeorsQ3yDQFrea6+HiA==      (来自 server_generate_key.php 的 aes_key)
  Ivparameter=QjPxaafcSkhfbIZ5a6Oqig==     (来自 aes_iv)
  载体: {"encryptedData":"/TU3Mh8yKqNBcTcVGqXTSwSz0T0/lmSAzTbJg7HWOSBs..."}
  正则: "encryptedData":"(.*)"

场景 C：RSA 公钥（单向）
  Encrypt=RSA, 公钥=页面 JS 中的 PEM
  明文结构（按 JS 的 JSON.stringify 顺序）:
    {"username":"<payload>","password":"<payload>"}
  载体: data=<RSA 密文>
  正则: data=(.*)
  说明: 不需要解密响应；只要加密后的密文能被服务端私钥解开，登录判据就生效。
```

最小验证判据（Intruder 结果表）：

```text
payload=123456  → 200, 响应体 {"success":true}
payload=12      → 200, 响应体提示用户名或密码错误 / 解密错误
```

注意：原文实测截图里，当响应方向也配了解密规则、而服务端返回的其实是明文 JSON 时，插件会抛出自己的异常栈（`com.autoDecoder.util.codeDecode.decryptKeyivmode` → `Cipher.doFinal` → 提示“解密错误，请确认选项无误！”），但服务端业务响应仍是 `{"success":true}`。结论有两条：一是“插件报解密错误”不等于“请求失败”，响应判据要看业务字段与响应长度；二是响应本身就是明文时，不要给响应方向配解密规则。

## 变体与关联

- 变体：**全报文加密**（不是单字段）时，正则改为匹配整个 body（如 `^([\s\S]*)$`），或改用 Flask 脚本方式处理（见关联卡 `tools-burp-autodecoder-flask-custom-encrypt-decrypt-script`）。
- 变体：key/iv 以 CryptoJS `WordArray` 数值数组传递（`{words:[...],sigBytes:N}`）时，需要先按大端序还原字节，再填入 key/iv；见 `code-analysis-reverse-obfuscation-cryptojs-wordarray-key-restore`。
- 变体：key 由 `Math.random()` 逐字符生成或每次随机时，单纯配 key 不够，要在响应方向改 JS 把随机表达式固定（见 `web-generic-auth-frontend-js-random-key-fixation-autodecoder`）。
- 变体：AES 包裹 + RSA 包裹 AES key 的混合方案（`key` 字段是 RSA 密文、`content` 是 AES 密文）需要在 auth 侧同步重算，见 `web-generic-auth-hybrid-rsa-aes-login-bruteforce`。
- 关联：`code-analysis-reverse-frontend-request-response-encryption-automation`（key 动态或算法复杂时的完整 JS 逆向 + PyExecJS 路线）、`web-generic-auth-server-key-sign-oracle-replay-reproducible`（服务端下发密钥 + 代签仍可复现的整体论证）、`web-generic-auth-cas-aes-cbc-login-encryption-reverse`（登录参数 AES-CBC 逆向）。
- 边界：本卡描述的是测试工具配置流程，不代表目标存在具体漏洞；能否爆破仍取决于服务端的失败计数、验证码与口令强度。

## 检测与防御

- 检测（服务端视角）：同一 IP/账号在短时间内出现大量登录请求、密文长度相近且仅少数位变化、密文解密成功但账号口令错误的连续失败——这是“前端加密被工具复现后爆破”的典型信号。
- 检测：前端 bundle 中出现 `CryptoJS.enc.Utf8.parse("...")` 形式的硬编码 key/iv、`JSEncrypt` 公钥、以及 `encryptedData` 单字段请求体，都说明加密只是封装。
- 防御：前端加密不能替代 TLS，也不能作为认证强度；必须配合服务端失败计数、账号锁定、验证码/风控、设备指纹。
- 防御：key 不应硬编码在 JS；即使使用前端加密，也应服务端下发**每次不同**的会话密钥并绑定会话/时间戳/nonce，且服务端同时校验签名与业务权限。
- 防御：登录接口做全局限速与异常检测（同一密文被重放、同一 key 被长时间复用、解密失败率异常）；敏感操作加二次校验。
- 通用原则：凡客户端能算出的东西都不是秘密；加密只能提高自动化成本，攻击者可原样复现。
