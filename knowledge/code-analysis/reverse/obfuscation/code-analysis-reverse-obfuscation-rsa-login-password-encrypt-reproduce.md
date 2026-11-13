---
id: code-analysis-reverse-obfuscation-rsa-login-password-encrypt-reproduce
title: 前端登录 RSA 密码加密复刻：定位 getPwd/RSAKey，复用 setPublic(modulus,exponent) 或 RSAKeyPair+encryptedString 生成密文
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: frontend-rsa-login-password-encrypt-reproduction
aliases:
- RSAKey 登录加密逆向
- encryptedString 复刻
- setMaxDigits RSAKeyPair
- enpassword 加密
- key_to_encode
- 前端 RSA 登录密码
- getPwd 加密函数
tags:
- javascript
- reverse
- frontend-encryption
- rsa
- jsbn
- login
- password
- devtools
- console
- api-automation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V656
  verified_at: '2026-11-13T06:39:57+08:00'
  notes: 已对照原文35张截图核对：getPwd中j.RSAKey/setPublic(a.result.modulus,a.result.publicExponent)/encrypt(b.val())与图17/19/22逐字一致；db构造与prototype setPublic=eb/encrypt=gb/doPublic=fb、c.exports={RSAKey:db}与图21/23/25一致；实战2 setMaxDigits(129)+RSAKeyPair(010001,空,modulus)+encryptedString与图33/34/35一致，getpwd(123)在乐易模块成功输出密文；enpassword/J_RsaPsd字段与图16一致。已修正原文未支持且技术上存疑的setMaxDigits位数推断。未验证点：原文未回放登录请求做端到端验证，仅控制台/JS运行器验证密文生成，confidence medium属实。
---

## 一句话结论

登录表单把密码用前端 RSA 加密后再提交时，公钥与加密实现必然存在于页面 JS 中：通过 onClick/Event Listeners/源码搜索/断点定位到 `getPwd`、`encryptedString` 等加密函数后，把 jsbn 风格的 `RSAKey`（`setPublic(modulus, publicExponent)` + `encrypt`）或 `RSAKeyPair("010001","",modulus)` + `encryptedString` 连同公钥参数扣到控制台/JS 运行器里，即可对任意明文生成合法密文，供脚本化登录与口令测试使用。

## 原理

- **前端加密不是安全边界**：浏览器必须能算出密文，所以 RSA 公钥（modulus/exponent）、算法实现（jsbn/JSEncrypt 等）一定存在于 JS 或可在运行时调用；RSA 公钥本身可以公开，用它加密不构成身份认证，服务端只校验"能否用私钥解开并进入登录逻辑"，不区分密文由浏览器还是脚本生成。
- **两种常见实现形态**（原文两处实战）：
  1. 运行时从接口取公钥：`c = new j.RSAKey; c.setPublic(a.result.modulus, a.result.publicExponent); var d = c.encrypt(b.val());`，其中 `a.result` 来自页面初始化时的 AJAX 响应，`b.val()` 是用户输入的明文密码。
  2. 页面内嵌公钥：`setMaxDigits(129); var key_to_encode = new RSAKeyPair("010001","", "<modulus hex>"); encryptedString(key_to_encode, password)`，以隐藏字段（如 `RsaPwd`/`enpassword`/`pwd`）随表单提交。
- **jsbn 实现为何可扣**：打包后的代码里通常有 `db` 构造函数（`RSAKey` 的导出名），原型上挂着 `setPublic = eb`、`encrypt = gb`、`doPublic = fb`，末尾 `c.exports = { RSAKey: db }`；把该模块整体复制到控制台、改写 `RSAKey = db` 并删除未定义的包装依赖即可直接调用。
- **定位方法**：提交按钮的 `onclick="sologin(this)"`/`getPwd(...)` 直接给出函数名；或无内联属性时用 DevTools Event Listeners 面板看 click 绑定；或把页面另存后对元素 id/class（如 `#J_SubmitStatic`）全文搜索；最后在 Sources 中对加密函数下断点，F10/F11 单步查看 `b.val()` 与 `c.encrypt(...)` 的实参和返回值。

## 触发条件

- 登录/提交表单的密码字段由前端 JS RSA 加密后提交（请求中出现 `enpassword`、`pwd`、`RsaPwd` 等密文字段）。
- 公钥参数可从页面/接口获得：运行时下发的 `modulus/publicExponent`，或内嵌的 `RSAKeyPair` 常量。
- 登录流程没有与设备绑定的一次性因子（或仅要求同一会话内密文）；有验证码/风控时只影响后续脚本化尝试的可行性，不影响密文复刻本身。

## 利用步骤

1. 抓一次正常登录请求，确认密文字段名与提交格式。
2. 定位加密函数：看提交按钮的 onclick、Event Listeners 的 click 绑定、对元素 id/class 全文搜索，并在加密函数上下断点单步确认调用链（`b.val()` 为明文、`c.encrypt(...)` 为密文）。
3. 记录公钥来源：若 `setPublic(a.result.modulus, a.result.publicExponent)`，找到返回 `result` 的接口/页面变量；若 `RSAKeyPair("010001","","<modulus>")`，直接取页面中的常量。
4. 扣 JS：从 webpack `define` 模块中复制 RSAKey 实现，改写导出（如 `RSAKey = db`），删除外部未定义的包装变量，在 Console 或 JS 运行器（如乐易模块）中先执行定义再调用。
5. 调用加密函数生成密文并提交；脚本化时把同一段 JS 交给 Node/PyExecJS/JS 运行器执行，Python 负责发送请求。

## PoC

在原页面控制台（或抠出的 JS 运行器）中：

```javascript
// 形态一：服务端下发 modulus/publicExponent
RSAKey = db;                     // db 为该 bundle 中 RSAKey 的导出函数
c = new RSAKey;
c.setPublic("<modulus_hex>", "010001");
c.encrypt("123456");             // 返回 RSA 密文

// 形态二：页面内嵌 key_to_encode
setMaxDigits(129);
key_to_encode = new RSAKeyPair("010001", "", "<modulus_hex>");
encryptedString(key_to_encode, "123");
```

说明：`<modulus_hex>` 用目标页面实际值替换；原文截图显示 modulus 为长十六进制串，指数多为 `010001`。原文只在控制台/JS 运行器验证密文生成，未回放登录请求做端到端验证。

## 变体与关联

- 变体：公钥由接口动态下发且每次刷新变化时，脚本先请求公钥接口再加密；同一会话内通常可复用。
- 变体：`setMaxDigits` 的取值需与页面实现及 key 长度一致，直接沿用页面原值最稳妥（原文两处实例均调用 `setMaxDigits(129)` 后再 `new RSAKeyPair(...)`），扣出的实现要与页面一致。
- 变体：若使用 JSEncrypt/RSA-OAEP/WebCrypto 而非 jsbn，则按对应库或 Node `crypto` 复刻（见关联卡）。
- 关联：[[code-analysis-reverse-obfuscation-weapi-asrsea-aes-rsa-hop-param-forge]]（同样使用 `setMaxDigits + RSAKeyPair + encryptedString`，但为 AES+RSA 嵌套接口参数）、[[code-analysis-reverse-obfuscation-rsa-oaep-dom-public-key-parameter-forge]]（RSA-OAEP 公钥还原与参数伪造）、[[code-analysis-reverse-frontend-request-response-encryption-automation]]（前端加密定位与自动化的通用方法论）、[[code-analysis-reverse-obfuscation-devtools-scope-edit-plaintext-before-encrypt]]（不扣算法的另一种绕过）。

## 检测与防御

- 前端加密只能提高抓包/改包成本，不能替代服务端校验：登录接口必须做失败次数限制、验证码、设备指纹与风控，避免仅凭密文即可无限尝试。
- 不要把公钥加密当作身份凭据；服务端对登录参数做频率与来源异常检测，监控脚本化登录特征（固定间隔、无鼠标/键盘事件、异常 UA/指纹）。
- 代码层面可对关键函数做轻度混淆/反调试，但应明确其只是增加逆向成本。
