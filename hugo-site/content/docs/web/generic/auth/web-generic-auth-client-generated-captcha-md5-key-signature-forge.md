---
id: web-generic-auth-client-generated-captcha-md5-key-signature-forge
title: 图形验证码由前端本地生成、其值参与 key=MD5(硬编码salt+ts+手机号+验证码) 签名：提取 salt 后离线伪造任意验证码通过校验
type: scenario
domain: web
path: web/generic/auth
technique: client-generated-captcha-keyed-md5-signature-forge
tags:
- web
- business-logic
- captcha
- sms
- signature
- md5
- client-side-trust
- javascript
- brute-force
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V452
  verified_at: '2026-11-10T01:54:28+08:00'
  notes: 已对照原文与 17 张截图核对；key=MD5('Aw@XcsjiwWD'+ts+phone+verifyCode) 经复算与截图成功请求（ts=1712889983175、phone=18512341234、verifyCode=1234）的 key 48b03b82572c533d4278e714e7ca9455 一致；无验证码图片请求、E5017 时间戳过期、Intruder 批量 A0000 均有截图佐证；未被验证点：未在目标环境复跑
url: /docs/web/generic/auth/web-generic-auth-client-generated-captcha-md5-key-signature-forge/
draft: false
kb_aliases:
- 前端本地生成图形验证码
- 验证码 key 签名伪造
- oe 函数验证码绕过
- ts 时间戳校验绕过
- MD5 签名验证码形同虚设
- 发送短信验证码伪造
---

# 一句话结论

某个登录/绑定手机号的发送短信接口，其图形验证码由前端 JS 本地生成，验证码值 `b` 与手机号、毫秒时间戳一起参与 `key = MD5(硬编码salt + ts + phone + b)`，服务端重算同一公式并与请求里的 `key` 比对；由于 salt 硬编码在可下载 JS 中、验证码值也由客户端提供，攻击者可自选验证码值（如 1234）离线算出合法 `key`，图形验证码完全失效，可自动化调用发送短信、注册、登录爆破等被该验证码保护的接口。

# 原理

- **正常流程与本例的异常点**：正常图形验证码应由服务端生成答案并保存在服务端，前端只拿到图片；本例点击“获取验证码”时在 Network 中没有任何获取验证码图片的请求，说明图形验证码是前端 JS 本地生成字符串并绘制成图片，用户看图输入的值与前端内部变量 `b` 天然一致。
- **请求结构与签名公式**：发送短信请求体为 `{phone, key, ts, verifyCode, productId}`。业务 chunk 中计算逻辑为 `const o = new Date().getTime(); key: oe("Aw@XcsjiwWD" + o + a.value + b), ts: o + "", verifyCode: c.value`，其中 `a.value` 是手机号、`b` 是前端生成的图形验证码值、`c.value` 是用户输入。`oe` 经 `import {m as oe} from "./md5-xxxx.js"` 与库内 `export {md5 as m}` 对应，实际就是 js-md5。即 `key = MD5(salt + ts + phone + verifyCode)`。
- **服务端校验方式可被回显验证**：手工改动 `verifyCode` 后回显“验证码错误”，说明服务端是拿客户端提交的 `verifyCode` 重算 `MD5(salt + ts + phone + verifyCode)` 与 `key` 比对；先按猜测构造时回显“时间戳过期”（E5017），说明 `ts` 还有新鲜度窗口校验。
- **为什么校验必然失效**：`salt` 是客户端 JS 中的硬编码常量，`verifyCode`、`phone`、`ts` 都由客户端控制，服务端没有任何“只有它能生成的秘密”；攻击者对任意 `verifyCode` 都能算出匹配的 `key`，且时间戳可用 `Date.now()` 每次现取，于是“验证码校验”退化为客户端可复算的完整性哈希，不构成安全边界。
- **根因**：把“人机验证”实现为客户端可复算的哈希校验，且验证码答案本身由客户端生成；验证码值参与签名反而让攻击者一次掌握全部材料。

# 触发条件

- 图形验证码由前端生成（页面无获取验证码图片的请求），或验证码值参与客户端可复算的签名/加密。
- 签名或校验使用硬编码 salt/密钥，且相关 JS 可公开下载。
- 服务端仅校验 `key` 与 `verifyCode` 的一致性及时间戳窗口，无独立频率限制或行为验证。
- 攻击者能抓取发送短信/登录请求并访问前端 JS（无需登录或低权限会话即可）。

# 利用步骤

1. 访问登录/绑定页，点击“获取验证码”抓包，观察 Network 中没有图形验证码图片请求，记录请求体字段 `key`、`ts`、`verifyCode`、`phone`。
2. 在 DevTools Sources 全局搜索参数名 `verifyCode` 或 `key`，定位业务 chunk 中的计算行：`key = oe("hardcodedSalt" + o + phone + b)`、`ts: o`。
3. 在计算行下断点并触发发送，单步步入 `oe`；确认进入 `md5-*.js` 后，回到业务 chunk 搜索 import，找到 `import {m as oe} from "./md5-*.js"`，再在库 chunk 找到 `export {md5 as m}`，确认别名真身。
4. 美化 md5 库 chunk，删除 `export {md5 as m};` 行（否则 Console/JS 引擎报 `SyntaxError: export declarations may only appear at top level of a module`），在 Console 中执行 `md5('123')` 对照已知 MD5 值验证抠取成功。
5. 按 `key = MD5(salt + ts + phone + verifyCode)` 构造请求：`ts` 取当前毫秒时间戳，`verifyCode` 任取（如 1234），`key` 同步计算；先用 Repeater 单发，确认返回成功。
6. 用 BurpCrypto ExecJs 或脚本对手机号列表批量生成请求体（每次现取时间戳），确认接口无独立频控后自动化运行；控制发送量并保留证据。

# PoC

```js
// md5 为从目标前端库 chunk 抠出的 js-md5 纯函数；salt 以目标 JS 中实际硬编码值为准
function buildSmsBody(phone, captcha) {
  const ts = Date.now();
  const key = md5("Aw@XcsjiwWD" + ts + phone + captcha);
  return JSON.stringify({
    phone: phone,
    key: key,
    ts: String(ts),
    verifyCode: captcha,
    productId: ""
  });
}
// 示例：buildSmsBody("18512341234", "1234")
```

```http
POST /api/sms/send HTTP/1.1
Host: target.example
Content-Type: application/json

{"phone":"18512341234","key":"<MD5(salt+ts+phone+1234)>","ts":"<当前毫秒时间戳>","verifyCode":"1234","productId":""}
```

# 变体与关联

- **变体**：salt 换成 AES key、HMAC key 或固定拼接串；时间戳从严格窗口到完全不校验；有的实现只签手机号+验证码、TS 不参与，伪造更简单；同一套 key 可能同时保护注册、登录、找回密码等多个接口，绕过一次可复用。
- **识别信号**：验证码无图片请求、请求体带 `key`/`sign`/`ts`/`nonce` 等字段、JS 中出现 md5/sha1/hmac 调用与硬编码字符串。
- **关联**：[[web-generic-auth-sms-captcha-type-param-validcode-removal-bypass]]（同为验证码保护形同虚设，绕过点不同）；[[web-generic-auth-image-captcha-answer-response-echo]]（答案回显变体）；[[web-generic-auth-client-recomputable-signature-forge]]（服务端信任客户端可复算签名）；[[tools-burp-burpcrypto-execjs-webpack-md5-function-extract-sign]]（本案例的签名函数抠取与 Burp 自动化手法）；[[web-generic-auth-sms-code-multi-number-shared-arbitrary-login]]。

# 检测与防御

- 图形验证码答案必须由服务端生成并保存在服务端（session/缓存），一次性消费；不得由前端生成或随请求提交。
- 不得用客户端可复算的哈希作为“是否通过验证码”的依据；验证码校验结果应在服务端独立判定，并绑定会话、手机号与业务场景。
- 短信发送实施独立于验证码的多维限流：手机号 + 账号 + IP + 设备指纹，配合原子计数与幂等键；验证码短有效期、一次性、失败计数。
- 检测特征：请求中 `key` 与 `verifyCode` 同步变化且恒能通过；同一时间窗口内大量不同手机号的发送请求；验证码页面无图片获取请求；同一 IP/设备的高频调用。
