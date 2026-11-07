---
id: web-generic-auth-captcha-client-refresh-session-reuse
title: 验证码只在请求生成接口时刷新：一次获取后复用同一 Session 验证码爆破口令
type: scenario
domain: web
path: web/generic/auth
technique: captcha-client-refresh-session-reuse
tags:
- web
- auth
- captcha
- brute-force
- session
- rate-limit
- business-logic
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V234
  verified_at: '2026-11-07T09:05:44+08:00'
  notes: 已对照 18753 原文与全部 8 张图片核对：mallKaptcha 每次访问生成 ShearCaptcha 并 setAttribute 到 session，图 08 Burp 历史同一 JSESSIONID 仅一次 GET /common/mall/kaptcha、随后多次 POST /login 且响应为“登录失败！”而非验证码错误，与卡片描述一致。未验证点：原文未展示登录校验代码/登录请求体，无法从截图直接确认复用同一验证码值，“登录失败”也可能发生在验证码校验之前；卡片已标 confidence=medium 且未在真实环境复现。dedup 候选 2FA 参数篡改、captcha OCR 枚举/爆破、限速绕过、短信 OTP 预测均为不同手法，非同一卡。
url: /docs/web/generic/auth/web-generic-auth-captcha-client-refresh-session-reuse/
draft: false
kb_aliases:
- 验证码不刷新
- 验证码复用
- captcha reuse
- 验证码生命周期
- 前端控制验证码刷新
- 一次验证码多次登录
---

## 一句话结论

当图形验证码只在客户端主动请求 `/captcha` 生成接口时才写入/刷新 session，而登录校验失败后不销毁或不轮换该 session 验证码时，攻击者只需请求一次验证码、识别一次，就能用同一个 `JSESSIONID` 和同一个验证码值反复提交登录请求，绕过“每次尝试都要过验证码”的防爆破设计。

## 原理

- **验证码的防爆破价值依赖“一次性”**：服务端把 captcha 明文/答案放在 session 中，登录时取出比对。正确设计应在每次校验后（无论成功失败）删除或轮换该值，使每次登录尝试都需要新验证码；否则同一个答案在 session 生命周期内一直有效。
- **刷新触发点由客户端控制**：案例的 `/common/mall/kaptcha` 每次被访问都会生成新验证码并 `session.setAttribute(Constants.MALL_VERIFY_CODE_KEY, shearCaptcha)`；前端只有在点击“刷新验证码”或重新打开登录页时才请求它。攻击者用脚本登录时完全可以不请求该路由，于是 session 中的验证码保持不变。
- **为什么能绕过**：登录接口只比较“提交的 captcha == session 中的 captcha”，而不检查“这个 captcha 是否已经被使用过”“本次尝试是否距上次尝试太近”。在没有账号锁定、IP 限速或设备指纹的情况下，攻击者可以：
  1. 请求一次验证码并用 OCR/人工识别得到答案；
  2. 保持同一 `JSESSIONID`，用同一答案对密码字典逐条提交；
  3. 服务端如果每次失败后不删除 session 验证码，所有尝试都能通过验证码校验，只有密码错误会返回“登录失败”。
- **与验证码 OCR 的区别**：OCR 方案需要每次尝试都识别新验证码，受识别率/请求频率限制；本方案只识别一次，绕过成本更低。两者可组合：先试复用，若服务端每次失败轮换 captcha，再退回 OCR。
- **为什么案例成立**：Burp 历史中同一 `JSESSIONID` 只有一次 `GET /common/mall/kaptcha`，随后连续多次 `POST /login`，响应均为“登录失败！”而非“验证码错误”，说明验证码在多次尝试间未被销毁/轮换；文章将其称为“验证码 bypass”。

## 触发条件

- 验证码答案存储在 session/服务端会话中，登录接口按 session 比对。
- 验证码生成接口与登录接口分离，且只有客户端请求生成接口时才刷新；登录失败后不删除/不轮换 session 中的验证码。
- 没有账号锁定、IP/设备限速、失败次数阈值或行为验证。
- 攻击者能保持同一会话 Cookie，并能识别一次验证码（人工、OCR 或从响应/日志泄露）。
- 目标账号存在（可结合用户名枚举）。

## 利用步骤

1. 用浏览器/代理访问登录页，记录 `JSESSIONID`；抓取一次 `GET /common/mall/kaptcha` 的响应图片，识别出验证码答案。
2. 构造 `POST /login`，携带同一 `JSESSIONID`、用户名、密码字典条目和该验证码答案。
3. 连续发送多条登录请求，期间**不**再请求验证码生成接口；观察响应差异：
   - 若返回“登录失败/密码错误”而不是“验证码错误”，说明验证码被复用；
   - 若返回“验证码错误”，说明服务端每次失败后轮换或消费了验证码，需改用每次识别新验证码的 OCR 方案。
4. 用 Intruder/脚本跑密码字典，按响应长度/状态码/跳转筛出成功登录。
5. 若服务端在成功后也不轮换，可进一步测试会话固定/重放；若验证码有有效期，控制在有效期内完成爆破。

## PoC

```http
# 1) 只请求一次验证码，保留同一个 JSESSIONID
GET /common/mall/kaptcha HTTP/1.1
Host: target
Cookie: JSESSIONID=<fixed>

# 2) 识别图片得到 captcha=abcd，然后用同一个 Cookie/答案反复登录
POST /login HTTP/1.1
Host: target
Content-Type: application/json
Cookie: JSESSIONID=<fixed>

{"loginName":"admin","password":"<candidate1>","verifyCode":"abcd"}

# 3) 不重新请求 /common/mall/kaptcha，继续换密码
{"loginName":"admin","password":"<candidate2>","verifyCode":"abcd"}
```

原文在 Burp 历史中展示同一 `JSESSIONID` 仅一次验证码 GET、随后多次 `/login` POST，响应为“登录失败！”，用于证明验证码未随失败轮换。实际利用需结合用户名枚举与密码字典；不同框架的字段名/JSON 结构按目标调整。

## 变体与关联

- **验证码在响应中回显**：有些实现把 captcha 明文放在响应 JSON/HTML 中，直接读取即可，无需 OCR；属于更严重的实现缺陷。
- **验证码弱随机/固定**：用时间戳、递增 ID、固定值生成，可直接预测；结合 `srand(time)` 等 PRNG 预测。
- **每次失败轮换但无速率限制**：仍需每次识别/请求新验证码，可退回 [[web-generic-auth-captcha-ocr-username-enum-bruteforce]] 的 OCR + captcha-killer 方案。
- **会话固定/验证码绑定缺失**：验证码只按 IP 或全局存储，攻击者可复用他人验证码或跨会话使用；应绑定 session + 一次性 token。
- 关联：[[web-generic-auth-captcha-ocr-username-enum-bruteforce]]（OCR 识别 + 爆破）、[[web-generic-auth-login-rate-limit-bypass-cookie-xff]]（限速绕过）、[[web-generic-auth-login-bruteforce-response-payload]]（响应差异判定成功）。

## 检测与防御

- **一次性使用**：登录校验取出 session 验证码后立即删除（无论成功失败）；失败时重新生成并写回，确保每次尝试都需要新答案。
- **服务端轮换**：验证码生成接口只负责生成，校验接口负责消费；不要依赖客户端主动刷新来轮换。
- **限速与锁定**：按账号 + IP + 设备指纹限制失败次数，触发验证码升级/临时锁定/告警；对同一 session 的连续登录尝试做频率限制。
- **绑定与有效期**：验证码绑定 session、IP、UA 或一次性 nonce，设置短有效期；校验时比较全部绑定信息。
- **检测特征**：同一 `JSESSIONID` 在短时间内多次 `POST /login` 但只有一次 `GET /captcha`；登录失败响应中验证码错误与密码错误可区分；验证码答案在响应中回显或可预测。
