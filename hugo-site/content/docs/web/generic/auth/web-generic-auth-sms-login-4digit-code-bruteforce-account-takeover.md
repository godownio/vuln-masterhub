---
id: web-generic-auth-sms-login-4digit-code-bruteforce-account-takeover
title: 短信验证码登录 4 位码无失败次数限制：爆破验证码登录任意手机号账户
type: scenario
domain: web
path: web/generic/auth
technique: sms-login-4digit-code-bruteforce-account-takeover
tags:
- web
- auth
- sms
- verification-code
- bruteforce
- account-takeover
- logic-flaw
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-24
  verified_at: '2026-11-08T13:24:12+08:00'
  notes: 已对照原文核对：4位码/15分钟/无锁定与截图09-11一致，getUserByPhone枚举并入合理；dedup_review对arbitrary-registration的端点差异成立；卡无sources字段（与库内约定一致）；未验证点：未实测万次全爆破，confidence medium合理
url: /docs/web/generic/auth/web-generic-auth-sms-login-4digit-code-bruteforce-account-takeover/
draft: false
kb_aliases:
- 短信验证码登录爆破
- 4 位登录验证码爆破
- 验证码登录任意用户
- 验证码登录账户接管
- 图形验证码只保护发送不保护校验
---

## 一句话结论

手机号+短信验证码直接登录的接口若使用 4 位数字验证码、有效期长达 15 分钟、且提交错误验证码后既不锁定账号也不要求重过图形验证码，攻击者仅凭受害者手机号即可在有效期内穷举 0000–9999 共 1 万个组合，命中后拿到该账户的 accessToken，完成任意用户登录与账户接管。

## 原理

- 4 位纯数字验证码的有效取值空间只有 10^4 = 10000 个，远低于 6 位码的 10^6；在 15 分钟有效期内以每秒数次的速度提交，穷举完整个空间在工程上完全可行。
- 服务端只用“手机号 + verifyCode”两个字段判定登录，验证码本身与手机号绑定且在整个有效期内不变（不因一次校验失败而作废），因此每一次错误尝试不会消耗掉任何“机会”，爆破成功率随尝试次数线性上升。
- 图形验证码/滑块只挡在“发送验证码”环节，登录校验接口并不复用该人机校验，攻击者只需在爆破前触发一次短信、后续 1 万次提交都不再受人机验证约束。
- 接口对成功与失败返回可区分的结果（失败返回“验证码错误”的业务码，成功返回 code=0 并携带用户信息与 accessToken），构成一个干净的判定 oracle，使自动化爆破无需处理歧义响应。
- 成功后登录响应直接回吐实名、身份证号、住址、手机号等字段并下发 accessToken，把“登录”直接升级为“身份信息泄露 + 账户控制”，若账户绑定支付/交易能力还可造成资金损失。

## 触发条件

- 系统支持“手机号 + 短信验证码”免密登录，且登录请求体只依赖 phone 与 verifyCode。
- 验证码为 4 位（或更短）纯数字，有效期以十分钟计。
- 登录校验接口没有按手机号/设备/IP 的失败次数限制、没有失败后强制刷新验证码、没有在登录环节复用人机验证。
- 手机号可被枚举或已知（同系统的用户信息查询接口常可按手机号探测账号是否存在）。

## 利用步骤

1. 在登录页正常走一遍流程，抓取登录请求，确认请求体字段（如 `phone`、`verifyCode`）与成功的响应结构。
2. 用可按手机号查询用户信息的接口（如登录页加载时调用的 `getUserByPhone` 类接口）对目标号段做枚举，确认受害手机号已注册；参数换成不存在的号码时 `data` 为空，可作存在性判据。
3. 对受害手机号触发一次发送验证码（此处通过图形人机验证即可），记录发送时间，用于计算 15 分钟窗口。
4. 用 Burp Intruder 或脚本对 `verifyCode` 做 0000–9999 的 Numbers 爆破，保留原请求的头与 Cookie，按响应长度/业务码过滤成功包。
5. 命中后响应中直接返回用户资料与 accessToken，用该 token 访问个人中心/订单/钱包接口验证接管效果。

## PoC

```http
POST /api/login HTTP/1.1
Host: target
Content-Type: application/json

{"phone":"13800000000","verifyCode":"0000","loginPswd":"","userHash":"","userId":""}
```

失败响应可区分：

```json
{"code":5,"msg":"验证码错误","data":null}
```

成功响应携带身份信息与令牌：

```json
{"code":0,"msg":"success","data":{"userInfo":{"phone":"138****0000","realName":"***","cardId":"***","address":"***"},"accessToken":"***"}}
```

最小爆破（示意，仅用于授权测试）：

```bash
for c in $(seq -w 0 9999); do
  r=$(curl -s -X POST https://target/api/login -H 'Content-Type: application/json' \
      -d "{\"phone\":\"13800000000\",\"verifyCode\":\"$c\"}")
  case "$r" in *'"code":0'*) echo "hit $c"; break;; esac
done
```

## 变体与关联

- 变体：同样 4 位码无次数限制，但端点用于注册而非登录——机制相同、后果是任意手机号注册，见 [[web-generic-auth-sms-4digit-code-bruteforce-arbitrary-registration]]。
- 变体：验证码不按手机号区分、一次请求可给多个号码发同一码，则无需爆破，见 [[web-generic-auth-sms-code-multi-number-shared-arbitrary-login]]。
- 变体：验证码回显在响应体或日志中、或可离线校验哈希，可绕过在线爆破直接得到码。
- 关联：登录响应过度返回实名/身份证/住址属于个人信息超范围返回；手机号存在性探测属用户枚举，可与本场景串联先筛目标再爆破。
- 边界：若服务端限制单手机号 5 次失败、失败即作废验证码、或登录环节强制人机验证，则本场景不成立。原文仅在本人号码上演示了“先错后对”两次提交并成功登录，未在受害号码上跑完 1 万次爆破，故 confidence 标 medium。

## 检测与防御

- 检测：同一手机号/同一 IP 在短时间内对登录接口产生大量 `verifyCode` 失败（尤其连续递增的 4 位数字）；同一验证码被多次尝试；登录成功前存在异常数量的 4xx/业务失败响应。
- 修复：验证码提升到 6 位以上并限制有效期（≤5 分钟）；登录校验失败 3–5 次即作废验证码并要求重新获取；按手机号+IP+设备做失败计数与锁定；登录环节复用人机验证。
- 加固：验证码一次性使用、绑定手机号与会话；登录成功后不要返回身份证号等非必要字段；对高频验证码校验行为告警。
