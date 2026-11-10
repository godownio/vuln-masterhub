---
id: web-generic-auth-js-admin-username-reset-phone-echo
title: 前端 JS 泄露管理员账号 + 找回密码按用户名回显手机号：管理员 PII 与账号清单批量泄露
type: scenario
domain: web
path: web/generic/auth
technique: frontend-js-admin-account-reset-phone-echo
aliases:
- const.js 泄露管理员用户名
- 找回密码回显完整手机号
- 管理员账号与 PII 泄露
- 用户名枚举 + 手机号回显
tags:
- web
- auth
- password-reset
- pii
- information-disclosure
- frontend-js
- username-enumeration
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:29:25+08:00'
  notes: 已对照原文核对；const.js 中 const manager=[{name,email,id}] 两条管理员记录，找回密码输入用户名后弹安全验证并回显绑定手机号，与卡片一致；未验证点：原文截图手机号被作者打码，无法确认是否为未脱敏完整号码（卡片已标 confidence=medium，建议后续以未打码证据复核「完整回显」表述）
---

## 一句话结论

站点把管理员账号清单写进前端常量文件（`const.js`），又在「找回密码」处按用户名查询并把绑定手机号完整回显到页面，两个「低危」拼起来就是「管理员账号 + 手机号」成对泄露：无需登录即可枚举系统里的特权账号并拿到其真实手机号，为后续钓鱼、撞库、短信轰炸与社工接管提供直接素材。

## 原理

- 前端常把「内置账号、角色映射、默认管理员」写成常量文件随打包产物发布，本意是「页面展示用」，但这些字符串对任何访问者都可见：账号名本身就是高价值信息（管理员 ID 可省去枚举），且文件名（`const.js`、`config.js`）便于批量拉取。
- 「找回密码」流程的第一步是「校验用户名是否存在」，第二步是「把绑定手机号展示给用户核对」。若服务端把完整手机号（而非 `138****1234` 掩码）返回并渲染到页面，攻击者只要知道用户名就能得到 PII；这属于典型的「验证环节信息过度暴露」。
- 之所以构成可复用链：账号清单泄露把「用户名枚举」成本降为 0，手机号回显又把「PII 获取」成本降为 0，两者相接即无需任何爆破或短信成本。
- 掩码缺失的根因通常是「把数据库字段直接塞进响应」而不是「按验证级别返回脱敏字段」；有些系统还会在同一接口区分「用户不存在」与「存在但手机号为空」，进一步放大枚举效果。
- 危害定位：单独看只是信息泄露，但泄露对象是管理员且含真实手机号，等于给出定向钓鱼/短信验证码劫持的目标清单，属于可以进一步推进的前置资产。

## 触发条件

- 前端产物中存在账号清单/角色常量，且未做访问控制。
- 存在找回密码、账号申诉、绑定手机查询等「按用户名查询」的公开接口。
- 该接口返回完整手机号（未脱敏）或返回可区分的「账号存在/不存在」差异。
- 无频率限制或限制宽松，可对多个用户名批量查询。

## 利用步骤

1. 下载目标页面引用的全部 JS（含 `const.js`），grep `admin`、`username`、`user`、`account`、`role` 等关键字，提取账号清单与角色映射。
2. 访问「找回密码」页面，输入提取到的用户名，抓取该步骤请求（多为 `POST /api/.../checkUser` 或 `?username=`）。
3. 检查响应中是否带手机号字段（`phone`、`mobile`、`telephone`），确认是完整号码还是掩码。
4. 用同一请求替换其它用户名，观察「存在/不存在」的响应差异（不同提示文案、不同状态码、不同字段），确认可枚举。
5. 汇总账号 + 手机号，作为社工/钓鱼/撞库的输入；如需进一步验证，可对「手机验证码登录」入口做一次合法测试（不实际发送大量短信）。
6. 记录请求与响应作为证据，控制查询数量，避免触发短信接口产生真实短信。

## PoC

```http
GET /static/js/const.js HTTP/1.1
Host: target
```

（从返回内容中提取 `adminList`/`ADMIN_USER` 一类常量，得到管理员用户名。）

```http
POST /api/user/findpwd/checkUsername HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=<从 JS 中提取的管理员用户名>
```

响应中若出现 `"phone":"1xxxxxxxxxx"` 之类完整号码，即确认泄露：

```json
{"code":0,"msg":"用户存在","data":{"mobile":"1xxxxxxxxxx"}}
```

## 变体与关联

- 变体：同一常量文件里还可能直接给出默认口令、加密密钥、内部接口地址，一并作为资产收集结果。
- 变体：找回密码接口只返回掩码时，可结合「短信轰炸/验证码登录」入口探测号码是否正确，或从其它接口（订单、个人中心）交叉获取完整号码。
- 变体：邮箱找回、密保问题找回、客服工单查询同样可能回显手机号/邮箱/身份证后六位。
- 关联：[[web-generic-auth-imid-userinfo-mobile-pii-enumeration]]（按 ID 越权遍历获取手机号的同类 PII 泄露）。
- 关联：[[web-generic-auth-password-reset-unbound-phone-any-phone]]（同样从找回密码入口出发，但走的是重置链路而不是信息泄露）。
- 关联：[[pentest-recon-frontend-obfuscated-js-hardcoded-credentials]]（前端 JS 中提取账号口令类常量，属同源前置步骤）。

## 检测与防御

- 防御：不要把内置账号、角色映射写进前端常量；需要展示的账号信息应来自需要鉴权的接口。
- 防御：找回密码接口只返回「是否已发起」与脱敏号码（保留前 3 后 4），不区分「账号不存在」与「账号存在但无手机号」，统一文案与状态码。
- 防御：对找回密码/申诉类接口做频率限制、图形验证码与短信发送配额，禁止同一会话批量查询不同用户名。
- 检测：监控前端资源里出现 `admin/管理员/默认账号` 类常量的发布；把常量文件纳入构建期扫描。
- 检测：对找回密码接口的「用户名遍历」行为告警（同一来源短时间大量不同 username 的请求、响应均含手机号字段）。
