---
id: web-generic-auth-sms-login-code-not-bound-phone-parameter-tamper
title: 短信登录验证码未绑定手机号：替换/双写 phone 参数复用自己的验证码登录任意账号
type: scenario
domain: web
path: web/generic/auth
technique: sms-login-code-phone-binding-bypass
tags:
- web
- auth
- sms
- verification-code
- account-takeover
- parameter-pollution
- logic-flaw
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V215
  verified_at: '2026-11-07T05:04:33+08:00'
  notes: 已对照全文与 img/13-15 核对：拿到企业负责人手机号后走单位登录，抓包改手机号/验证码绕过并登录企业账号，原文总结的三种手法为直接替换手机号、双写手机号、添加同义手机号字段。未验证点：截图参数已打码、未给完整请求；与 password-reset-unbound-phone（重置流程任意手机号）、multi-number-shared（多号码同码）、echo-response（响应回显）均非同一利用链，按 new/append 保留。
url: /docs/web/generic/auth/web-generic-auth-sms-login-code-not-bound-phone-parameter-tamper/
draft: false
kb_aliases:
- 验证码未绑定手机号
- 替换手机号绕过验证码
- 双写手机号绕过
- 重复参数短信绕过
- 短信登录任意账号
---

## 一句话结论

招聘/就业平台的短信登录只校验“手机号 + 验证码”组合，没有验证验证码是否真的发给了该手机号，也没有把验证码与会话绑定；攻击者先用自己的手机号收一条验证码，再抓包把登录请求里的 `phone` 换成受害者号码（或双写 `phone`、添加同义字段），用自己的验证码即可登录受害者账号。

## 原理

- **验证码的认证语义**：短信验证码证明的是“持有该手机号”，因此服务端必须把验证码绑定到“发码时的手机号 + 会话/请求”。登录时若只把客户端提交的 `phone` 与 `code` 做一次比对，而验证码存储/校验的维度是会话或请求 ID，攻击者就可以在发码和验码之间替换手机号。
- **发码与验码的号码来源不一致**：常见实现中，发码接口按请求里的手机号发送并存储验证码；登录接口又从请求里重新取手机号查询用户。如果两次取参的字段/顺序不一致（例如发码取 `phone`、登录取 `mobile`；或参数污染时框架取第一个、业务取最后一个），就会出现“码发给攻击者、登录用受害者”的错位。
- **参数污染变体**：文章总结了三种手法——直接替换手机号、双写手机号（同一参数出现两次）、添加相同数据结构的手机号（如同时传 `phone` 与 `mobile`/`phoneNumber`），利用服务端不同层取参不一致绕过绑定校验。
- **逐级放大**：在招聘平台中，企业联系人手机号只对已登录学生可见；拿到手机号后接管企业账号，企业账号可下载学生简历，简历中含学生手机号；再用同样方法接管学生账号，最终拿到学生身份证号并修改密码。验证码绕过是整条链的支点。

## 触发条件

- 目标登录/注册流程使用短信验证码，攻击者能收到自己手机号的短信。
- 验证码校验未绑定手机号（按会话/请求 ID 存储），或发码与验码读取手机号的字段/顺序不一致。
- 登录接口接受客户端提交的手机号，且未强制使用服务端会话中已绑定的号码。
- 攻击者已获得受害者手机号（企业信息页、简历、通讯录、公开名单等）。
- 无图形验证码/风控阻断批量尝试，或可用低权限账号正常获取验证码。

## 利用步骤

1. 注册/登录一个普通账号，找到只对登录用户可见的企业联系人信息或简历，获取受害者手机号。
2. 用自己的手机号在登录页请求验证码，收到一条属于自己号码的验证码（不要使用）。
3. 抓取登录请求，把 `phone`/`mobile` 参数替换为受害者手机号，`code` 仍填自己收到的验证码，发送。
4. 若返回“验证码错误/手机号不匹配”，尝试参数污染：
   - 双写 `phone=<victim>&phone=<attacker>`（或 `phone=<attacker>&phone=<victim>`，取决于框架取第一个/最后一个）；
   - 同时提交 `phone=<victim>&mobile=<attacker>`、`phoneNumber`、`tel` 等同义字段；
   - 在 JSON 中放重复键或数组 `{"phone":["<victim>","<attacker>"]}`。
5. 观察发码接口与登录接口实际使用的号码，调整字段顺序/编码，直到用受害者手机号 + 自己验证码登录成功。
6. 进入受害者账号后验证权限；在招聘平台中继续下载简历获取更多学生手机号，重复步骤 2-5 批量接管学生账号。

## PoC

基本替换（表单）：

```http
POST /<auth-path>/login HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded
Cookie: <anonymous-or-low-priv-session>

phone=<victim_phone>&code=<attacker_received_code>
```

参数污染变体：

```http
phone=<victim_phone>&phone=<attacker_phone>&code=<attacker_received_code>
```

```http
phone=<victim_phone>&mobile=<attacker_phone>&code=<attacker_received_code>
```

```json
{"phone": "<victim_phone>", "mobile": "<attacker_phone>", "code": "<attacker_received_code>"}
```

文章实测：用企业联系人手机号 + 自己收到的验证码成功登录企业账号；用简历中的学生手机号同样登录学生账号，并可查看身份证号、修改全部学生密码。

## 变体与关联

- **发码阶段替换**：部分系统在“发送验证码”请求里就按客户端 phone 发码；攻击者先填自己号码收码，再在登录请求替换 phone。
- **双写/重复参数**：利用 WAF、网关、业务代码对重复参数取第一个/最后一个的差异；也可用 `phone[]=`、`phone=1&phone=2`、大小写字段等。
- **同义字段**：`mobile`、`phoneNumber`、`tel`、`loginName` 等同时出现时，发码与登录可能各取一个。
- **验证码复用**：验证码有效期长、可多次使用、按会话共享时，可在多个目标账号间复用。
- **关联**：[[web-generic-auth-sms-code-multi-number-shared-arbitrary-login]]（多号码同码）、[[web-generic-auth-password-reset-unbound-phone-any-phone]]（找回密码手机号未绑定）、[[web-generic-auth-applicantchange-pin-sms-bypass-registration]]（短信参数组合绕过）、[[web-generic-auth-sms-code-echo-response-arbitrary-login]]（验证码回显）。

## 检测与防御

- **绑定校验**：验证码必须按“单个手机号 + 会话 ID”生成、存储和校验；登录时从服务端会话取发码手机号，忽略客户端再次提交的 phone。
- **参数唯一性**：拒绝重复参数/数组/同义字段，统一由网关规范化后再进入业务；发码与验码使用同一字段解析逻辑。
- **一次性与限流**：验证码一次性使用、短有效期、失败次数限制；对同一手机号/同一 IP/设备批量发码与登录做限流和风控。
- **检测**：登录请求的 phone 与验证码实际接收号码不一致、重复参数、同一验证码尝试多个手机号、同一设备短时间登录多个账号；对异常批量登录告警。
- **响应**：确认绕过后面下线相关账号会话、修复绑定校验、评估受影响账号范围并通知用户。
