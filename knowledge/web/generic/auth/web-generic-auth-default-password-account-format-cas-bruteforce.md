---
id: web-generic-auth-default-password-account-format-cas-bruteforce
title: 帮助文档泄露账号格式与默认口令：CAS 登录 base64 密码 Pitchfork 爆破绕过前端锁定
type: scenario
domain: web
path: web/generic/auth
technique: default-password-account-format-cas-bruteforce
aliases:
- 默认口令爆破
- 初始密码等于账号
- CAS 登录爆破
- base64 密码 Pitchfork
- 账号格式泄露
- 教师账号爆破
tags:
- web
- auth
- weak-password
- default-credential
- bruteforce
- cas
- account-enumeration
- base64
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:12+08:00'
  notes: 已对照原文与图7-17核对：学生/教师手册写明账号=学校简称+学号/工号、初始密码=账号；CAS 登录 password 为 Base64；Pitchfork 396 请求，payload 219/127 返回 200、长度 1487/1478、Set-Cookie CASTGC；爆出教师账号并登录看到 14069 条学生数据。CAS 端点锁定/限速差异按 396 次批量请求推断；未复跑。
---

## 一句话结论

系统的学生/教师使用手册直接写明账号格式为“学校简称 + 学号/工号”、初始密码与账号一致；主登录页虽有连续 5 次失败锁定，但 CAS 登录端点 `/cas-server/login` 没有同样的锁定/限速，且密码字段只是 Base64 编码；用 Burp Intruder 的 Pitchfork 模式让账号与 `base64(账号)` 一一对应，向 CAS 端点跑 396 个账号即可爆出测试教师账号，进而获得高权限教师会话。

## 原理

- 账号可预测：帮助文档/学生手册/教师手册写明“账号 = 学校简称 + 学号/工号”，学校简称可在登录页“查询学校简称”查到，学号/工号格式固定且连续（原文学生账号 120101、120102…；教师工号 0325 等），因此可以批量构造账号。
- 默认口令：文档明确“初始密码和账号一致（密码中的字母均为小写）”，即 `password = account`；管理员批量下发的初始口令没有强制首次修改，导致大量账号仍使用默认口令。
- 编码绕过/自动化：CAS 登录请求把密码做 Base64 后提交（`password=Y2N5ejExMT...`），爆破时第二个字典直接使用 `base64(账号)`，第一个字典使用账号；Burp Intruder Pitchfork 让两个字典按顺序一一对应，避免笛卡尔积浪费请求。
- 锁定差异：主登录页提示“连续输错 5 次后账号将被锁定”，但 CAS 端点没有同样的账号锁定/失败计数/验证码，原文对 396 个账号各发一次请求，多数返回 500/302，少数返回 200 登录成功并下发 `CASTGC` Cookie，说明锁定只做在一个前端入口。
- 结果识别：成功响应为 200、长度约 1478/1487，JSON/回调含 `"login":"success"`，并 `Set-Cookie: CASTGC=...`；失败为 302/500 或长度明显不同。
- 成立条件：默认口令未改、账号格式可推断、CAS 端点无锁定/限速、密码编码可复现；三者叠加使“弱默认口令”变成可批量接管。

## 触发条件

- 系统存在默认口令策略（初始密码=账号/工号/统一默认值）且未强制首次修改。
- 帮助文档、使用手册、登录页提示等泄露账号命名规则与默认口令规则。
- 登录入口（尤其 CAS/SSO 后端）没有失败次数锁定、IP 限速、验证码或设备指纹。
- 密码字段的编码方式可复现（Base64/MD5/RSA 等），可批量生成。
- 攻击者能构造账号列表（学号/工号连续或可枚举），并在授权范围内测试。

## 利用步骤

1. 收集登录页、帮助中心、学生/教师使用手册，记录账号格式、默认口令规则、学校简称查询方式。
2. 枚举学校简称与学号/工号范围，生成账号字典（如 `xxu120101`、`xxu120102`…、教师 `xxu0325`）。
3. 抓取 CAS 登录请求，确认密码编码（Base64）与请求参数（`lt`、`username`、`password`、`execution`、`_eventId` 等）；先手工验证一个已知测试账号。
4. Burp Intruder 选择 Pitchfork，Payload 1 = 账号字典，Payload 2 = Base64 编码后的同一账号字典（原文用 Base64-encode 处理规则）；并发/延迟控制在授权范围内。
5. 按响应状态码、长度、`"login":"success"`、`Set-Cookie: CASTGC` 过滤成功项；对成功账号登录后台，确认角色与权限。
6. 仅在授权测试中使用测试账号；不要修改/导出真实业务数据，发现默认口令账号应报告而非扩大利用。

## PoC

```http
# CAS 登录请求（原文；密码为 Base64）
GET /cas-server/login?lt=LT-1177218-hPsHSGMekhheaSdQBm6N5e...&service=<service>&callback=logincallback&username=<account>&password=<base64(account)>&isajax=true&isframe=true&_eventId=submit&serviceURL=&type=pwd&execution=e22s1&_x_code=&_=1756370940197 HTTP/1.1
Host: <target>
Cookie: <pre-login-cookies>
```

```text
Burp Intruder（Pitchfork）：
  Payload 1: 账号列表（如 xxu0390, xxu0391, ..., xxu0219 ...）
  Payload 2: 同一账号列表 + Base64-encode 处理规则
  请求数：396

结果（原文）：
  payload 219 → 200，响应长度 1487，login success，Set-Cookie: CASTGC=...
  payload 127 → 200，响应长度 1478
  其他 → 302（31-36 字节）或 500（5498 字节）
```

```text
登录成功示例：
{"login":"success","token":"...","execution":"..."} + Set-Cookie: CASTGC=TGT-...
```

## 变体与关联

- 变体（账号格式）：学校简称+学号、学校简称+工号、手机号、身份证后六位、`admin` 等；帮助文档/登录页提示是主要来源。
- 变体（默认口令）：账号本身、`123456`、`admin`、工号后六位、`学校简称+123456`；先测“账号=口令”，再测通用弱口令。
- 变体（编码）：Base64、MD5、SHA1、RSA 公钥加密；抓包确认后批量生成，必要时在 Burp 中用处理规则。
- 变体（锁定绕过）：主站有锁定但 CAS/SSO/移动端接口没有；同一账号分散到多个入口/协议；IP 轮换会触发风控，授权测试应避免。
- 关联：[[web-generic-auth-captcha-ocr-username-enumeration-same-password]]（验证码+用户名枚举+同口令）、[[web-generic-auth-astrbot-dashboard-weak-password]]（弱口令）、[[web-generic-auth-cas-service-open-redirect-ticket-theft-ato]]（同文章 CAS ticket 接管，不同链路）。
- 边界：强制首次改密、CAS 端点启用锁定/验证码/限速、默认口令随机化时，爆破不可行；原文仅爆出测试账号，未对真实学生/教师账号操作。

## 检测与防御

- 修复：首次登录强制修改默认口令；密码策略禁止“账号=口令”；所有认证入口（含 CAS/SSO/移动端）统一失败计数、锁定、限速与验证码。
- 加固：帮助文档不要写默认口令规则；账号格式避免完全可预测；对批量登录、单 IP 多账号、单账号多密码做风控与告警；管理员批量下发口令时使用随机值并强制改密。
- 检测：同一 IP/设备在短时间内对大量账号各尝试一次（Pitchfork 特征）；CAS 登录失败率异常；同一账号从不同 IP 成功登录；默认口令账号首次登录后未改密。
- 响应：发现默认口令账号立即要求改密/重置；对已登录会话做审计，排查是否发生数据访问或横向移动。
