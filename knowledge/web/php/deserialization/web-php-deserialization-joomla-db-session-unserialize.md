---
id: web-php-deserialization-joomla-db-session-unserialize
title: Joomla 数据库 session 表注入触发反序列化：改 data 字段为 joomla|Base64 序列化串并重放 Cookie
type: scenario
domain: web
path: web/php/deserialization
technique: joomla-db-session-unserialize
aliases:
- Joomla session 反序列化
- Joomla 数据库 session 注入
- joomla| 前缀
- Joomla session 表 getshell
- Joomla session 伪造
tags:
- php
- joomla
- deserialization
- session
- database
- object-injection
- cve-2023-23752
cve: []
severity: critical
confidence: high
affected_versions: Joomla ≤3.4.6 session 直接序列化入库；3.4.7+ 对 session 数据加 Base64（原文标记）；示例覆盖 3.4.8 与 4.2.7
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:59:01+08:00'
  notes: '已对照原文核对；图01 为 #__session 表 joomla|s:N:"<Base64序列化串>"; 格式、图02 为 3.4.6→3.4.7 diff 中 base64_decode 后 unserialize；≤3.4.6/3.4.7+ 版本表述按原文（3.4.6之前直接入库、3.4.7起加 Base64）；未实际连库改 data 复现，属入口原语，最终危害依赖本批两张 gadget 卡，与卡内关联一致'
---

## 一句话结论

拿到 Joomla 数据库权限后，不必登录后台：访问首页取得 `session_id`，直接把 `#__session` 表中该会话的 `data` 字段改成特制的 `joomla|s:N:"<Base64(序列化对象)>";`，再带着原 Cookie 访问首页，Joomla 会话处理器会 Base64 解码并 `unserialize()` 该数据，触发任意反序列化 gadget。

## 原理

- Joomla 3.4.6 及更早版本默认把 session 直接序列化存储在数据库 `#__session` 表中，`data` 列就是序列化后的会话数据；只要拿到数据库写权限就能替换会话内容。
- 3.4.7 起官方在 session 序列化外增加了一层 Base64：会话处理代码从 `$_SESSION['joomla']` 取出字符串，`base64_decode()` 后直接 `unserialize($data)`，没有类型/类白名单限制（`libraries/joomla/session/session.php`）。
- 因此数据库中的 `data` 形如 `joomla|s:<长度>:"<Base64 后的序列化字符串>";`；请求携带同一个 session Cookie 时，Joomla 用它初始化会话并反序列化，造成对象注入。
- 常见前置是 CVE-2023-23752 等配置泄露拿到 MySQL 账号口令；攻击者也可以从其他途径获得数据库写权限。Joomla 4 仍然使用 `joomla|` + Base64 的会话存储格式，示例在 4.2.7 上同样成立。
- 该入口把“数据库访问”转化为“PHP 对象注入”，后续危害取决于可用 gadget（如 Joomla 4 日志写入、Joomla 3 数据库驱动/SImplePie 链）。

## 触发条件

- 已有目标 Joomla 数据库的写权限，且能访问 `#__session` 表（表前缀可变，如 `hehdv_session`）。
- 目标 Joomla 版本使用数据库 session 存储（默认配置），且会话数据反序列化未做类白名单。
- 能先访问站点拿到一个有效 session Cookie，并在改库后用同一 Cookie 再次请求。
- 目标 classpath 中存在可用的反序列化 gadget。

## 利用步骤

1. 访问 Joomla 首页，从响应 Set-Cookie 或浏览器 Cookie 中取得 session 名与 session_id（如 `<随机串>`）。
2. 用泄露/拿到的数据库凭据连接 MySQL，定位 `#__session` 表，执行：
   `UPDATE <prefix>_session SET data='joomla|s:<len>:"<base64>";' WHERE session_id='<id>';`
3. 重新携带原 Cookie 访问首页（或任意 Joomla 页面），触发会话读取与 `unserialize()`。
4. 若 gadget 是写文件/命令执行，等待副作用落地；无回显时通过写 WebShell、外带或 DNS/HTTP 观察。
5. 清理会话记录，恢复被修改的数据。

## PoC

生成会话 data（以任意 gadget 对象 `$obj` 为例）：

```php
<?php
$str = base64_encode(serialize($obj));
echo "joomla|" . serialize($str);
```

入库：

```sql
UPDATE hehdv_session
SET data='joomla|s:<长度>:"<Base64序列化串>";'
WHERE session_id='<cookie 中的 session_id>';
```

随后用原 Cookie 请求：

```http
GET / HTTP/1.1
Host: target
Cookie: <session_name>=<session_id>
```

## 变体与关联

- **版本差异**：≤3.4.6 的 `data` 可直接放原始序列化串；3.4.7+ 必须按 `joomla|` + Base64 包装。
- **前置链**：CVE-2023-23752 未授权配置泄露拿数据库口令，见 [[web-php-joomla-api-config-application-public-db-credential-leak]]。
- **Joomla 4 gadget**：本批 FormattedtextLogger `__destruct` 任意文件写入卡；**Joomla 3 gadget**：本批 JDatabaseDriverMysqli + SimplePie assert RCE 卡。
- **边界**：session 处理器改为文件/Redis 存储、数据库前缀未知、目标禁用数据库 session、或 `unserialize` 加了 `allowed_classes` 白名单时失效。

## 检测与防御

- **数据库侧**：限制应用数据库账号权限，业务账号不应具备任意 UPDATE `#__session` 的能力；监控对 session 表 `data` 字段的异常更新。
- **会话完整性**：session 数据签名/HMAC 或服务端加密存储；升级 Joomla 并跟进安全补丁。
- **反序列化加固**：会话反序列化使用 `allowed_classes` 白名单，避免直接 `unserialize` 用户可影响的数据库内容。
- **检测**：`data` 字段出现 `joomla|s:` 且 Base64 解码后含对象结构；同一 session_id 在短时间内被更新并立即被访问；Joomla 进程写文件/派生进程。
