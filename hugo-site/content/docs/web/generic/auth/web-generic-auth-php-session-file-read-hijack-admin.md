---
id: web-generic-auth-php-session-file-read-hijack-admin
title: 读取 PHP session 文件劫持管理员会话：枚举会话目录 sess_* 文件，把会话 ID 填入 PHPSESSID/SECUREPHPSESSID 直接登录后台
type: scenario
domain: web
path: web/generic/auth
technique: php-session-file-read-hijack
tags:
- web
- php
- session
- session-file
- hijack
- cookie
- authentication-bypass
- arbitrary-file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V675
  verified_at: '2026-11-13T11:40:36+08:00'
  notes: 已对照原文核对（22图）：config.inc.php 中 sessiondir=/sess、glob('/var/sess/*') 读出 sess_1a68f4d3.../sess_fa788...、源码 SERVER_PROTOCOL==https 时 session_name('SECUREPHPSESSID')、把会话ID填入 Cookie 后以 root 登录 J-Web、后台创建 super-user toanle 并 SSH 登录成功，均与截图一致；文中也说明多数环境因版本差异不成功（未打通部分已排除）。未在本机复现。
url: /docs/web/generic/auth/web-generic-auth-php-session-file-read-hijack-admin/
draft: false
kb_aliases:
- PHP 会话文件劫持
- sess_ 文件读取登录
- /var/sess 会话劫持
- PHPSESSID 伪造
- SECUREPHPSESSID 劫持
- session 文件任意读取
- J-Web 会话劫持
---

## 一句话结论

PHP 默认把会话保存为 `session.save_path` 下的 `sess_<PHPSESSID>` 文件，服务端仅凭 Cookie 里的 session ID 加载对应文件、不重新认证；一旦攻击者可读取该目录（任意文件读取、目录列举、RCE 后的文件函数），即可枚举出活跃会话文件名，把文件名中的 ID 填进 `PHPSESSID`（HTTPS 目标常为 `SECUREPHPSESSID`）直接接管管理员会话登录后台。

## 原理

- PHP 文件会话机制：`session_start()` 按客户端 Cookie（默认 `PHPSESSID`）中的 ID 读取 `session.save_path/sess_<id>` 文件恢复会话数据；文件存在且未过期即认为会话有效，不校验请求方身份。写权限由 `session.save_path` 目录控制，读同理。
- 会话 ID 即凭证：文件名 `sess_1a68f4d3090a85e92002...` 中的随机串就是 Cookie 值。拿到目录列表等于拿到一批会话 ID，无需破解。
- 会话文件内容（如 `admin|b:1;` 或序列化结构）可确认该会话是否已登录、用户是谁、权限级别，便于挑选高价值目标；且活跃会话在过期前（常见 3600 秒或自定义）持续有效。
- 部分应用为 HTTPS 单独设置会话名（如 Juniper J-Web 用 `SECUREPHPSESSID`，源码 `session_name('SECUREPHPSESSID')`），HTTP/HTTPS 必须使用对应 Cookie 名，否则会话不生效。
- 攻击者视角的完整链条：文件读取/代码执行 → 定位会话目录（如配置中的 sessiondir、`session_save_path()` 输出） → `glob('sess_*')` 列出文件 → 读取确认活跃管理员会话 → 设置 Cookie → 刷新后台。

## 触发条件

- 目标使用 PHP 文件会话（默认），且会话目录（如 `/var/lib/php/sessions`、`/tmp`、自定义 `/var/sess`）可被攻击者通过任意文件读取/命令执行/目录列举读到。
- 管理员或高权限用户存在未过期的活跃会话，且会话文件仍在该目录。
- 应用仅依赖 Cookie 中的 session ID 鉴权，没有绑定来源 IP/UA 或额外因子。
- 攻击者掌握对应 Cookie 名（HTTP `PHPSESSID`，HTTPS 可能为 `SECUREPHPSESSID` 等自定义名）。

## 利用步骤

1. 通过任意文件读取、LFI、命令执行或 PHP 代码执行获得文件系统读取能力。
2. 读取应用配置或调用 `session_save_path()` 确认会话目录（例如 Juniper J-Web 配置中 `sessiondir` 指向 `/sess`，实际映射为 `/var/sess/`）。
3. 列举目录：`glob('/var/sess/*')` 或 `ls`，筛出 `sess_<id>` 形式的会话文件（可能还有 `php.log` 等噪音）。
4. 读取候选会话文件内容，确认包含管理员用户名/权限/登录标志的活跃会话。
5. 在浏览器 DevTools 或请求头中设置 Cookie：`SECUREPHPSESSID=<文件名中的 id>`（HTTP 环境用 `PHPSESSID`），访问后台首页；服务端加载该会话，直接以管理员身份进入（示例中进入 J-Web 后显示 `root` 用户）。
6. 后利用：通过后台创建超级用户（账号密码可用于 SSH/设备管理），或修改配置实现持久化。

## PoC

```php
<?php
// 列举会话文件（源自 PHP 代码执行后的读取能力）
$files = glob('/var/sess/*');
foreach ($files as $file) {
    echo $file . "<br>";
}
// 输出示例：/var/sess/sess_1a68f4d3090a85e92002a71e637b145fdb003bb6
//           /var/sess/sess_fa78813680ede4e56b5ceee4e3c924d7a4fef965b
?>
```

```bash
# 用读到的 session id 作为 Cookie 访问后台（HTTPS 示例）
curl -k -H 'Cookie: SECUREPHPSESSID=1a68f4d3090a85e92002a71e637b145fdb003bb6' \
     https://target/ | grep -i 'root\|dashboard'
# 浏览器等价操作：DevTools → Application → Cookies → 修改 SECUREPHPSESSID 值后刷新
```

## 变体与关联

- 变体：会话文件命名随 PHP 配置/设备实现不同（`sess_<id>` 下划线、`sess-<id>` 连字符）；会话数据可能 Base64/序列化/自定义，只用于确认身份，不影响劫持。
- 变体：无目录列举但可预测 ID 时（低熵 PRNG、固定 session id），直接猜 ID；与 [[web-generic-auth-php-session-file-write-forge]]（写入伪造会话）互补——一个读、一个写。
- 关联：J-Web 的实际案例见 [[web-php-rce-juniper-jweb-phprc-env-injection-cve-2023-36845]]（CVE-2023-36845 提供读文件能力后劫持 root 会话）。
- 边界：会话目录不可读、会话已过期、会话绑定 IP/UA、使用 Redis/DB 会话存储时本手法不成立或被削弱。

## 检测与防御

- 修复：任意文件读取/代码执行漏洞是根因，须优先修复；会话目录权限收紧（仅 Web 进程可读写，其他用户不可读），避免 `/var/sess`、`/tmp` 全局可读。
- 加固：改用 Redis/数据库会话并加会话绑定（IP/UA/设备指纹）；设置较短会话超时与旋转；敏感后台要求二次认证；HTTPS/HTTP 会话名统一且 HttpOnly/Secure。
- 检测：Web 进程外对会话目录的批量读取（glob/ls 行为）、短时间内大量 `sess_*` 文件访问；同一会话 ID 从不同 IP/UA 复用；异常 Cookie 值命中现有会话文件。
