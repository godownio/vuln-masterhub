---
id: web-php-wordpress-db-hash-update-plugin-credential-harvest
title: 拿到 WordPress 数据库凭据后直改 wp_users 密码哈希接管后台，再读取密码管理插件存储的 SSH 私钥
type: scenario
domain: web
path: web/php
technique: wordpress-db-hash-update-admin-takeover-credential-harvest
aliases:
- WordPress 改数据库密码
- wp_users user_pass 更新
- wp-config 数据库凭据利用
- 密码管理插件凭据读取
- pms_encrypt_key
- wp-admin 接管
tags:
- wordpress
- php
- mysql
- wp_users
- phpass
- credential
- password-manager
- ssh-key
- admin-takeover
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V617
  verified_at: '2026-11-12T20:57:03+08:00'
  notes: 已对照原文及截图核对：截图40-43 show tables 见 wp_pms_passwords、pms_encrypt_key，截图41-42 存 SSH key 条目与加密私钥，截图45 wp-config 泄漏 DB 凭据，截图46 useotools 生成 phpass 哈希，截图47-48 登录 wp-admin 且终端确认 UPDATE wp_users 成功，随后获得 id_rsa。与 web-php-wordpress-backup-sql-phpass-credential（读备份破解）及 Joomla 改哈希卡（不同 CMS）非同一链；库内无 wp_users 直改哈希卡。非组件漏洞故不设 affected_versions。未在本机复现。
---

## 一句话结论

一旦拿到 WordPress 的数据库凭据（`wp-config.php` 可读、SQL 注入可写、或数据库弱口令），不必破解现有密码哈希：生成一个已知口令的 phpass 哈希并 `UPDATE wp_users SET user_pass=...`，即可直接以管理员登录 `wp-admin`；密码管理类插件（如 passwords-manager）把用户凭据加密存在自建表中（密钥在 `wp_options` 的 `pms_encrypt_key`），登录后台后即可读取插件解密展示的 SSH 私钥，从 Web 层转入系统层。

## 原理

- WordPress 登录校验只比较 `wp_users.user_pass` 中存储的 phpass 哈希（`$P$...`）与输入口令的派生结果；对 `wp_users` 有写权限就等价于对该账户有完全控制权，无需知道原密码或破解哈希。
- `wp-config.php` 明文存放 `DB_NAME`、`DB_USER`、`DB_PASSWORD`、`DB_HOST`；Web 进程用户（或通过 LFI/备份泄露）可读取，MySQL 若只监听 localhost，则可借助已获得的 shell 或 SSH 端口转发连接。
- 密码管理插件通常自建表保存用户录入的密码/密钥（原文为 `wp_pms_passwords`，字段含 `user_name`、`user_email`、`user_password`、`url` 等），并用数据库/选项中的对称密钥（原文 `wp_options.pms_encrypt_key`）加密；插件后台页面会用该密钥解密并展示明文，因此拿到管理员会话即可收割。
- 为什么用"改哈希"而不是"破解"：phpass 哈希抗爆破，强口令几乎不可破；而写入权限允许直接替换为攻击者已知口令的哈希，一步完成账户接管，且可保留原管理员账户名以规避新建账户的审计。

## 触发条件

- 可读取 `wp-config.php` 或经其它途径获得 WordPress 数据库账号（且有 `wp_users` 写权限）；
- 数据库可从攻击机/跳板机连通（可配合端口转发）；
- 目标站点安装并使用了存储敏感凭据的插件（密码管理器、SMTP、备份、API key 管理等），且凭据有复用价值；
- 需要处理域名解析（如把站点域名指向目标 IP 或本地 hosts）。

## 利用步骤

1. 从 `wp-config.php` 读取 `DB_NAME/DB_USER/DB_PASSWORD/DB_HOST`，或从泄露的配置/备份中获得。
2. 连接 MySQL：`mysql -u <user> -p'<pass>' <db>`，`show tables;` 确认 WordPress 表与插件自建表。
3. 枚举 `wp_users` 中的管理员 `user_login`；查询插件表（如 `wp_pms_passwords`）确认是否存有 SSH key、账号等条目，以及 `wp_options` 中的插件加密密钥（如 `pms_encrypt_key`）。
4. 用在线或本地 phpass 工具为目标口令生成哈希（形如 `$P$B...`），执行 `UPDATE wp_users SET user_pass='<hash>' WHERE user_login='<admin>';`。
5. 访问 `/wp-login.php` 或 `/wp-admin` 用新口令登录；如站点绑定域名，先配置 hosts 或端口转发。
6. 在插件管理页面读取解密后的凭据；原文据此获得 `id_rsa`，SSH 登录目标系统用户，进入下一层提权。

## PoC

```sql
-- 数据库侧最小操作（哈希为已知口令的 phpass）
UPDATE `wp_users` SET `user_pass` = '$P$BqTMH6f2/YJmGLjPetfgm3MnNewMhS1' WHERE user_login = 'admin';
SELECT option_value FROM wp_options WHERE option_name = 'pms_encrypt_key';
SELECT user_name, user_email, url FROM wp_pms_passwords;
```

```text
# 连接与转发示例
mysql -u wordpressuser -p'wordpresspassword123!!' wordpress
ssh -L 3306:127.0.0.1:3306 user@target   # 数据库仅监听 localhost 时
```

## 变体与关联

- 变体：直接 `INSERT` 一个新管理员账户（可能触发通知/审计）；或改 `user_email` 后走"忘记密码"流程（依赖邮件可达）。
- 变体：不改库而在后台插件中直接读凭据——需要已有管理员会话（XSS/会话劫持/弱口令）。
- 变体：若只能读库不能写，转去导出 `wp_users` 哈希离线破解或找备份中的历史用户（见关联卡）。
- 关联：[[web-php-wordpress-backup-sql-phpass-credential]]（备份 SQL + phpass 破解 + 口令复用，与本卡"在线改哈希"路径不同）、[[web-generic-sqli-wordpress-151-cat-union-dump-wp-users]]（SQL 注入导出 wp_users）。

## 检测与防御

- 开发/运维：`wp-config.php` 权限收紧到 Web 用户只读且禁止其它用户读取；数据库账户最小权限（不给 `wp_users` 任意写）、禁止远程 root；定期轮换数据库口令。
- 插件治理：避免在 WordPress 中存储 SSH 私钥等高价值凭据；密码管理插件必须使用强加密并限制后台访问。
- 检测：监控 `wp_users.user_pass` 的非插件更新（尤其伴随 `user_login` 未变、登录来源异常）；监控数据库中 `UPDATE wp_users`；对 `wp-admin` 登录做异常来源与 MFA 校验。
