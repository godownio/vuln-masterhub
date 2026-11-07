---
id: web-php-wordpress-backup-sql-phpass-credential
title: WordPress 配置与旧数据库备份泄露：phpass 破解历史账户并复用至宿主机 SSH
type: scenario
domain: web
path: web/php
technique: wordpress-backup-sql-phpass-credential-reuse
tags:
- wordpress
- php
- backup
- credential
- phpass
- hashcat
- ssh
- container
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T12:16:37+08:00'
  notes: 已对照全文核对：wp-config.php 泄露 DB_NAME wp/DB_USER wp/DB_PASSWORD fiFtDDV9LYe8Ti；在线 wp_users 仅 admin 且 /... rockyou 未破；/opt/wordpress/backup-13-04-2020.sql 末尾含 lynik-admin 的 /wzJzd3pj/n7oTe2GGpi5HcIl4ppc.，hashcat -m 400 破解为 1stepcloser；用该口令 SSH 宿主机 lynik-admin 成功，容器/宿主机由 TTL 62/63、/proc/1/cgroup、/.dockerenv 判断。卡内步骤/PoC 与原文一致。未验证点：PoC 未在本机执行；备份路径/口令为靶场值。frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/php/web-php-wordpress-backup-sql-phpass-credential/
draft: false
kb_aliases:
- wp-config.php 数据库凭据
- WordPress 备份 SQL 泄露
- phpass hashcat 400
- wp_users 历史用户
- 容器 www-data 到宿主机 SSH
- 应用密码复用
---

## 一句话结论

拿到 WordPress 容器内的 www-data 后，`wp-config.php` 会给出数据库凭据；在线 `wp_users` 可能只有管理员且 hash 难以破解，但 `/opt`、Web 目录或备份目录中的旧 `.sql` 备份往往保留已删除用户及其 phpass 哈希；用 `hashcat -m 400` 破解后，应用账户口令可能被复用到宿主机 SSH，从而从容器跳到宿主机。

## 原理

- WordPress 的 `wp-config.php` 以明文保存 `DB_NAME`、`DB_USER`、`DB_PASSWORD`、`DB_HOST`；拿到 Web 进程读权限即可连数据库。
- `wp_users.user_pass` 使用 phpass（Portable PHP password hashing framework），哈希形如 `$P$B...`；hashcat 模式 400 可破解，rockyou 等字典对弱口令有效。
- 数据库备份是时间点快照：备份时存在的用户即使后来被删除，仍保留在 `.sql` 文件中。在线表可能只显示管理员，但备份里可能有历史管理员/运维账户。
- 备份文件常见位置：`/opt/<app>/backup-*.sql`、Web 根目录、`/var/www/backup`、`/backup`、Docker volume、`wp-content/backup`；扩展名 `.sql`、`.sql.gz`、`.bak`、`.dump`。
- 密码复用：WordPress 账户名/口令常与系统账户相同（本例 `lynik-admin` 既是 WordPress 用户也是宿主机用户），破解后可尝试 SSH/SMB/其他服务。
- 容器识别：Web 服务的 TTL 比宿主机少一跳（62 vs 63）、`/proc/1/cgroup` 含 `/docker/`、存在 `/.dockerenv`，说明拿到的是容器 shell；SSH 的 TTL 正常，说明 SSH 在宿主机。因此容器内的 www-data 不能直接 `su` 到宿主机用户，但可以用泄露凭据 SSH 宿主机。
- 为什么成立：备份文件权限过宽 + 应用与系统账户口令复用 + 容器与宿主机网络可达，三者叠加就把"容器内 Web RCE"升级为"宿主机用户登录"。

## 触发条件

- 已在 WordPress 容器内获得命令执行或任意文件读取（如主题/插件 RCE、文件包含、日志写入）。
- `wp-config.php` 可读，数据库可连。
- 目标存在可读的旧数据库备份（`.sql`/`.sql.gz`/`.bak`），且包含额外用户。
- 备份中的 phpass 哈希可被字典/规则破解。
- 破解出的口令在宿主机 SSH 或其他服务上复用，且宿主机 SSH 可达。

## 利用步骤

1. 读取 `wp-config.php`，取得数据库名、用户、口令、主机。
2. 连接数据库，查询 `wp_users`：`select ID,user_login,user_pass from wp_users;`。
3. 在文件系统搜索备份：`find / -name '*.sql' -o -name '*.sql.gz' -o -name '*.bak' 2>/dev/null`，重点看 `/opt`、`/var/www`、`/backup`。
4. 从备份中提取 `INSERT INTO wp_users`，得到历史用户与哈希。
5. 用 hashcat 破解 phpass：`hashcat -m 400 '<hash>' rockyou.txt`；必要时加规则/掩码。
6. 用破解出的账号口令尝试宿主机 SSH（注意容器 TTL 与宿主机 TTL 差异，SSH 通常在宿主机）。
7. 登录宿主机后读取 user flag，继续本地提权（如 LDAP/组配置）。

## PoC

```bash
# 1. 读取配置
cat /var/www/html/wp-config.php | grep -E "DB_NAME|DB_USER|DB_PASSWORD|DB_HOST"

# 2. 查询在线用户
mysql -u wp -p'<DB_PASSWORD>' wp -e 'select ID,user_login,user_pass from wp_users;'

# 3. 搜索备份
find / -type f \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.bak' \) 2>/dev/null

# 4. 备份中的历史用户
tail -n 20 /opt/wordpress/backup-13-04-2020.sql | grep 'INSERT INTO `wp_users`'

# 5. 破解 phpass
hashcat -m 400 '$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.' rockyou.txt
# ...:1stepcloser

# 6. 复用至宿主机 SSH
sshpass -p '1stepcloser' ssh lynik-admin@<host>
```

容器/宿主机判断（原文）：

```bash
cat /proc/1/cgroup        # 含 /docker/<id>
ls -la /.dockerenv        # 存在
nmap -sV -p 22,80 <host>  # 22 的 TTL 正常（宿主机），80/443 TTL 少一跳（容器）
```

说明：命令为原文流程的结构化复现，未在本机执行；仅用于授权测试。

## 变体与关联

- 变体：备份可能是 `.sql.gz`/`.zip`/`.tar.gz`，先解压再 grep；也可能在 Docker volume、CI 产物、对象存储中。
- 变体：其他 CMS/框架（Joomla、Drupal、Discuz、ThinkPHP）同样会在配置文件和备份中泄露数据库凭据与用户哈希。
- 变体：phpass 破解不出时可尝试用户名/公司名变体、规则攻击，或从其他泄露源获取口令，见 [[pentest-initial-access-password-semantic-mutation-reuse]]。
- 关联：[[pentest-privilege-escalation-credential-file-harvesting]]（主机侧凭据文件搜索）；[[pentest-privilege-escalation-ldap-sshpublickey-sssd]]（登录宿主机后的进一步提权）。
- 边界：备份不存在/不可读、哈希强口令破解失败、应用与系统口令不复用、宿主机 SSH 不可达或仅允许密钥时，本链不成立。

## 检测与防御

- 检测：Web 进程读取 `wp-config.php`、执行 `find / -name '*.sql'`、连接数据库查询 `wp_users`；容器内出现对 `/opt` 备份目录的访问。
- 检测：宿主机 SSH 出现来自容器网段或应用服务器的登录；同一口令在应用与系统账户上复用。
- 防御：删除 Web/opt 目录中的数据库备份，备份放到独立受控位置并加密；`wp-config.php` 权限最小化；数据库账户最小权限。
- 加固：应用账户与系统账户使用不同口令，禁止复用；启用 SSH 密钥登录并限制来源；容器与宿主机网络隔离，容器内不挂载敏感目录。

