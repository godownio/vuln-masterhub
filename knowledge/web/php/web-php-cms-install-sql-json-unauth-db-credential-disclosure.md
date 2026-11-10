---
id: web-php-cms-install-sql-json-unauth-db-credential-disclosure
title: CMS 安装目录残留 install/sql-config/sql.json：未授权读取数据库主机、库名、账号与明文口令
type: scenario
domain: web
path: web/php
technique: install-config-json-unauth-db-credential-disclosure
aliases:
- sql.json 数据库配置泄露
- install 目录未清理
- 安装残留配置文件
- RapidCMS 未授权信息泄露
- 数据库账号口令泄露
tags:
- php
- cms
- install
- information-disclosure
- database-credential
- unauthenticated
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V392
  verified_at: '2026-11-09T11:30:29+08:00'
  notes: 已对照原文全文与全部42图核对：RapidCMS 1.3.1 安装完成页提示清空 install/install-config/install.json（图09）、runlogin.php 用 file_get_contents('../install/sql-config/sql.json') 读配置连库（图14）、未授权 GET /install/sql-config/sql.json 返回 server/dbusername/dbpassword/dbname（图12，实测 root/root，卡片以占位符呈现）均一致。与 web-php-rce-install-config-unescaped-dbname（配置字段注入 RCE）、Joomla API 配置泄露、IIS web.config.bak 扫描均非同一条，dedup related/new 成立。PoC 未在本机执行；未授权路径可访问性依赖站点根部署。frontmatter 无 sources/source_url/文章ID。
---

## 一句话结论

不少 PHP CMS 的安装器会把数据库连接信息写成 `install/sql-config/sql.json`（含 `server`、`dbusername`、`dbpassword`、`dbname`），运行期再由登录等脚本 `file_get_contents` 读取；安装完成后若 install 目录未被删除或未被 Web 服务器禁止访问，直接 GET `/install/sql-config/sql.json` 即可未授权拿到数据库主机、库名、账号和明文口令，进而直连数据库或复用口令横向。

## 原理

- **安装器生成、运行期依赖**：安装流程初始化数据库后把连接参数写入 `install/sql-config/sql.json`；业务代码（如后台登录 `runlogin.php`）通过 `file_get_contents('../install/sql-config/sql.json')` + `json_decode` 读取，再 `mysqli_connect($dataxx['server'], $dataxx['dbusername'], $dataxx['dbpassword'], $dataxx['dbname'])`。
- **安装锁与配置分离**：安装完成只写另一个文件 `install/install-config/install.json` 作为“已安装”锁（安装页提示“解锁请清空 install/install-config/install.json”），但 `sql.json` 仍留在原地，也没有被删除或移出 Web 根。
- **为什么未授权可读**：`sql.json` 是静态 JSON 文件，Apache/Nginx 默认把 install 目录当普通静态目录处理，没有鉴权；目录列表可能关闭，但已知/猜测路径即可直接取。`install/` 不在入口 `public/` 之下时是否可访问取决于虚拟主机把站点根指向哪一层，本例站点根包含 install 目录，故可直接访问。
- **影响**：泄露的是数据库连接凭据，通常是安装时填写的 root/高权限账号（示例为 `root`/`root`）。拿到后可尝试直连 3306、通过 SSRF/数据库客户端读库表、枚举其他系统凭据；口令复用时可进一步登录主机或其它业务。
- **审计意义**：这是“安装残留”类问题，不依赖复杂漏洞；扫描 `install/`、`setup/`、`install.php`、`sql.json`、`install.json`、`config.php.bak` 等路径往往能直接拿到配置，是代码审计/黑盒打点的低成本入口。

## 触发条件

- 目标为使用 install 安装器且安装后未清理 install 目录的 PHP CMS（示例 RapidCMS）。
- Web 服务器可访问站点根下的 `install/` 目录，`sql.json` 未被 .htaccess/nginx 规则拒绝。
- 数据库账号为高权限或口令可复用（按最小权限部署的应用账号价值较低）。
- 数据库端口可直连，或存在 SSRF/内网代理等访问 DB 的通道（否则仅获得配置信息，价值下降）。

## 利用步骤

1. 指纹识别 CMS 与版本（首页/后台/静态资源），判断是否使用 install 安装器。
2. 尝试访问 `GET /install/sql-config/sql.json`；若 404，再试 `install/install-config/install.json`、`install/setp*.php`、`install.php` 等路径确认 install 目录存在。
3. 从返回 JSON 中提取 `server`、`dbusername`、`dbpassword`、`dbname`。
4. 若数据库端口可达，用 mysql 客户端直连并验证权限；枚举库表、管理员表与自定义凭据表。
5. 若数据库不可直连，使用泄露信息辅助后续利用（例如配合 SSRF、数据库写文件功能、或口令复用尝试后台/主机登录）。
6. 测试完成后清理测试连接与会话，避免改动业务数据。

## PoC

```http
GET /install/sql-config/sql.json HTTP/1.1
Host: target
```

```json
{
  "server": "localhost",
  "dbusername": "root",
  "dbpassword": "<明文口令>",
  "dbname": "rapidcms"
}
```

```bash
# 数据库端口可达时直连验证
mysql -h <server> -u root -p'<dbpassword>' -D <dbname> -e 'select database(), user();'
```

说明：以上按原文复现流程整理；示例中数据库账号为安装时填写的高权限账号，实际目标以返回内容为准。

## 变体与关联

- **路径变体**：`install/install-config/install.json`（安装锁，可确认安装状态）、`install/setp*.php`（安装步骤页）、`config/database.php`、`config.php.bak`、`.env`、`database.sql` 备份等；目录列举开启时可一次枚举。
- **读取变体**：配置被 `install.lock`/`install.json` 保护但文件仍可读；配置写入 `runtime/`、`data/` 等可写目录时同样可能被直接下载。
- **关联**：[[web-php-joomla-api-config-application-public-db-credential-leak]]（API 鉴权缺失泄露配置，机制不同但同属未授权 DB 凭据泄露）；[[web-php-rce-install-config-unescaped-dbname]]（安装配置字段未转义进入 SQL 的另一类问题）。
- **边界**：install 目录已删除、Web 服务器拒绝访问、配置移出 Web 根、数据库账号为最小权限且端口不可达时，单独泄露配置的危害有限。

## 检测与防御

- **部署**：安装完成后删除整个 `install/` 目录（或至少删除 `sql.json`/`install.json` 并禁止访问），把配置移到 Web 根之外；备份文件与 `.env` 同样不得位于可下载路径。
- **权限**：数据库使用最小权限应用账号，禁止 root 远程连接；安装后立即更换安装时使用的口令，并禁止口令复用。
- **检测**：访问日志中出现 `/install/sql-config/sql.json`、`/install/install-config/install.json`、`/install/setp` 等路径；响应体含 `dbpassword`、`dbusername` 字段；对 Web 根做敏感文件基线扫描。
- **运营**：上线检查清单加入“安装残留与备份文件清理”，CI/部署脚本自动删除 install 目录并对站点根做 404 基线校验。
