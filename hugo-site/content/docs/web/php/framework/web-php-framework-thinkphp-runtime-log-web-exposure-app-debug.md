---
id: web-php-framework-thinkphp-runtime-log-web-exposure-app-debug
title: ThinkPHP app_debug 开启且 runtime/log 可直读：按日期遍历日志泄露 SQL、请求参数与数据库连接信息
type: scenario
domain: web
path: web/php/framework
technique: thinkphp-runtime-log-web-exposure-app-debug
tags:
- php
- thinkphp
- information-disclosure
- log
- app-debug
- debug
- cms
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V644
  verified_at: '2026-11-13T03:32:32+08:00'
  notes: 已对照原文与截图 img39/40/42/43/44 核对：config/log.php 默认 type=File、single=false、max_files=8、close=false（img39）、config/app.php app_debug=true（img40）、.env APP_DEBUG 覆盖说明（img41）、runtime/log/202303/07.log|08.log（img42）、直接 GET 同目录日志回显 DB CONNECT mysql:host=127.0.0.1;port=3306;dbname=kitecms 与 SQL 语句（img43/44）。dedup top 候选 thinkphp-debug-sql-error-env-credential-leak 走报错页环境变量，非同链。未验证点：未复跑；max_files=8 的实际保留行为未验证。
url: /docs/web/php/framework/web-php-framework-thinkphp-runtime-log-web-exposure-app-debug/
draft: false
kb_aliases:
- ThinkPHP 日志泄露
- runtime/log 暴露
- app_debug 日志泄露
- TP 日志信息泄露
---

# 一句话结论

ThinkPHP 默认启用文件日志（`config/log.php` 中 `type=File`、`path=''`），当 `config/app.php` 的 `app_debug=true`（或 `.env` 中 `APP_DEBUG=true`）时会把请求详情、SQL 执行语句、错误与调用信息写入 `runtime/log/YYYYMM/DD.log`；若 Web 服务器未禁止访问 `runtime` 目录，攻击者无需登录即可直接 GET `/runtime/log/202303/08.log` 并按日期目录遍历，得到完整 SQL（含数据库 host/库名）、请求参数、路径等敏感信息，为进一步攻击提供凭据与结构。

# 原理

- **默认日志配置**：ThinkPHP 5 的 `config/log.php` 返回 `['type'=>'File','path'=>'','level'=>[],'single'=>false,'apart_level'=>[],'max_files'=>8,'close'=>false]`，即开启文件日志、按日期分目录写入 `runtime/log/YYYYMM/DD.log`。
- **调试模式放大记录**：`config/app.php` 的 `app_debug=true` 会让框架记录详细调试信息（请求参数、SQL、错误堆栈、Trace）；ThinkPHP 官方文档亦说明开启调试模式会详细记录日志（原文引用了该说明）。`.env` 中的 `APP_DEBUG=true` 会覆盖配置文件。
- **目录位于 Web 根**：ThinkPHP 默认 `runtime` 目录在项目根下，若 Web 服务器未对 `/runtime` 做 deny 规则，日志文件可直接通过 HTTP 访问；文件名按日期可枚举，`max_files` 仅保留最近若干天但仍可遍历。
- **日志内容价值**：日志中的 SQL 语句包含 `mysql:host=...;port=...;dbname=...;charset=...` 以及业务查询、参数；调试信息可能包含请求体、Cookie、文件路径，可用于发现后台地址、数据库结构、上传接口与凭据。
- **为什么是漏洞**：日志文件本身是调试产物，不应对外可读；应用把调试模式误开到生产并保留默认 runtime 路径，两者叠加导致未授权的信息泄露。

# 触发条件

- 目标为 ThinkPHP 应用（原文 KiteCMS 基于 TP5.1），`app_debug=true` 或 `.env` 中 `APP_DEBUG=true`。
- `config/log.php` 保持默认文件日志开启（`close=false`）。
- Web 服务器未禁止访问 `/runtime/`（无 Nginx location deny、无 .htaccess 限制），且 `runtime/log` 目录可列/可猜路径。
- 知道或可枚举日期（`YYYYMM/DD.log`）。

# 利用步骤

1. 访问 `/runtime/log/` 或直接猜测 `/runtime/log/202303/08.log`；原文用 BurpSuite 修改日期参数获取不同日期的日志。
2. 遍历 `YYYYMM` 目录与 `DD.log` 文件，下载历史日志。
3. 在日志中检索 `mysql:host=`、`SQL`、`[ DB ]`、`[ SQL ]`、`[ info ]`、请求参数、`Cookie`、路径等关键字。
4. 提取数据库 host/库名、后台路径、接口参数、可能的凭据或 Token，用于后续登录/注入/上传攻击。

# PoC

```http
GET /runtime/log/202303/08.log HTTP/1.1
Host: target
```

响应为文本日志，含类似：
```text
[2023-03-08T08:04:12+08:00][info] [ DB ] CONNECT:[ UseTime:0.012917s ] mysql:host=127.0.0.1;port=3306;dbname=kitecms;charset=utf8mb4
[ SQL ] SHOW COLUMNS FROM `kite_admin` [ RunTime:0.000498s ]
```

# 变体与关联

- `.env` 文件存在时以 `APP_DEBUG=true` 为准，配置文件的 `app_debug` 可能被覆盖；两者任一开启即可。
- `single=true` 时日志为单文件，路径不同但仍可访问；`level` 过滤可能减少记录内容。
- 与 ThinkPHP 调试页报错泄露（[[web-php-framework-thinkphp-debug-sql-error-env-credential-leak]]）互补：前者通过触发异常看环境变量，本卡直接读历史日志。
- 同类日志包含/投毒：[[web-php-file-inclusion-weiphp5-templatefile-param-binding-fetch-log]]。

# 检测与防御

- 检测：Web 访问日志中出现对 `/runtime/`、`/runtime/log/`、`*.log` 的请求（尤其非管理员 IP）；应用日志目录被外部访问；异常日期枚举。
- 防御：生产环境关闭 `app_debug`（`APP_DEBUG=false`）并关闭详细日志；Web 服务器显式 deny `/runtime`、`/storage`、`/config` 等目录；把 `runtime` 移到 Web 根之外；日志文件权限最小化；定期清理并监控日志访问。
