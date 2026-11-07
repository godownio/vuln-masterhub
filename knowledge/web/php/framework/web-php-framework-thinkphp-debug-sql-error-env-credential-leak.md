---
id: web-php-framework-thinkphp-debug-sql-error-env-credential-leak
title: ThinkPHP 调试页 + 单引号 SQL 报错：Whoops 环境变量泄露数据库账号口令与绝对路径
type: scenario
domain: web
path: web/php/framework
technique: thinkphp-debug-sql-error-env-credential-leak
aliases:
- ThinkPHP 报错注入信息泄露
- Whoops 环境变量泄露
- APP_DEBUG 数据库密码泄露
- mobile 单引号 SQL 报错
- ThinkPHP Connection.php line 385
tags:
- php
- thinkphp
- debug
- app-debug
- sqli
- error-based
- information-disclosure
- credential-leak
- whoops
- env
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V247
  verified_at: '2026-11-07T12:49:32+08:00'
  notes: 已对照原文核对（含 44 张图）：mobile 单引号触发 SQLSTATE[42000] 1064、Connection.php line 385 调用栈（img13/14/16），随后 updatexml 报错注入取数（img15/16）并批量提取管理员登录 IP（img17）。最终危害成立：img29 的 Whoops Environment Variables 实际渲染 PHP_APP_DEBUG=1、PHP_APP_TRACE、PHP_APP_APIURL、PHP_DATABASE_HOSTNAME=127.0.0.1、PHP_DATABASE_DATABASE/USERNAME/PASSWORD、PHP_DATABASE_HOSTPORT=3306、PHP_DATABASE_PREFIX 及绝对路径/HTTP_TOKEN，原文正文亦明确“可以得到数据库账号密码、系统绝对路径”；截图中的口令值由作者打码，属发表脱敏，不影响泄露事实。卡片未声称已登录数据库，且已注明 Cloudflare 后台分支未打通，与原文一致。未验证点：未复跑请求、未验证泄露口令可直连 DB；frontmatter 无 sources/source_url。
---

## 一句话结论

ThinkPHP 应用在 `APP_DEBUG=true` 时，向登录/注册接口的 `mobile` 等字符串参数插入一个单引号即可让拼接 SQL 报语法错误；Whoops 异常页会显示 `Connection.php line 385` 的调用栈和完整 Environment Variables，其中包含 `PHP_DATABASE_HOSTNAME`、`PHP_DATABASE_DATABASE`、`PHP_DATABASE_USERNAME`、`PHP_DATABASE_PASSWORD`、`PHP_APP_DEBUG`、`PHP_APP_TRACE`、系统绝对路径和请求 Token 等，攻击者可直接获得数据库账号口令与内网路径，并可在同一注入点继续做报错注入取数。

## 原理

- **调试模式放大了错误**：ThinkPHP 在 `APP_DEBUG=true`（`.env` 的 `PHP_APP_DEBUG=1`）时注册 Whoops/异常处理器，SQL 异常、PHP 异常都会渲染调试页，包含错误消息、文件/行号、调用栈、Request Data、Cookies、Environment Variables、Server/Request Data。
- **SQL 拼接**：登录/注册逻辑把 JSON 体中的 `mobile`（以及 `password`/`oldpassword` 等）直接拼进 SQL，而不是使用参数绑定；插入 `'` 破坏字符串边界，数据库返回 `SQLSTATE[42000]: Syntax error or access violation: 1064 ...`，ThinkPHP 的 `Connection.php` 在 query 失败时抛出 `PDOException`，调试页把异常上下文完整输出。
- **环境变量来源**：ThinkPHP 的 `.env` 被加载到 `$_ENV`/`$_SERVER`，调试页的 Environment Variables 区块会逐项打印；`PHP_DATABASE_HOSTNAME/PHP_DATABASE_DATABASE/PHP_DATABASE_USERNAME/PHP_DATABASE_PASSWORD` 即数据库连接配置，`PHP_APP_DEBUG/PHP_APP_TRACE` 暴露调试状态，`HTTP_TOKEN`/`HTTP_X_FORWARDED_*` 暴露请求头与内部令牌。
- **为什么是完整漏洞而非仅报错**：泄露的数据库口令可直接用于连接数据库（若网络可达）或复用到其他服务；同一 `mobile` 参数既然能触发语法错误，就说明可控内容进入 SQL，可进一步用 `updatexml`/`extractvalue`/类型转换等报错注入函数把库名、表名、管理员登录 IP 等数据拼进错误消息回显。原文即用该注入点批量提取管理员登录 IP。
- **调试页同时泄露绝对路径**：`Error Context`/`Call Stack` 中的文件路径（如 `/www/wwwroot/.../Connection.php`）可用于定位 ThinkPHP 版本、项目结构和后续文件读取/上传路径。

## 触发条件

- 目标为 ThinkPHP 应用且 `APP_DEBUG=true`（生产环境误开调试）。
- 登录/注册等接口把 `mobile` 等参数拼进 SQL（未使用参数绑定/ORM 绑定）。
- 接口可达，且错误页未被 Nginx/安全产品统一拦截或替换。
- 需要一个合法的请求结构（原文为 JSON：`{"mobile":"...","password":"...","oldpassword":"..."}`）；无需登录。

## 利用步骤

1. 抓取登录/注册请求，确认 `Content-Type: application/json` 与参数名（原文为 `mobile`、`password`、`oldpassword`）。
2. 在 `mobile` 值末尾插入单引号（如 `"mobile":"1'"`），发送请求。
3. 观察响应：出现 `SQLSTATE[42000]: Syntax error or access violation: 1064`、`Connection.php line 385`、`Query.php line 355` 等调用栈，说明单引号进入 SQL。
4. 在 Whoops 调试页向下翻到 Environment Variables / Server/Request Data，读取 `PHP_DATABASE_HOSTNAME`、`PHP_DATABASE_DATABASE`、`PHP_DATABASE_USERNAME`、`PHP_DATABASE_PASSWORD`、`PHP_APP_DEBUG`、`PHP_APP_TRACE`、绝对路径、`HTTP_TOKEN` 等。
5. 若数据库端口可达，用泄露的账号口令直连数据库；否则继续在同一参数上用报错注入函数提取库名、表名、管理员账号/IP 等（原文脚本批量提取管理员登录 IP）。
6. 用泄露的路径/Token 进一步寻找后台、配置文件或其他服务入口；原文尝试访问疑似后台时被 Cloudflare 拦截，未打通该分支。

## PoC

```http
POST /api/... HTTP/1.1
Host: target
Content-Type: application/json

{"mobile":"1'","password":"x","oldpassword":"x"}
```

响应关键片段（字段值原文打码，仅保留结构）：

```text
SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; ...
  Connection.php line 385
  Query.php line 355

Environment Variables
PHP_APP_DEBUG      1
PHP_APP_TRACE      ...
PHP_DATABASE_HOSTNAME  ...
PHP_DATABASE_DATABASE  ...
PHP_DATABASE_USERNAME  ...
PHP_DATABASE_PASSWORD  ...
```

报错注入取数（示意，需按目标 DB 类型调整）：

```sql
1' and updatexml(1,concat(0x7e,(select database()),0x7e),1)-- -
```

## 变体与关联

- 若 `APP_DEBUG` 关闭但仍显示 SQL 错误，可能只泄露 SQL 语法/表名；可改用时间盲注或布尔盲注，但无调试页的环境变量泄露。
- 同一调试页也可能由其他 PHP 异常触发（未定义索引、类型错误），不一定需要 SQL 注入；审计时可先找任意能触发异常的参数，再看调试页是否回显环境变量。
- 与库内“SQL 报错注入：updatexml/extractvalue 与类型转换错误回显数据”卡的关系：本卡的重点是 ThinkPHP 调试页把 `.env` 数据库口令一起打印，报错注入只是同一注入点的延伸。
- 与库内“未鉴权文件上传叠加 ThinkPHP 调试异常页变量泄露落盘路径”卡的区别：那张卡的泄露对象是上传文件的落盘路径，本卡是数据库账号口令/环境变量/绝对路径，触发点是 SQL 语法错误。

## 检测与防御

- **关闭调试**：生产环境设置 `APP_DEBUG=false`、`PHP_APP_DEBUG=0`，并确保异常页不回显堆栈/环境变量；自定义统一错误页。
- **参数化查询**：所有 SQL 使用参数绑定/ORM 查询构造器，禁止字符串拼接；对 `mobile` 等输入做类型/格式校验。
- **最小化环境变量暴露**：不要在 Web 进程环境中放置不必要的密钥；`.env` 权限最小化；数据库账号使用最小权限、限制来源 IP。
- **检测**：监控响应中的 `SQLSTATE[42000]`、`Connection.php line`、`PHP_DATABASE_PASSWORD`、`Whoops` 等特征；WAF 拦截单引号/报错注入 payload；审计 `APP_DEBUG` 配置基线。
- **应急**：一旦确认泄露，立即轮换数据库账号口令与 `HTTP_TOKEN` 等密钥，排查数据库登录日志与异常查询。
