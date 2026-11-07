---
id: web-generic-sqli-sqlite-attach-database-write-template-include
title: SQLite 堆叠注入 ATTACH DATABASE 写 EJS 模板：借模板 include 读取服务器文件
type: scenario
domain: web
path: web/generic/sqli
technique: sqlite-attach-database-write-template-include
aliases:
- SQLite ATTACH DATABASE 写文件
- db.exec 堆叠注入写模板
- EJS include 读文件
- SQLite 写 webshell 模板
- ATTACH DATABASE EJS
tags:
- sqli
- sqlite
- stacked-queries
- attach-database
- file-write
- ejs
- template-include
- nodejs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:39:40+08:00'
  notes: 已对照原文与全部 89 张图片核对；payload、ATTACH DATABASE 路径与 include 链一致；未在目标环境复现
---

## 一句话结论

Node/Express 应用如果在注册等接口用 `db.exec` 执行拼接 SQL，就支持多语句堆叠注入；SQLite 的 `ATTACH DATABASE '/app/views/upload.ejs' AS test` 会在模板目录创建数据库文件，随后 `CREATE TABLE` + `INSERT` 把 EJS 内容 `<%= include("/flag.txt") %>` 写进该文件，再访问会渲染 `upload.ejs` 的路由，模板引擎执行 include 读出服务器文件。

## 原理

- SQLite 的 `ATTACH DATABASE 'path' AS name` 会把指定路径作为数据库文件打开/创建；如果路径落在 Web 应用的模板目录（如 `/app/views`），就会在磁盘上生成一个文件。该文件是合法 SQLite 数据库，但其中的表数据按字节原样保存，攻击者可以把任意文本写进数据页。
- `db.exec`（sqlite3 模块）与 `db.get`/`db.run` 不同，允许一次执行多条以分号分隔的 SQL；当用户输入被直接拼进 SQL 时，就能堆叠 `ATTACH`、`CREATE TABLE`、`INSERT`。
- 模板引擎（EJS）渲染文件时按标签扫描：SQLite 文件头的二进制会被当作普通文本输出，但 `INSERT` 写入的 `<%= include("/flag.txt") %>` 会被识别并执行，从而把目标文件内容拼进响应。
- 该链成立需要四个条件：可控 SQL 拼接、可堆叠执行、模板目录可写、存在渲染攻击者可控文件名/固定文件名的路由；缺一不可。

## 触发条件

- 应用使用 SQLite，且某处把用户输入拼进 `db.exec` 等支持多语句的接口。
- 进程对模板目录有写权限，且该目录下存在会被渲染的模板名（如 `/upload` 路由渲染 `upload.ejs`）。
- 模板引擎允许 `include`/文件读取，且模板目录内的新文件会被加载。

## 利用步骤

1. 在注入点闭合原 SQL，例如注册接口的 `INSERT INTO users ... VALUES ('<input>', ...)`。
2. 用 `ATTACH DATABASE` 指向目标模板路径，创建别名库。
3. 在别名库中建表并插入恶意模板内容。
4. 用 `--` 注释掉原 SQL 剩余部分，保持语法完整。
5. 访问渲染该模板的路由（如 `/upload`），读取 include 的文件内容。

## PoC

```sql
');ATTACH DATABASE '/app/views/upload.ejs' AS test;
CREATE TABLE test.demo (data TEXT);
INSERT INTO test.demo (data) VALUES ('<%= include("/fla4444444aaaaaagg.txt") %>'); -- ('
```

对应的注入请求（示意）：`POST /register`，`username` 参数填入上述 payload，`password` 随意；随后 `GET /upload`。

## 变体与关联

- SQLite 其他写文件方式：`VACUUM INTO '/path'`（只能写数据库格式）、`ATTACH` + 表数据；MySQL `INTO OUTFILE`、PostgreSQL `COPY ... TO PROGRAM`/大对象。
- 模板引擎变体：EJS `include`、Jinja2 `{% include %}`、Thymeleaf `th:replace`、FreeMarker `<#include>`。
- 关联：SQL 注入写 JSP webshell（FineReport 系列）、模板引擎 SSTI、任意文件写入。

## 检测与防御

- 所有 SQL 使用参数化查询，禁止把用户输入拼进 `db.exec`；关闭不必要的多语句执行。
- SQLite 连接使用最小权限，模板目录只读；Web 进程不应能写 `views`/`templates`。
- 模板渲染只允许白名单模板名，禁止用户控制模板路径。
- 监控模板目录中的异常文件创建与 SQLite 文件头出现在模板目录的情况。
