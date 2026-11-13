---
id: web-java-component-rebuild-unauth-sqli-del-share-id-delete
title: Rebuild /filex/del-make-share 未授权 SQL 注入：20 位 ID 参数拼接 DELETE 语句删除全表数据
type: scenario
domain: web
path: web/java/component
technique: unauth-sqli-id-param-delete
aliases:
- Rebuild SQL 注入
- del-make-share 注入
- ID 参数注入
- 未授权删除 User 表
- 001-aaaaaaaa'or 1=1#
tags:
- java
- rebuild
- sql-injection
- unauthorized
- delete
- data-destruction
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V577
  verified_at: '2026-11-12T11:16:43+08:00'
  notes: 已对照原文与8张图核对：/filex/del-make-share由/filex/白名单未授权放行；ID#isId仅校验长度20与charAt(3)=='-'，构造函数Integer.parseInt(substring(0,3))取实体码（图06），实体表69个、低位实体码真实存在（图07）；payload 001-aaaaaaaa'or 1=1# 恰20字符，调试器确认sqlList size=40、delete from 'User' where USER_ID = '001-aaaaaaaa'or 1=1#（图08），为未授权DELETE数据破坏而非仅资源DoS。原文无精确版本与CVE号，均留空；未提供完整HTTP请求/响应，confidence medium合理。dedup候选均为异产品SQL注入卡，非同链。verified。
---

## 一句话结论

Rebuild 的 `/filex/del-make-share`（`FileShareController#delShareFile`）因 URI 含 `/filex/` 被鉴权拦截器放行，其 `@IdParam ID shortId` 只校验长度 20 且第 4 位为 `-`、前 3 位为存在的实体编码，剩余 16 位被直接拼进 DELETE 语句；构造 `001-aaaaaaaa'or 1=1#` 可生成 `delete from 'User' where USER_ID = '001-aaaaaaaa'or 1=1#`，删除整张表数据，形成未授权数据破坏。

## 原理

- **鉴权绕过**：`RebuildWebInterceptor#isIgnoreAuth` 对包含 `/filex/` 的 URI 返回 true（另有 `/filex/access/`、`/filex/download/`、`/filex/img/` 前缀白名单）；`delShareFile` 方法内不调用 `getRequestUser`，因此无需登录即可调用。
- **ID 校验只做格式/长度**：`ID#isId` 只检查字符串长度等于 `idLength`（默认 20）且 `charAt(3) == '-'`；`ID#valueOf` 再构造 `ID`，构造函数把前 3 位 `Integer.parseInt(id.substring(0,3))` 作为实体编码。攻击者只需让前 3 位是真实存在的实体编码（示例系统内部实体编码 1–69 大量存在，可 001–999 爆破探测），中间固定 `-`，后 16 位可放任意字符。
- **实体校验不阻止注入**：`CommonsService#tryIfHasPrivileges` 用 `getEntityCode()` 取实体并拒绝带权限字段的业务实体，但不会校验 ID 其余字符；只要实体存在就进入删除流程。
- **SQL 拼接**：持久化层按实体/字段名拼接 `delete from '<entity>' where <pk> = '<id>'`，ID 后缀中的单引号闭合字符串，`or 1=1` 使 WHERE 恒真，`#` 注释掉残留引号，最终删除全表记录（调试器中可见 `sqlList` 批量生成 40 条 DELETE）。
- **长度限制的利用**：整个 ID 只有 20 字符，去掉 `001-` 后仅 16 字符可用；`aaaaaaaa'or 1=1#` 恰好占满，说明在严格长度限制下仍足以完成注入。

## 触发条件

- 目标为 Rebuild 历史版本，`/filex/del-make-share` 路由可达且未额外鉴权。
- 前 3 位实体编码真实存在（低位编码通常对应 User/Role 等内置实体，可枚举）。
- 数据库使用单引号字符串拼接且未开启严格预处理；目标表存在可删除数据。
- 攻击者可发送 POST 请求并控制 ID 参数。

## 利用步骤

1. 确认目标为 Rebuild，访问 `/filex/del-make-share` 不带登录态，观察是否返回业务响应而非 401。
2. 爆破实体编码：用 `001-aaaaaaaaaaaaaaaa` 之类合法长度 ID 逐个尝试 001–999，找到不报"实体不存在"的编码。
3. 构造注入 payload，使总长度为 20：`001-aaaaaaaa'or 1=1#`（URL 编码空格与 `#`：`001-aaaaaaaa'or+1=1%23`）。
4. 以 POST 提交到 `/filex/del-make-share`（参数为 `@IdParam` 绑定的 ID 字段），在调试/日志中确认生成的 SQL 形如 `delete from 'User' where USER_ID = '001-aaaaaaaa'or 1=1#`。
5. 数据库对应表数据被批量删除；可通过业务页面/接口确认数据消失（数据破坏/拒绝服务）。

## PoC

```http
POST /filex/del-make-share HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

id=001-aaaaaaaa'or+1=1%23
```

```sql
-- 实际拼接出的 SQL（调试器观察）
delete from 'User' where USER_ID = '001-aaaaaaaa'or 1=1#
-- sqlList 批量生成约 40 条 DELETE，覆盖全表
```

- 参数名以 `@IdParam` 的框架绑定为准（通常为 `id`）；不同版本路由前缀可能带 context path。
- 若 `#` 被过滤，可尝试 `-- `（需注意长度）、`or'1'='1` 等等长变体；时间盲注可先用 `and sleep(...)` 验证，但 16 字符空间有限。
- 本文仅演示 DELETE 注入导致的数据破坏/拒绝服务，未给出任意数据读取或 RCE 的后续链。

## 变体与关联

- **同产品其他 ID 参数接口**：所有接收 `@IdParam ID` 且位于 `/filex/` 白名单下的删除/查询接口都可能存在同类拼接问题，可批量审计。
- **未授权文件读取**：同版本 `FileDownloader#readRaw` 可未授权读取 `.rebuild` 配置并解密数据库口令，见相关卡片；拿到数据库口令后可直连扩大影响。
- **SQL 注入通用绕过**：长度受限场景可用注释符、等价表达式压缩 payload；实体编码枚举是此类"结构化 ID"注入的关键前置。

## 检测与防御

- **参数化查询**：持久化层对 ID 使用预编译参数或严格类型（数值/固定格式），禁止字符串拼接。
- **严格校验 ID**：按实际格式校验为 `\d{3}-[0-9a-z]{16}` 之类白名单正则，而不是只校验长度与分隔符。
- **收窄未授权面**：`/filex/` 白名单改为精确路由匹配，删除类接口强制登录与权限校验。
- **监控与恢复**：审计 `del-make-share` 调用与批量 DELETE；数据库账号最小权限、开启 binlog/备份，发现注入后立即隔离并恢复数据。
