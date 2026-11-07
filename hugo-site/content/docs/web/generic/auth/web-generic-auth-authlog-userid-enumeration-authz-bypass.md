---
id: web-generic-auth-authlog-userid-enumeration-authz-bypass
title: 认证日志接口泄露合法 userId 后枚举用户详情：绕过按 ID 归属的访问限制
type: scenario
domain: web
path: web/generic/auth
technique: authlog-userid-enumeration-authz-bypass
tags:
- auth
- authz
- idor
- enumeration
- data-leak
- broken-access-control
- education
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V74
  verified_at: '2026-11-05T16:56:17+08:00'
  notes: 已对照原文与图11-15核对：学生 token 的 permissions 含 app:appAuthLog:list/system:user:query/export；/api/app/appAuthLog/list 返回 total=53463 并含 userId；/api/system/user/1 返回 roleName 超级管理员、/2 返回“没有权限访问用户数据”，用日志中的 userId 请求详情成功，均与卡内一致。未验证点：原文“userId 来自 authlog”为作者推断（日志响应截图中字段被打码），PoC 未复跑。
url: /docs/web/generic/auth/web-generic-auth-authlog-userid-enumeration-authz-bypass/
draft: false
kb_aliases:
- appAuthLog 未授权
- userId 枚举
- 合法 ID 旁路越权
- 用户详情接口越权
- 认证日志数据泄露
---

## 一句话结论

当低权限账号持有 `app:appAuthLog:list` 等越权菜单、认证日志接口又未做数据范围限制时，可直接拉到数万条含 userId 的认证记录；用户详情接口虽然会拒绝顺序枚举的 id=1/2，但用日志中泄露的真实 userId 逐个请求就能读到大量师生账号信息。

## 原理

- 权限模型有两层：功能级（能不能调用接口）与数据级（能看哪些对象）。该系统给普通学生账号分配了 `app:appAuthLog:list`、`system:user:query`、`system:user:export` 等管理权限，功能级校验已经失效。
- `GET /api/app/appAuthLog/list` 返回 `total: 53463` 级别的认证日志，字段包含姓名、工号/学号、账号名与内部 `userId`；接口没有按当前用户/租户过滤，等于一份合法的用户 ID 字典。
- `GET /api/system/user/{id}` 看似做了对象级校验：`id=1` 返回超级管理员信息，`id=2` 返回“没有权限访问用户数据！”；这说明校验不是“当前用户只能看自己”，而是某种 ID 归属/数据范围判断（例如只允许访问同一租户或同一数据源中的用户）。
- 顺序枚举会先撞到不属于当前数据范围的 ID（1、2），因此看起来被拦住；但日志接口泄露的 userId 恰好都属于可见范围，用这些 ID 请求即可绕过“顺序枚举被拒”的假象，批量读取用户详情。
- 根因是把“ID 是否合法/是否在可见集合”当作授权，而不是按调用者的角色与对象归属做检查；攻击者只需另一个接口提供合法 ID 集合，就能把受限枚举变成全量枚举。

## 触发条件

- 攻击者持有低权限账号，且账号被分配了日志/用户管理等超出其角色的功能权限。
- 认证日志、登录日志、操作日志等列表接口未做数据范围过滤，响应包含目标对象的内部 userId。
- 用户详情/资料接口按 ID 返回敏感信息，授权逻辑依赖 ID 归属或可见集合，而非明确的对象级授权。
- 系统未对批量枚举做速率限制、审计或异常检测。
- 用户详情响应包含姓名、工号/学号、账号、角色、联系方式等可识别信息。

## 利用步骤

1. 登录低权限账号，读取其权限列表，标记 `app:appAuthLog:list`、`system:user:query`、`system:user:export` 等不应属于该角色的权限。
2. 请求日志接口（如 `GET /api/app/appAuthLog/list`），记录 `total` 与单条记录中的 `userId`、账号、姓名、工号等字段。
3. 直接请求用户详情接口 `GET /api/system/user/1`、`/2`，确认顺序枚举是否被“没有权限访问用户数据”拦截。
4. 从日志响应中提取真实 userId 列表，去重后逐个请求 `GET /api/system/user/{userId}`；若返回 200 且含角色、姓名、账号等字段，说明按合法 ID 旁路成功。
5. 用分页/批量参数扩大日志拉取范围，统计可读取的用户数量与字段；抽样验证数据真实性，避免全量下载。
6. 用泄露的账号信息结合密码重置、撞库或社工继续接管高权限账号，评估最终危害。

## PoC

```http
GET /api/app/appAuthLog/list HTTP/1.1
Host: target
Authorization: Bearer <student-token>

HTTP/1.1 200 OK
{"code":200,"total":53463,"rows":[{"userId":12345,"userName":"张三","loginName":"2023xxxx","deptName":"..."}]}
```

```http
GET /api/system/user/1 HTTP/1.1
Host: target
Authorization: Bearer <student-token>

HTTP/1.1 200 OK
{"code":200,"data":{"userId":1,"roleIds":["1"],"roleName":"超级管理员","roleKey":"admin"}}
```

```http
GET /api/system/user/2 HTTP/1.1
Host: target
Authorization: Bearer <student-token>

HTTP/1.1 200 OK
{"code":500,"msg":"没有权限访问用户数据！"}
```

```python
import requests

H = {"Authorization": f"Bearer {token}"}
logs = requests.get(f"{BASE}/api/app/appAuthLog/list",
                    headers=H, params={"page": 1, "pageSize": 100}, timeout=15).json()
ids = {row["userId"] for row in logs.get("rows", [])}

for uid in list(ids)[:20]:          # 小样本验证，勿全量抓取
    r = requests.get(f"{BASE}/api/system/user/{uid}", headers=H, timeout=15)
    print(uid, r.status_code, r.text[:200])
```

## 变体与关联

- 变体：日志接口换成登录日志、操作日志、消息通知、组织架构、导出任务等，只要返回内部 userId/工号即可作为字典。
- 变体：详情接口的校验可能是“同租户/同部门/同数据源”，用另一接口泄露的 ID 同样可绕过；也可结合导出接口批量拉取。
- 变体：若用户详情只对 id=1 放行，可用超级管理员 ID 读取其资料，再通过角色/菜单接口扩展权限。
- 关联：[[web-generic-auth-teacher-roster-api-student-token-lesson-enumeration]]（同类“低权限 Token 调用高权限接口 + 自增 ID 枚举”的批量数据泄露）、[[web-generic-auth-missing-function-level-role-check]]（只验登录不验角色的通用根因）、[[web-generic-auth-gettokenbyid-userid-token-issuance]]（用 userId 换 Token 的另一条链）。
- 边界：日志接口按当前用户过滤、用户详情做严格对象级授权、返回字段脱敏、批量请求被限速时，本路径失效；仅拿到姓名/账号而无其他凭据时，危害取决于后续撞库/重置成功率。

## 检测与防御

- 检测：低权限账号调用管理端日志/用户接口；同一 Token 在短时间内请求大量不同 userId；日志接口返回的 total 与账号权限不匹配；响应中包含未脱敏的姓名、工号、账号。
- 修复：按角色做功能级授权（默认拒绝），只给需要的菜单/接口权限；日志与用户详情按当前用户的数据范围过滤，而不是先返回再校验。
- 修复：用户详情做对象级授权（只能访问本人或明确授权的对象），不要用“ID 是否存在/是否在可见集合”代替归属校验。
- 加固：对批量查询加分页上限、速率限制与审计告警；敏感字段脱敏返回；定期复核学生/普通账号的角色与权限分配。
