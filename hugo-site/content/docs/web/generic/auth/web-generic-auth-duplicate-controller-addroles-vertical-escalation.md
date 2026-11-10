---
id: web-generic-auth-duplicate-controller-addroles-vertical-escalation
title: 重复/遗留控制器接口越权：单数 addRole 受限、复数 addRoles 可直接授予超管角色
type: scenario
domain: web
path: web/generic/auth
technique: duplicate-controller-legacy-endpoint-role-escalation
tags:
- web
- authz
- vertical-privilege-escalation
- broken-access-control
- swagger
- legacy-endpoint
- java
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V373
  verified_at: '2026-11-09T06:40:01+08:00'
  notes: 已对照原文全文与 26/26 张截图核对：img15 Swagger 中 Role Controller（addRoles 给角色分配用户s、delete、delRoles、getList）与 Zh Controller（addRole/addRoles 给用户分配角色）与卡一致；img23 /addRole?jsdm=...&xh=0 与 img24 /addRoles?jsdm=...&xh=0 均返回 {"success":true}（原文称 addRole 不能越权、addRoles 可越权，卡按此描述并在 PoC 注明 addRole 可能返回 success 但权限未变，符合原文叙述）；img25 超管用户管理页含身份证号列。修正一处：原 PoC 末句「超管角色字段为 createSfzh 相关字典创建者」无原文依据且与字典接口混淆，已改为「角色代码可通过 zh/getRole 与应用/权限列表获取，原文未明确记录超管 jsdm 来源」（知识卡与 staging 卡同步）。原文无产品/版本，affected_versions 已 --clear。
url: /docs/web/generic/auth/web-generic-auth-duplicate-controller-addroles-vertical-escalation/
draft: false
kb_aliases:
- addRoles 越权
- addRole/addRoles 权限校验不一致
- 遗留控制器越权
- 重复接口提权
- Swagger 双控制器
- Role Controller vs Zh Controller
---

## 一句话结论

同一业务功能在系统里存在两套控制器（如 `Role Controller` 与 `Zh Controller`）时，新接口 `addRole` 做了角色校验，而遗留/重复的 `addRoles` 只校验登录、不校验调用者是否有权分配目标角色；任意已登录的低权限用户调用 `addRoles?jsdm=<超管角色代码>` 即可给自己追加超级管理员角色，重新登录后获得超管权限。

## 原理

- **鉴权按方法/控制器配置，容易漏掉遗留接口**：Java Web 常用注解（`@RequiresRoles`、`@PreAuthorize`）或拦截器按路径给接口加授权检查。功能迭代时新控制器加了校验，旧控制器未删除，旧接口成了“只验登录、不验角色”的盲区。
- **同一功能存在多个近义路径**：案例中 Swagger 同时列出 `Role Controller`（`/…/addRoles` 给角色分配用户、`delete`、`delRoles`、`getList`）与 `Zh Controller`（`/…/addRole` 给用户分配角色、`/…/addRoles` 给用户分配角色）。单数 `addRole` 不能越权，复数 `addRoles` 可以越权——两者参数相近、语义相近，只有实际调用才能发现校验差异。
- **服务端信任角色代码**：接口接收 `jsdm`（角色代码）参数并直接写入用户的角色关联，没有校验“当前登录用户是否有权把该角色授予自己/他人”，也没有限制可分配角色集合；因此只要拿到超管角色代码（可从角色列表/`getRole`/字典/前端常量枚举），就能完成自我提权。
- **为什么 Swagger 让问题更严重**：接口文档把两个控制器、全部路径和参数一次性列出，攻击者无需字典即可发现重复端点并做对照测试；即使文档不公开，JS 或历史流量中也可能保留旧路径。
- **危害**：提权为超管后可访问统一管理中心、用户管理（姓名、学号、身份证号、电话、邮箱等全量 PII）、系统配置等高权限功能，并可能进一步 RCE。

## 触发条件

- 攻击者持有一个可登录的低权限账号（学生/普通用户），系统没有强制 MFA 或角色变更二次校验。
- 目标暴露接口文档（Swagger/knife4j）或前端 JS 中保留两套控制器的路径；或可通过字典/历史流量发现 `addRole`/`addRoles` 等近义接口。
- 至少一个“分配角色”类接口只校验登录（或使用宽松的路径匹配），未校验调用者角色与目标角色范围。
- 角色代码（`jsdm`/`roleId`/`roleIds`）可枚举或可从角色列表接口获取；超管角色代码通常可从 `getList`/`getRole` 返回中识别。

## 利用步骤

1. 枚举接口：从 Swagger/knife4j、前端 JS、Burp 历史流量中收集所有路径，按业务功能（用户、角色、权限、字典）聚类。
2. 找重复/近义端点：对同一功能筛选单复数、大小写、别名、版本前缀（`/addRole` 与 `/addRoles`、`/v1/` 与 `/v2/`、`.do` 与 `.json`）等变体。
3. 用低权限账号登录，抓取 Cookie/JWT；先对每个候选接口发一次“无害角色代码”请求，观察是 200/success 还是 401/403/“无权限”。
4. 对返回 success 的接口，换成目标超管角色代码再请求（参数名可能是 `jsdm`、`roleId`、`roleIds`、`role`）；同时留意是否需要 `xh`/用户 ID 等额外参数（案例中带 `xh=0`）。
5. 重新登录或刷新会话，检查是否出现“统一管理中心/用户管理/系统设置”等超管菜单；必要时用 `getRole`/角色列表接口确认自身角色已变更。
6. 验证后按需移除自身超管权限并退出，降低遗留痕迹；记录完整请求/响应作为报告证据。

## PoC

以下为按案例整理的请求形态（路径、参数名与角色代码以目标为准）：

```http
# 1) 低权限会话（Cookie 或 Authorization）
GET /<module>/addRole?jsdm=<role_code>&xh=0 HTTP/1.1
Host: target
Cookie: access_token=<low_priv_token>
# 可能返回 success:true 但权限未变（新接口有校验）

# 2) 调用同功能的复数/遗留接口
GET /<module>/addRoles?jsdm=<super_admin_role_code>&xh=0 HTTP/1.1
Host: target
Cookie: access_token=<low_priv_token>

HTTP/1.1 200 OK
{"success":true}
```

随后重新登录，超管菜单“统一管理中心 → 用户管理”出现，用户列表可看到姓名、学号、身份证号、电话、邮箱等字段。角色代码可通过 `zh/getRole`（账号-角色对应关系）与应用/权限列表接口获取或枚举，原文未明确记录超管 `jsdm` 的具体来源，测试时以目标返回为准。

## 变体与关联

- **角色参数篡改**：新增/登录接口直接接收 `roleId`/`roleIds` 并落库，属于同类“客户端控制角色”问题；见 [[web-generic-auth-roleid-roleids-parameter-tampering-admin]]。
- **只验登录不验角色**：拦截器对教师/管理接口仅校验会话，低权限会话重放即可垂直越权；见 [[web-generic-auth-missing-function-level-role-check]]。
- **Swagger 孤儿接口**：文档中页面不可见的接口鉴权覆盖更易遗漏，需逐个测试；见 [[pentest-recon-spring-swagger2-unauth-api-doc-exposure]]。
- **变体**：旧版 API 前缀（`/v1/`、`/old/`）、`do/action` 风格端点、大小写差异、重复控制器名（`Role` vs `Zh`）；批量分配角色接口（`roleIds` 数组）可能一次授予多个角色。
- **检测思路**：对角色分配类请求做审计，对比同一用户角色变更前后权限；关注非管理员账号调用 `addRole*`/`roleIds` 的日志。

## 检测与防御

- **统一授权**：在网关或方法级注解上做 deny-by-default 的功能级授权，角色分配接口必须校验“调用者是否有权分配该角色/角色集合”，而不是只校验登录。
- **清理遗留接口**：下线旧控制器与测试接口；API 清单纳入发布流程，定期做“文档/路由 vs 实际控制器”差异检查，发现单复数/别名重复端点。
- **角色代码白名单**：服务端限定可分配角色范围，禁止普通用户给自己或他人授予管理员/超管；角色变更需二次确认与审计。
- **审计与告警**：记录角色变更的操作者、目标用户、角色代码、来源 IP；对低权限账号调用角色管理接口、短时间自我提权后访问管理页的行为告警。
- **最小权限**：超管账号与日常账号分离；敏感操作（批量重置密码、导出 PII）要求更高认证强度（MFA/二次校验）。
