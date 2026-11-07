---
id: web-java-component-tongweb-default-console-credentials
title: 东方通 TongWeb 控制台 twusers.properties 初始口令未改导致后台登录
type: scenario
domain: web
path: web/java/component
technique: tongweb-default-console-credentials
tags:
- java
- tongweb
- middleware
- default-credentials
- weak-password
- console
- auth
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V56
  verified_at: '2026-11-05T09:00:48+08:00'
  notes: 已对照原文核对：TongWeb console/heimdall 共用配置、AuthFilter 调 UserManager.checkUserPassword(defaultRealm,...)、twusers.properties 内置 cli/thanos/security/auditor 账号与初始口令，均与正文及图片 01-09 一致；原文未给版本区间、未展示登录成功截图，卡片不写 affected_versions、confidence 标 medium 且 PoC 说明无 HTTP 验证，处理正确。
url: /docs/web/java/component/web-java-component-tongweb-default-console-credentials/
draft: false
kb_aliases:
- TongWeb 默认口令
- 东方通中间件默认密码
- twusers.properties 初始口令
- cli cli123.com
- thanos thanos123.com
- security security123.com
- auditor auditor123.com
---

## 一句话结论

TongWeb 控制台的 `AuthFilter` 用 `UserManager.checkUserPassword("defaultRealm", ...)` 校验 `twusers.properties` 中的账号口令，而该文件自带 `cli/cli123.com`、`thanos/thanos123.com`（首次登录需改）以及 `security/security123.com`、`auditor/auditor123.com`（需系统管理员修改）等初始口令；若目标未修改这些口令，攻击者可直接登录控制台，无需绕过 `AuthFilter`。

## 原理

- `AuthFilter` 作用于 `/rest/api/*`：从请求参数 `username`/`password` 或 `Authorization: Basic` 头取凭据，调用 `UserManager.checkUserPassword("defaultRealm", user, pass)`；校验通过后再走过期口令检查（`PwdManager.isPwdExpired`）。
- `UserManager.initDefault("twusers.properties", "defaultRealm")` 说明账号库来自 `twusers.properties`。截图中该文件以加盐哈希保存口令，但产品随附的初始口令为固定值：
  - `cli / cli123.com`、`thanos / thanos123.com`：初始口令，首次登录要求修改；
  - `security / security123.com`、`auditor / auditor123.com`：需要系统管理员修改。
- 因此这不是代码绕过，而是「默认凭据 + 未改密」：只要管理员没有完成首次改密/修改初始账号，凭据就直接有效。原文指出，当 cli/thanos 的密码被改后，`AuthFilter` 就无法用默认口令绕过；反之未改密时直接登录即可，不需要再研究 `AuthFilter` 绕过。
- 控制台、heimdall 使用相同配置，console 下的能力在 heimdall 中同样存在；`sysweb` 的 `/rjcs` 需要 admin 权限，其余路径为白名单，但只注册了一个 servlet，实际攻击面有限。

## 触发条件

- 目标暴露 TongWeb 控制台/管理端口（console 或 heimdall 上下文）且可访问登录接口。
- `twusers.properties` 中 `cli`、`thanos`、`security`、`auditor` 等账号仍使用初始口令，或管理员仅修改了部分账号。
- 目标未对管理控制台做来源 IP 限制、MFA 或登录失败锁定。

## 利用步骤

1. 识别目标为东方通 TongWeb 中间件，找到 console/heimdall 管理入口（常见为 9060 等管理端口，按部署配置确认）。
2. 使用初始账号逐个尝试登录：`cli/cli123.com`、`thanos/thanos123.com`、`security/security123.com`、`auditor/auditor123.com`。
3. `cli`/`thanos` 若返回强制改密页面，说明仍是初始口令但需先改密；若 `security`/`auditor` 未改密则可直接进入管理界面。
4. 登录后按角色使用控制台功能（部署应用、数据源、JNDI、JMX 等），并可结合其他后台漏洞扩大影响。
5. 若默认口令均失败，再回到 `AuthFilter`/白名单路由方向继续审计，不要假设默认口令可用。

## PoC

无 HTTP PoC：原文未给出登录请求或登录成功截图，仅在 `twusers.properties` 中展示账号哈希并列出上述初始口令；可用性取决于目标是否改密。

## 变体与关联

- 变体：管理员把 `security`/`auditor` 改成弱口令时，可用字典继续爆破；`twusers.properties` 泄露后也可离线分析哈希强度。
- 变体：console 与 heimdall 共用账号体系，从一个上下文拿到的凭据可尝试另一个上下文。
- 关联：TongWeb 其他后台/端口漏洞（如 EJB 监听端口）；通用默认口令与后台暴露卡。

## 检测与防御

- 检测：登录日志中出现 `cli`、`thanos`、`security`、`auditor` 等内置账号；同一来源尝试多个内置账号；管理控制台对公网暴露。
- 防御：部署后立即修改 `twusers.properties` 中所有初始口令，删除不需要的 `cli`/`thanos` 测试账号；对 `security`/`auditor` 强制改密。
- 防御：控制台限制来源 IP、启用 MFA、配置登录失败锁定与告警；不要将管理端口暴露到互联网。
- 防御：定期审计账号列表与口令策略，禁止使用产品文档中的示例口令。
