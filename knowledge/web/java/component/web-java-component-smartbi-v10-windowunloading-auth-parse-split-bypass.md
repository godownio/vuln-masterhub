---
id: web-java-component-smartbi-v10-windowunloading-auth-parse-split-bypass
title: Smartbi V10 windowUnloading 参数分裂：鉴权检查与 RMIServlet 实际调用方法不一致的绕过
type: scenario
domain: web
path: web/java/component
technique: smartbi-v10-windowunloading-auth-parse-split
aliases:
- Smartbi 鉴权绕过
- windowUnloading 绕过
- CheckIsLoggedFilter
- RMIInfo 解析不一致
- ATTR_KEY_RMIINFO
- V10 未授权方法调用
tags:
- smartbi
- java
- auth-bypass
- filter
- parameter-smuggling
- rmi-servlet
- access-control
cve: []
severity: critical
confidence: medium
status: verified
affected_versions: Smartbi V10（原文：仅存在于 V10；V11 在 CheckIsLoggedFilter 中统一调用 parseRMIInfo 并设置 ATTR_KEY_RMIINFO 修复）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:08:59+08:00'
  notes: 已对照原文与61张图核对：V10 CheckIsLoggedFilter 从 windowUnloading 解析 className/methodName 做白名单鉴权但未写 ATTR_KEY_RMIINFO、RMIServlet parseRMIInfo 回退 getParameter 重新解析、V11 统一 parseRMIInfo 并 setAttribute 修复，均与卡片一致。未验证点：原文未给完整端到端请求，卡片 PoC 为按机制构造（已注明）；未本机复现，confidence=medium 合理。
---

## 一句话结论

Smartbi V10 的 `CheckIsLoggedFilter` 在处理 `/vision/RMIServlet` 时，会从查询串 `windowUnloading=&...` 中解析 `className`/`methodName` 并用它们做白名单鉴权，但没有把解析结果写入 `ATTR_KEY_RMIINFO`；随后 `RMIServlet` 的 `parseRMIInfo` 发现该 attribute 不存在，转而从请求体/参数重新解析真正要调用的方法。于是鉴权检查的是一组方法，实际执行的是另一组方法，攻击者可借此以未授权/低权限身份调用任意已注册 Service 方法。

## 原理

- **鉴权与执行使用两套解析**：V10 的 `CheckIsLoggedFilter#doFilter` 对 `isRmi` 请求有专门逻辑：若查询串以 `windowUnloading=&` 或 `windowUnloading&` 开头，就把其后的内容 URL 解码，解析出 `className`、`methodName`、`params`，设置到 request attribute，然后基于这组值做白名单鉴权（`needToCheck`/`needToCheckIsLoggedIn`）。
- **attribute 未落地**：该 filter 只设置了 `className`/`methodName`/`params` 等普通 attribute，并未设置 `ATTR_KEY_RMIINFO`。`RMIServlet` 的 `RMIUtil.parseRMIInfo` 首先调用 `getRMIInfoFromRequest` 查找 `ATTR_KEY_RMIINFO`；找不到时，回退到 `request.getParameter("className")`、`getParameter("methodName")`、`getParameter("params")`（以及 multipart/encode 等分支）重新构造 `RMIInfo`。
- **参数分裂**：攻击者在 `windowUnloading=&` 后放一组**白名单内**的 `className`/`methodName`（用于通过鉴权），在请求体/其它参数位置放**真正要执行**的危险 `className`/`methodName`/`params`。filter 校验前者，Servlet 执行后者，形成“检查一个、执行另一个”的经典参数解析不一致。
- **V11 的修复**：filter 不再自己实现一套解析，而是直接调用 `RMIUtil.parseRMIInfo`，该函数最终会 `request.setAttribute("ATTR_KEY_RMIINFO", info)`；进入 `RMIServlet` 时 `getRMIInfoFromRequest` 直接取到同一份 `RMIInfo`，鉴权与执行一致，绕过失效。
- **本质**：鉴权组件与业务组件各自解析同一请求，且没有共享解析结果；只要两者对参数来源/优先级的理解不同，就能构造出“鉴权看 A、执行用 B”的分裂。

## 触发条件

- Smartbi V10（原文明确该问题仅存在于 V10；V11 已改为统一解析并写入 `ATTR_KEY_RMIINFO`）。
- 目标暴露 `/smartbi/vision/RMIServlet`，且 `CheckIsLoggedFilter` 生效。
- 攻击者能控制查询串中的 `windowUnloading=` 内容，同时在请求体/其它参数位置提供不同的 `className`/`methodName`/`params`。
- 存在一组可通过白名单鉴权的 `className`/`methodName`（如公开的登录、版本查询等方法）。
- 实际要调用的危险方法已注册为 Service，且其自身没有额外的函数级权限校验。

## 利用步骤

1. 确认目标为 V10，且 `/smartbi/vision/RMIServlet` 受 `CheckIsLoggedFilter` 保护。
2. 先从公开方法中找一组能通过 `needToCheck` 白名单的 `className`/`methodName`（如 `UserService#checkVersion`、`UserService#login` 等公开方法）。
3. 构造请求：查询串 `?windowUnloading=&<URL 编码后的白名单 className/methodName/params>`，请求体再放一组真正要执行的危险 `className`/`methodName`/`params`。
4. 发送请求，filter 用查询串中的白名单方法通过鉴权；`RMIServlet` 因 `ATTR_KEY_RMIINFO` 缺失而从请求体解析并执行危险方法。
5. 将危险方法替换为可造成实际危害的 Service（如数据源测试、表达式执行等），验证未授权调用是否成功。
6. 若请求体解析受 Content-Type 影响，可尝试普通 form、multipart、`encode` 参数等不同载体，确保 filter 与 Servlet 读取到不同的值。

## PoC

原文章节给出了机制与关键代码，但未给出完整端到端 HTTP 请求；以下为按机制构造的请求形态：

```http
POST /smartbi/vision/RMIServlet?windowUnloading=&className%3DUserService%26methodName%3DcheckVersion%26params%3D%5B%5D HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

className=<危险Service>&methodName=<危险方法>&params=<危险参数>
```

要点：查询串中的 `windowUnloading=` 后是一组 URL 编码的“白名单方法”，用于 filter 鉴权；请求体中的 `className`/`methodName`/`params` 是实际执行的方法。两者解析来源不同，导致鉴权与执行不一致。

## 变体与关联

- 变体（参数位置）：白名单参数可放在 `windowUnloading=&` 后的查询串、`windowUnloading&` 形式；实际执行参数可放在 POST body、multipart、`encode` 或 GET 参数，取决于 filter 与 Servlet 的解析优先级。
- 变体（解析差异）：任何“filter 先解析一次、Servlet 再解析一次”的架构都可能出现同类问题；重点检查是否共享同一个 request attribute/对象。
- 关联：[[web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce]]（本卡绕过后可调用的危险方法之一）。
- 关联：[[web-java-component-smartbi-rmiservlet-stub-jsonpcallback-get-post-bypass]]（另一条 V10 RMIServlet 的绕过路径）。
- 关联：[[web-generic-auth-missing-function-level-role-check]]（功能级权限缺失的通用模式）。
- 边界：V11 已统一解析并设置 `ATTR_KEY_RMIINFO`，本卡不适用；若危险方法自身有函数级权限校验，绕过后仍可能被拦截。

## 检测与防御

- 修复：鉴权组件与业务组件共享同一份解析结果（如统一调用 `parseRMIInfo` 并写入 `ATTR_KEY_RMIINFO`），禁止各自重新解析请求。
- 解析一致性：明确参数的唯一来源与优先级；对同一请求只解析一次，后续组件只读 attribute，不直接读 `getParameter`。
- 鉴权：对 `RMIServlet` 的所有 Service 方法做函数级权限校验，不能只依赖 URL/方法名白名单；公开方法单独标注并审计。
- 检测：请求同时出现 `windowUnloading` 与请求体 `className`/`methodName`/`params`；查询串中的方法与请求体中的方法不一致；`windowUnloading=` 后带 URL 编码的 RMI 参数；同一会话调用未授权 Service。
- 运营：升级到 V11 或包含对应修复的补丁；审计其它 filter/servlet 是否存在“两套解析”的同类架构缺陷。
