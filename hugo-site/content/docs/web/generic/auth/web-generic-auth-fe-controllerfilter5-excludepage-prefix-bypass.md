---
id: web-generic-auth-fe-controllerfilter5-excludepage-prefix-bypass
title: ControllerFilter5 excludePage 前缀通配白名单 + ../ 归一化差异绕过 Java 鉴权
type: scenario
domain: web
path: web/generic/auth
technique: exclusion-filter-prefix-path-normalization-bypass
tags:
- java
- servlet-filter
- webfilter
- auth-bypass
- path-parsing
- path-traversal
- whitelist
- code-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:54:37+08:00'
  notes: 已对照原文及49张图核对：图09 @WebFilter urlPatterns 含 *.jsp/*.do//servlet/* 等，doFilter 取 getRequestURI 后先 excludePage；图10 excludePage 对 url* 用 startsWith、*url 用 endsWith、*url* 用 contains；图11 excludeSet 含 /zhyq/djfw/gateway/*。卡内 ../ 归一化差异绕过为源码+容器行为构造，原文仅提出思路、无响应截图；卡已注明必须匹配 urlPatterns 后缀、context path 与 JSP 二次 session 校验等条件。PoC 未在本机执行。
url: /docs/web/generic/auth/web-generic-auth-fe-controllerfilter5-excludepage-prefix-bypass/
draft: false
kb_aliases:
- ControllerFilter5 绕过
- excludePage 鉴权绕过
- 网关前缀白名单绕过
- /zhyq/djfw/gateway/ 绕过
- Java 注解过滤器绕过
- 前缀通配路径穿越
---

## 一句话结论

某企业 Java 系统的 `ControllerFilter5` 用注解注册为 `@WebFilter`，其 `excludePage(uri)` 对白名单 `/zhyq/djfw/gateway/*` 采用 `uri.startsWith(前缀)` 判断，而 `uri` 取自未规范化的 `getRequestURI()`；构造 `/zhyq/djfw/gateway/../../../<受保护页面>.jsp` 时过滤器看到网关前缀而放行，容器路由到归一化后的受保护页面，从而绕过登录校验。

## 原理

- **过滤器注册方式**：`@WebFilter(filterName="controllerFilter", urlPatterns={"*.jsp","*.jspx","*.do","*.fe","*.xml","/servlet/*","*.xf","/easemobHisMessageServlet"})`，并非全部写在 `web.xml` 中；审计时必须同时枚举注解与 web.xml，否则会漏掉鉴权点。
- **白名单匹配逻辑**（`excludePage`）：
  ```java
  for (String url : excludeSet) {
      if ((url = url.trim()).startsWith("*") && url.endsWith("*")) {   // *url*
          url = url.substring(1, url.length() - 1);
          if (!uri.toLowerCase().contains(url.toLowerCase())) continue;
          return Boolean.TRUE;
      }
      if (url.startsWith("*")) {                                        // *url
          url = url.substring(1);
          if (!uri.toLowerCase().endsWith(url.toLowerCase())) continue;
          return Boolean.TRUE;
      }
      if (url.endsWith("*")) {                                         // url*
          url = url.substring(0, url.length() - 1);
          if (!uri.toLowerCase().startsWith(url.toLowerCase())) continue;
          return Boolean.TRUE;
      }
      if (!url.equalsIgnoreCase(uri)) continue;                         // exact
      return Boolean.TRUE;
  }
  ```
  白名单集合里有 `/zhyq/djfw/gateway/*`，即“任何以 `/zhyq/djfw/gateway/` 开头的 URI 都放行”。
- **路径表示差异**：`doFilter` 用 `request.getRequestURI()` 取原始 URI，**不做 `..` 归一化**；容器在 servlet 映射/静态资源处理阶段会把 `/a/b/../../../admin/x.jsp` 归一化为 `/admin/x.jsp`。过滤器看到的是带前缀和 `..` 的原始串，业务代码看到的是归一化后的受保护页面。
- **为什么能绕过**：`excludePage` 命中白名单后直接 `chain.doFilter`，跳过后面的 `sqlInjection` 检测与 `userExpired` 登录判断。于是未登录请求也能到达受保护 JSP/servlet。
- **过滤器的 `web.xml` 分支**：同项目还有一个 `RestfulFilter` 拦截 `/rest/*`，对 `/rest/dev/` 走 `WebServiceAuth.validateDevInterfaceRule`（检查 queryString、`&token`、`timeStamp` 数字且在 5 分钟内）；它是另一条鉴权路径，本卡只讨论 `ControllerFilter5` 的路径白名单绕过。
- **补充条件**：`@WebFilter` 的 `urlPatterns` 不含 `/*`，所以构造的路径必须仍然匹配某个模式（以 `.jsp`/`.do`/`.xml` 结尾，或落在 `/servlet/*` 下）。文章示例写作 `/admin/info`，实际利用时应改为 `/admin/info.jsp`（或对应 `.do`/servlet 路径），否则请求根本不会经过该过滤器。另若应用部署在非根 context path，白名单前缀需相应带上 context path，否则匹配不上。

## 触发条件

- 目标使用该 FE 系统代码库，`ControllerFilter5` 已通过 `@WebFilter` 注册且覆盖目标路由（`*.jsp`、`*.do`、`/servlet/*` 等）。
- `excludeSet` 中存在以 `/` 开头、以 `*` 结尾的前缀白名单（如 `/zhyq/djfw/gateway/*`）。
- 容器会对请求路径中的 `..` 做归一化，且归一化后的目标路由仍落在过滤器覆盖范围内（这是能到达受保护页面的关键）。
- 目标页面/接口在过滤器之后没有额外的会话/权限校验（部分 JSP 自己还会检查 session，需要找无二次校验的入口）。

## 利用步骤

1. 确认目标路由确实经过 `ControllerFilter5`：请求一个正常受保护 `.jsp`，未登录应被 302 到 `/main/logout.jsp`。
2. 找一个前缀白名单，例如 `/zhyq/djfw/gateway/*`。
3. 构造 `前缀 + ../` 跳到目标页面，并保证路径仍以过滤器覆盖的后缀结尾：
   ```text
   /zhyq/djfw/gateway/../../../admin/info.jsp
   ```
4. 观察是否不再 302，而是返回目标 JSP 内容或业务数据。
5. 若目标 JSP 自身有 session 校验，继续寻找不做二次校验的接口；也可与 `/servlet/*` 下的 servlet 组合（前缀白名单路径 + `../` + `/servlet/xxx`）。
6. 记录响应差异作为证据；不要对生产系统做破坏性操作。

## PoC

基线（预期 302 到登出页）：

```http
GET /admin/info.jsp HTTP/1.1
Host: target
```

前缀白名单 + 归一化绕过：

```http
GET /zhyq/djfw/gateway/../../../admin/info.jsp HTTP/1.1
Host: target
```

说明：`ControllerFilter5` 用 `getRequestURI()` 看到的前缀是 `/zhyq/djfw/gateway/`，`excludePage` 返回 TRUE 后直接放行；Tomcat/Java EE 容器在映射阶段将 `..` 归一化为 `/admin/info.jsp`。`../` 的层数按白名单目录深度调整。PoC 依据过滤器源码与该类路径归一化行为构造，原文未给出响应截图，未在本会话执行。

## 变体与关联

- **后缀模式白名单**：`*url` 与 `url*` 两类通配都可用于“前缀/后缀 + 穿越/添加无害段”的绕过；`*url*` 的 contains 匹配更宽松。
- **过滤器覆盖范围**：目标必须以 `.jsp`、`.jspx`、`.do`、`.fe`、`.xml`、`.xf` 结尾，或在 `/servlet/*` 下；否则请求不经过该过滤器，绕过也就无从谈起（反过来也可能意味着某些路由被过滤器完全漏掉）。
- **上下文路径**：非根 context path 时，`getRequestURI()` 包含 context path，前缀白名单需要包含它；构造时不要漏掉。
- **二次校验**：JSP 里常见的 `session.getAttribute("_$government") == null → redirect` 会抵消过滤器绕过，需要继续找无二次校验的页面或 servlet。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（原始 URI 与路由路径不一致的通用根因）；[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]（OA 过滤器子串白名单绕过）；[[web-generic-auth-oa-jsf-sessionfilter-loginjsf-semicolon-bypass]]（矩阵参数绕过）。

## 检测与防御

- **代码修复**：鉴权过滤器不要对 `getRequestURI()` 原始串做 `startsWith`/`contains` 白名单；先 `URI.normalize()`、URL 解码、删除 `;` 参数，再与精确路径或规范化后的前缀比较；白名单用精确路径或目录边界匹配，不要用裸前缀。
- **过滤器覆盖**：确保所有后台 JSP/servlet 都在过滤器覆盖范围内；对未匹配任何 `urlPatterns` 的路径单独做拒绝或兜底鉴权。
- **检测特征**：请求路径包含 `..`、`;`、连续 `/`、编码的 `%2e%2e`，且路径以白名单前缀开头；同一资源正常请求 302、变体请求 200；`getRequestURI()` 与容器访问日志中的归一化路径不一致；未登录会话访问 `.jsp`/`.do` 返回业务内容。
- **加固**：反向代理层拒绝含 `..` 的路径；WAF 对白名单前缀 + 穿越组合告警；对后台路径做统一认证网关。
