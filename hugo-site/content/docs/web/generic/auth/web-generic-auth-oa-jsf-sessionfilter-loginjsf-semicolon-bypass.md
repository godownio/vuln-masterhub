---
id: web-generic-auth-oa-jsf-sessionfilter-loginjsf-semicolon-bypass
title: JSF OA SessionFilter 用 getRequestURI 模糊匹配 login.jsf，;login.jsf 矩阵参数绕过登录
type: scenario
domain: web
path: web/generic/auth
technique: sessionfilter-requesturi-loginjsf-substring-bypass
tags:
- java
- servlet-filter
- auth-bypass
- path-parsing
- semicolon
- jsf
- oa
- access-control
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T09:02:29+08:00'
  notes: 已对照原文与54张图核对：图15 SessionFilter 未登录时 getRequestURI().indexOf("login.jsf")==-1 才 302 sessionInvalid.jsf，否则 chain.doFilter；图13 filter 映射 /pages/* 与 /pageconfig/pages/*；图17-19 UrlFCFilter 用 getServletPath()、未命中 URLFCS 时 isPermitted 返回 true；图25-26 menuurl 为空。Tomcat 矩阵参数剥离与 getRequestURI 原始串差异的绕过原理成立。卡片 PoC 用 /pages/xxx.jsf;login.jsf，符合实际 filter 映射（原文示例 /admin/info.jsf;login.jsf 为泛例）。未验证点：PoC 未在真实目标执行；原文无版本/CVE；frontmatter无sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-oa-jsf-sessionfilter-loginjsf-semicolon-bypass/
draft: false
kb_aliases:
- SessionFilter 绕过
- login.jsf 鉴权绕过
- ;login.jsf 绕过
- getRequestURI 子串匹配绕过
- JSF OA 未授权访问
- 矩阵参数鉴权绕过
---

## 一句话结论

旧 JSF OA 的 `SessionFilter` 在未登录时只判断 `request.getRequestURI().indexOf("login.jsf") == -1`，只要原始 URI 里出现 `login.jsf` 子串就 `chain.doFilter` 放行；在受保护的 `.jsf` 路由后追加 `;login.jsf`（Tomcat 矩阵参数）即可让过滤器看到登录页而容器仍路由到业务 JSP，实现未登录访问。

## 原理

- **过滤器逻辑**：
  ```java
  boolean b1 = request.getSession().getAttribute("LoginInfo.ROOT") == null;
  if (b1) {
      if (request.getRequestURI().indexOf("login.jsf") == -1) {
          response.sendRedirect(request.getContextPath() + "/sessionInvalid.jsf");
      } else {
          chain.doFilter(request, response);
      }
  } else {
      chain.doFilter(request, response);
  }
  ```
  未登录时，唯一放行条件是“请求 URI 中包含 `login.jsf` 子串”。它本意是放行登录页本身，但使用的是**子串包含**而不是路径相等或前缀边界。
- **`getRequestURI()` 的语义**：Servlet API 返回客户端请求行中的原始 request-target，包含 context path 与 servlet path，**不删除 `;` 路径参数、不做 URL 解码、不解析 `..`**。因此 URI 中出现 `;login.jsf` 时，过滤器看到的是带 `login.jsf` 的字符串。
- **容器路由的语义**：Tomcat 在 servlet 映射前会把 `;` 之后到下一个 `/` 的内容当作矩阵参数（path parameter）剥离。`/pages/xxx.jsf;login.jsf` 对映射而言等同于 `/pages/xxx.jsf`，仍命中 `FacesServlet` 的 `*.jsf` 映射，再按 `javax.faces.DEFAULT_SUFFIX=.jsp` 渲染 `xxx.jsp`。
- **两者语义差异**：过滤器判断用原始 URI，路由使用剥离矩阵参数后的路径。攻击者构造“过滤器看到 login.jsf、路由落到受保护 JSP”的请求，即可同时满足放行与到达业务代码。
- **为什么该项目的另一个过滤器挡不住**：`UrlFCFilter` 使用 `getServletPath()` 取路径；该方法返回的是容器规范化后的 servlet path（已剥离 `;` 参数），`;login.jsf` 不会出现在其中，因此不能用同一手法绕过。它还会从 `config/sysauth_<project_ename>.xml` 加载 URL→functioncode 映射，未命中映射时 `isPermitted` 直接返回 `true`；映射表为空或 `menuurl` 为空时，实际鉴权压力全落在 `SessionFilter` 上。
- **适用范围**：`SessionFilter` 在 `web.xml` 中只映射到特定目录（本类项目为 `/pages/*` 与 `/pageconfig/pages/*`），因此绕过也只对这些目录下的 `.jsf`/JSP 生效；其他路由是否可达取决于 `UrlFCFilter` 与其他二次校验。

## 触发条件

- 目标为使用该 JSF 代码库的 OA，`SessionFilter` 已注册且作用于目标 `.jsf` 路由（`/pages/*`、`/pageconfig/pages/*`）。
- 未登录访问目标路由会 302 到 `/sessionInvalid.jsf`，说明命中 `getRequestURI().indexOf("login.jsf")` 分支。
- 容器支持 `;` 矩阵参数（Tomcat/JBoss 等常见），且 `FacesServlet` 仍能将去掉矩阵参数后的 `.jsf` 路径映射到 JSP。
- 目标没有在过滤器之前统一拒绝 `;` 或做路径规范化。

## 利用步骤

1. 找一个受 `SessionFilter` 保护的业务 `.jsf` 路由，例如 `/pages/xxx.jsf` 或 `/pageconfig/pages/xxx.jsf`。
2. 不带会话直接请求，确认返回 302 到 `/sessionInvalid.jsf`，作为基线。
3. 在原路径后追加矩阵参数 `;login.jsf`：`/pages/xxx.jsf;login.jsf`。
4. 观察响应是否不再 302，而是返回业务 JSP 内容；若返回登录页或 404，检查目标路径是否确实在 filter 的 `url-pattern` 内，以及 JSF 是否按 `DEFAULT_SUFFIX` 渲染。
5. 成功后在该未授权会话中继续访问业务接口，寻找后续的 SQL 注入、文件读取、上传等入口。

## PoC

基线（预期 302 到会话失效页）：

```http
GET /pages/info.jsf HTTP/1.1
Host: target:8080
Cookie: JSESSIONID=<anonymous>
```

绕过（预期过滤器放行并渲染 info.jsp）：

```http
GET /pages/info.jsf;login.jsf HTTP/1.1
Host: target:8080
Cookie: JSESSIONID=<anonymous>
```

说明：`login.jsf` 只要求作为子串出现在原始 URI 中；`;login.jsf` 是最小形态，也可按目标路由结构调整为 `;login.jsf;`、`;xlogin.jsf` 等。PoC 依据过滤器代码与容器矩阵参数语义构造，未在真实目标复现。

## 变体与关联

- **子串位置**：`;login.jsf` 可放在最后一段；若容器或框架对 `;` 处理不同，可尝试把 `login.jsf` 放进额外路径段（需确保路由仍能落到目标 `.jsf`）。
- **编码变体**：部分容器/代理会解码 `%3B`；若目标有 WAF，可测试编码后的分号与大小写变体，但 `getRequestURI()` 通常保留原始编码，需以实际容器行为为准。
- **过滤路径差异**：若 `SessionFilter` 映射到 `/*`，则该绕过覆盖全部 `.jsf` 路由；若只映射到 `/pages/*`，则只在对应目录生效。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（同为“鉴权路径表示与路由路径表示不一致”的根因）；[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]（OA 过滤器子串白名单绕过）；[[web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass]]（路径包含 `login` 即判已登录的另一种实现）。

## 检测与防御

- **代码修复**：登录页放行改为精确路径匹配（`equals`）或规范化后前缀边界匹配；不要对 `getRequestURI()` 做 `indexOf` 子串判断。鉴权应使用与路由一致的规范化路径，并在规范化前拒绝 `;`、`%3b`、`..` 等可疑字符。
- **过滤器加固**：统一在鉴权前做 `URI.normalize()`、剥离矩阵参数、URL 解码，再比较；`getRequestURI()` 与 `getServletPath()` 混用时要明确安全语义。
- **检测特征**：请求路径包含 `;login.jsf`、`;` 后接登录页关键字；未携带有效 `LoginInfo.ROOT` 会话却返回 200 业务页面；同一路由正常请求 302、矩阵参数变体 200；WAF 日志中出现 `.jsf;` 组合。
- **部署缓解**：反向代理层拒绝带 `;` 的 `.jsf`/`.jsp` 路径；限制 `/pages/*`、`/pageconfig/pages/*` 的公网直接访问；对 OA 做版本升级或虚拟补丁。
