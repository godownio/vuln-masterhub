---
id: web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass
title: 泛微 e9 鉴权与参数过滤绕过：路径含 login 即判已登录，xssList 正则点号通配跳过 HTMLFilter
type: scenario
domain: web
path: web/generic/auth
technique: weaver-e9-islogin-xsslist-regex-bypass
aliases:
- 泛微 e9 登录绕过
- 泛微 isLogin 绕过
- LoginSSOxjsp 绕过
- XssRequestForWeblogic 绕过
- xssList 正则绕过
- 泛微 e9 参数过滤绕过
tags:
- auth-bypass
- java
- weaver
- ecology
- oa
- filter-bypass
- regex
- path-matching
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:29:18+08:00'
  notes: 已对照原文与本地61张截图核对：isLogin 的 path.indexOf("login") 放行、XssRequestWeblogic#getParameter→SecurityCore#isXssFilter 正则匹配（xssList 四项截图）、HTMLFilter 全角化、.jsp 静态判定与 SecurityRuleFileAlaPoc 的 isValid 均与卡片一致；affected_versions 原为分析环境版本，已按规则清除。未实际复现。
---

## 一句话结论

泛微 e9 的 `SecurityCore#isLogin` 只要请求路径（小写并 URL 解码后）包含子串 `login` 就返回已登录，而 `SecurityCore#isXssFilter` 用正则匹配 `xssList`，列表中的 `/login/LoginSSO.jsp` 里的 `.` 在正则中可匹配任意字符；因此在受保护 servlet 路径前加 `/login/LoginSSOxjsp`，同时绕过登录重定向和 `XssRequestWeblogic` 对所有 `getParameter` 值的全角化过滤。

## 原理

1. **登录判定**：`SecurityMain#process` 先调用 `sc.isLogin(req)`；当 `enableFirewall()` 为真、`isLogin` 为假且不是静态文件时，返回 `isLogin` 错误页并重定向。`SecurityCore#isLogin` 对 `getRequestURI()` 做 `toLowerCase()` 和 URL 解码，多个分支直接 `return true`，其中一条是 `path.indexOf("login") != -1`。所以只要路径里出现 `login` 字符串（不必是登录接口），就被当作已登录。
2. **参数过滤**：`XssRequestForWeblogic#doFilter` 把请求包装成 `XssRequestWeblogic`，其 `getParameter` 先调用 `sc.isXssFilter(path, name, value)`，返回真才进入 `HTMLFilter.filter()`。
3. **xssList 正则匹配**：`SecurityCore#isXssFilter` 遍历 `xssList`，用 `StringUtil.matches(path, xss)` 做**正则**匹配；命中后把 `xssPathMap` 中该 path 置为 `false` 并返回默认的 `false`，于是 `getParameter` 跳过 `HTMLFilter`。`xssList` 含 `/login/LoginSSO.jsp`，其中 `.` 是正则通配符，`/login/LoginSSOxjsp` 也能命中。
4. **过滤的后果**：`HTMLFilter` 命中 `union select`、`sleep`、`benchmark`、`xp_cmdshell` 等规则时，用 `toSBC()` 把字符转成全角（例如 `ｕｎｉｏｎ`），SQL 关键字失去语义。绕过 `isXssFilter` 后参数原样进入业务层，`/weaver/weaver.email.FileDownloadLocation` 的 `mailId` 才能维持可用的 `union select`。
5. **为什么不直接写 `.jsp`**：`.jsp` 结尾的 `/weaver/*` 路径会先被 `SecurityMain#process` 的静态文件判定拦截（路径以 `/api/` 开头或含 `messageservlet`、`/weaver/` 且以静态后缀结尾时进入 `errorRedirect`）；`/login/LoginSSO.jsp/111` 则被 `SecurityRuleFileAlaPoc#validate` 拦截，其 `isValid` 要求 `.jsp` 出现在最后一个 `/` 之后，否则判定为攻击。`LoginSSOxjsp` 不含 `.jsp`，两类规则都不命中。

## 触发条件

- 目标为泛微 e-cology 9（原文环境 9.00.210804 v10.42），`SecurityMain` 过滤器启用且 `enableFirewall()` 返回真。
- 目标 servlet 位于 `/weaver/*` 路由下，且其业务参数通过 `getParameter` 获取、后续直接拼接 SQL 或命令。
- `WEB-INF/weaver_security_rules.xml` 中的 `xssList` 包含带 `.` 的路径（默认含 `/login/LoginSSO.jsp`）。
- 请求路径可在 servlet 路径前插入任意 `/login/<字符串>` 段，且不破坏容器到 servlet 的映射。

## 利用步骤

1. 找到目标接口的 `/weaver/*` 路径，例如 `/weaver/weaver.email.FileDownloadLocation`。
2. 先直接请求，确认返回 302 到 `/login/Login.jsp`，说明 `isLogin` 分支生效。
3. 在 servlet 路径后追加 `/login/LoginSSOxjsp`（利用 `.` 通配 `x`），再请求；`isLogin` 命中 `indexOf("login")`，`isXssFilter` 命中 `LoginSSO.jsp` 正则，两个分支同时放行。
4. 在参数中放入原本会被 `HTMLFilter` 全角化的 `union select` 等关键字，观察响应是否仍按原 SQL 语义执行。
5. 不要使用 `.jsp` 或 `.jsp/` 形式：前者被静态文件判定拦截，后者被 `SecurityRuleFileAlaPoc` 拦截。

## PoC

未加绕过时（预期 302 到登录页）：

```http
GET /weaver/weaver.email.FileDownloadLocation?ddcode=7ea7ef3c41d67297&downfiletype=eml&download=1&mailId=1 HTTP/1.1
Host: target:8060
```

加绕过路径（预期进入 doGet，参数未被全角化）：

```http
GET /weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation?ddcode=7ea7ef3c41d67297&downfiletype=eml&download=1&mailId=1 HTTP/1.1
Host: target:8060
```

判断依据：前者响应 `Location: /login/Login.jsp`；后者不再重定向，且 `mailId` 中的 `union select` 在调试断点里保持原样（未变成全角字符）。`LoginSSOxjsp` 中的 `x` 可替换为任意单字符，只要整体不出现 `.jsp`。

## 变体与关联

- 其他 `xssList` 条目同样可用正则通配：`/login/LoginSSO2.jsp`、`OfficeServer.jsp`、`/docs/docs/UploadDoc.jsp` 中的 `.` 都可匹配任意字符。
- 登录放行只依赖路径包含 `login`，因此任何 `/weaver/*` 接口都可以尝试插入 `/login/<任意串>`；但插入后能否到达目标 servlet 取决于容器路由。
- 原文还提到 `isLogin` 可用静态后缀（如 `.mp4`）放行，但 `SecurityMain` 对 `/weaver/` 路径另有静态文件拦截，实测 `.mp4` 请求仍 302，不作为可靠变体。
- 关联：[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（同属“鉴权用字符串匹配路径”的根因，但本例是 `indexOf` 包含匹配 + 正则通配，不依赖 `..` 规范化）。
- 关联：[[web-generic-sqli-weaver-e9-filedownloadlocation-union-file-read]]（本绕过支撑的第一个完整利用链）。

## 检测与防御

- **日志检测**：同一 `/weaver/*` 接口出现 `/login/` 中间段、且路径不以 `.jsp` 结尾的请求；`mailId`、`keyword` 等参数含 `union`、`select`、`sleep` 等关键字；未携带有效 `ecology_JSessionid` 却返回 200 业务数据。
- **修复**：`isLogin` 不要用 `indexOf("login")` 判断，改为精确匹配登录接口白名单；`isXssFilter` 不要用未转义的用户可控路径做正则匹配，`.` 应转义为 `\.`，或改用前缀/精确路径匹配。
- **加固**：`HTMLFilter` 只做 XSS 过滤不能替代 SQL 参数化；业务层对 `mailId` 等参数强制类型转换并使用预编译；对 `/login/` 出现在业务路由中的请求直接拒绝。
