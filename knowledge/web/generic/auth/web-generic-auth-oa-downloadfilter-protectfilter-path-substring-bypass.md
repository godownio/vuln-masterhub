---
id: web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass
title: OA DownloadFilter/ProtectFilter 路径子串白名单绕过（;common.js 与 exclude 接口）
type: scenario
domain: web
path: web/generic/auth
technique: oa-path-substring-filter-bypass
aliases:
- OA 鉴权绕过
- DownloadFilter 绕过
- ProtectFilter 绕过
- common.js 鉴权绕过
- mywork.jsp 过滤器绕过
- 路径分号参数绕过
tags:
- java
- servlet-filter
- auth-bypass
- waf-bypass
- path-traversal
- oa
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:02:11+08:00'
  notes: 已对照原文与本地截图核对：DownloadFilter getRequestURL+indexOf白名单、/user_edit.jsp;common.js 返回200（页面权限非法）；ProtectFilter AllUnProtectUnit子串匹配、/test/../mywork.jsp/../store_menu_ajax.jsp 绕过SQLInject拦截，均与截图一致；原文未给产品版本，未设置versions；PoC未复现
---

## 一句话结论

某 OA 的全局 `DownloadFilter` 用 `path.indexOf(...) != -1` 判断登录白名单，`ProtectFilter` 又用 `string.indexOf(rule) != -1` 判断“不防护接口”；在任意受保护 URL 后追加白名单子串（如 `;common.js`、`/test`、`desktop`、`mywork.jsp`）即可让过滤器提前放行，再由容器把带 `..`/`;` 的路径归一化到真正的敏感接口，实现鉴权与 SQLi/XSS 过滤双重绕过。

## 原理

- **DownloadFilter**：注册在 `/*`，`doFilter` 中先取 `request.getRequestURL()`：
  - 若 URL 含 `bak`/`CacheTemp`，要求 `privilege.isUserPrivValid(req,"admin")`，否则 302；
  - 否则判断 `!privilege.isUserLogin(req1)` 与一串白名单：`common.js`、`module_field_ajax.jsp`、`/setup`、`/index.jsp`、`/login_oa`、`/activex`、`/public`、`/js/`、`/inc/`、`/skin`、`/other`、`chatservice`、`images/`、`nest_`、`/flow/`、`module_sel.jsp`、`basic_select_sel.jsp`、`flow_sequence_sel.jsp`、`module_field_sel.jsp`、`/wap`、`/test`、`desktop`、`error.jsp`。这些判断使用 `indexOf` 子串匹配，且白名单 token 出现在 URL 任意位置都算命中。
  - 由于判断的是完整请求 URL/路径字符串，攻击者可以在受保护路径后追加 `;common.js`（矩阵参数）或 `/test` 等 token，使 `indexOf` 命中，从而不进入重定向分支，直接 `chain.doFilter`。
- **为什么 `;common.js` 有效**：Servlet 容器把 `;` 后的内容当作路径参数（matrix parameter），路由仍映射到前面的 `user_edit.jsp`；但过滤器看到的是原始 URI，包含 `common.js` 子串。原文实测 `/user_edit.jsp;common.js` 返回 200（页面自身提示“权限非法”），证明过滤器已被绕过。
- **ProtectFilter**：`/*` 全局注册，若 URL 不含 `error.jsp` 就调用 `SecurityUtil.filter`。该函数先遍历 `config_protect.xml` 的 `AllUnProtectUnit`（`exclude="true"`），只要请求 URL 字符串包含任一 rule 就 `return`，完全跳过后续参数检查；否则才对参数做 XSS/SQLi 检测。
- **ProtectFilter 绕过**：`config_protect.xml` 把 `mywork.jsp`、`script_run.jsp`、`linkman_list.jsp` 等列为 `exclude="true"`。构造 `.../test/../mywork.jsp/../存在注入的文件?sql=...`：URL 包含 `mywork.jsp` → 过滤器放行；容器归一化 `/test/../` 与 `/mywork.jsp/../` 后实际访问目标文件，参数中的 `update`/`select` 等关键字不再被拦截。
- **组合效果**：DownloadFilter 负责登录态，ProtectFilter 负责 SQLi/XSS；两者都基于“路径子串”而非规范化后的精确路径，因此可以分别/同时绕过，直接访问未授权 JSP、Struts2 action 或带恶意参数的接口。

## 触发条件

- 目标使用该 OA 代码库，`web.xml` 将 `downloadFilter`/`protectFilter` 映射到 `/*`。
- 攻击者能访问任意受保护 URL；无需登录（DownloadFilter 的绕过正是针对未登录场景）。
- 容器支持 `;` 矩阵参数与 `..` 路径归一化（Tomcat 常见）。
- 目标未在过滤器前做 URL 规范化，或 WAF 未拦截 `;`/`..`/白名单 token。

## 利用步骤

1. 选一个受保护资源（如 `admin/user_edit.jsp`、业务 action 或带参数的 JSP）。
2. DownloadFilter 绕过：在 URL 后追加 `;common.js`（或 `/test`、`desktop`），例如 `/oa/admin/user_edit.jsp;common.js`；观察是否不再 302 到登录页。
3. ProtectFilter 绕过：在目标路径中插入一个 `exclude="true"` 的文件名片段，如 `/oa/test/../mywork.jsp/../目标.jsp`；或直接在 URL 中加 `;mywork.jsp`。
4. 组合：`/oa/admin/目标.jsp;common.js?sql=...` 同时绕过两个过滤器；若 ProtectFilter 仍拦参数，再加入 `mywork.jsp` 路径片段。
5. 访问目标页面/接口，确认返回业务内容或执行注入；注意页面自身可能还有 `privilege.isUserPrivValid` 检查，需要继续寻找无二次校验的 JSP/action。

## PoC

DownloadFilter 绕过（原文实测）：

```http
GET /oa/admin/user_edit.jsp;common.js HTTP/1.1
Host: target:8088
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

响应为 200，页面内容为 JSP 自身的“权限非法”，而非 302 登录跳转。

ProtectFilter 绕过（原文实测）：

```http
GET /oa/test/../mywork.jsp/../store_menu_ajax.jsp;menu_code=manuallyUpdate HTTP/1.1
Host: target:8088
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

组合（结构示意）：

```text
/oa/test/../mywork.jsp/../目标.jsp;common.js?orderBy=updatexml(1,concat(0x7e,(select user()),0x7e),1)&sort=asc
```

## 变体与关联

- **其他白名单 token**：`/test`、`desktop`、`/public`、`/js/`、`images/`、`error.jsp` 等都可作为子串注入点；不同版本白名单可能不同。
- **矩阵参数分隔符**：Tomcat 用 `;`；若容器不支持，可尝试 `%3b`、路径中插入 `/test/` 等。
- **ProtectFilter 的 `error.jsp` 例外**：URL 含 `error.jsp` 时整个过滤器不执行，是更短的无害绕过。
- **后续利用**：绕过 DownloadFilter 后可访问未授权 JSP/Struts2 action；绕过 ProtectFilter 后可注入 SQLi/XSS 关键字。两条绕过可独立使用。
- 关联卡片：[[web-generic-sqli-oa-jsp-orderby-sort-updatexml]]、[[web-generic-auth-interceptor-startswith-login-path-traversal]]（如已存在）。

## 检测与防御

- **代码**：过滤器应使用规范化后的 `getServletPath()`/`getRequestURI()` 精确匹配，不应对完整 URL 做 `indexOf` 子串判断；先 `URI.normalize()`/拒绝 `..` 与 `;`，再做鉴权；白名单用 `equals`/前缀边界匹配。
- **配置**：`config_protect.xml` 的 `exclude` 应只放行确实无参数的静态资源，不要放行业务 JSP；ProtectFilter 应对所有动态接口生效。
- **检测**：URL 含 `;common.js`、`;` 后接白名单文件名、`/test/../`、`mywork.jsp/../`；同一 IP 对受保护 JSP 返回 200 而非 302；参数中出现 SQL/ XSS 关键字且 URL 含 exclude 文件名。
- **应急**：审计访问日志中带 `;`/`..` 的请求与对应响应码；修复过滤器并回归；排查是否已利用绕过访问敏感 JSP/执行注入。
