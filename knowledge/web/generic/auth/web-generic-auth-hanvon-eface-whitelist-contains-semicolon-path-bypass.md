---
id: web-generic-auth-hanvon-eface-whitelist-contains-semicolon-path-bypass
title: 汉王e脸通 Spring 拦截器白名单 contains + `..;/` 路径归一化绕过：未登录访问后台接口
type: scenario
domain: web
path: web/generic/auth
technique: whitelist-contains-semicolon-dotdot-normalization-bypass
aliases:
- 汉王e脸通鉴权绕过
- UserHandlerInterceptor 白名单绕过
- 白名单 contains 子串绕过
- ..;/ 路径归一化
- Spring 拦截器路径绕过
tags:
- web
- java
- spring
- interceptor
- auth-bypass
- whitelist
- path-normalization
- semicolon
- hanvon
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:00:05+08:00'
  notes: 已对照原文与图03-08核对：web.xml仅编码Filter、application-mvc.xml注册UserHandlerInterceptor(/**)、isWhiteUri为uri.contains(whiteUrl)、WHITE_LIST含/manage/mobiMeetingApp、preHandle取getRequestURI、白名单命中直接return true；PoC /manage/mobiMeetingApp/..;/admin/info与文中SQLi/上传PoC前缀一致；原文未给/admin/info响应截图；dup-scan与upload/file-read等pair均related
---

## 一句话结论

汉王e脸通综合管理平台的 Spring 拦截器 `UserHandlerInterceptor.isWhiteUri()` 用 `uri.contains(whiteUrl)` 判断白名单，且检查的是未规范化的 `request.getRequestURI()`；攻击者请求 `/manage/mobiMeetingApp/..;/admin/info`，原始 URI 命中白名单片段 `/manage/mobiMeetingApp` 被放行，Tomcat 解析 `;` 路径参数并归一化 `..` 后实际路由到 `/admin/info`，从而未登录访问后台受保护接口。

## 原理

- 鉴权集中在 `application-mvc.xml` 注册的 `com.hanvon.iface.web.filter.UserHandlerInterceptor`，`<mvc:mapping path="/**">` 覆盖所有请求；`web.xml` 只注册了编码 Filter，没有其他鉴权 Filter。
- `preHandle` 先取 `uri = request.getRequestURI()`，再进入 `if (!this.isWhiteUri(uri))` 分支做 `__sessional_user__` 与 token 校验；若 `isWhiteUri` 返回 true，则直接跳过登录/令牌校验并 `return true`。
- `isWhiteUri` 的实现是遍历 `WHITE_LIST`，只要 `uri.contains(whiteUrl)` 就返回 true。`WHITE_LIST` 中包含 `/manage/mobiMeetingApp`、`/manage/intercom/`、`/manage/m/`、`/manage/mobiVisit/` 等业务前缀。
- 关键差异：`getRequestURI()` 返回容器规范化前的原始路径，而 Tomcat 在路由时会先处理矩阵参数 `;` 与 `.`、`..` 段。`/manage/mobiMeetingApp/..;/admin/info` 对拦截器而言包含白名单子串，对 Tomcat 而言 `..;` 是带路径参数的父目录段，归一化后变成 `/admin/info`。
- 因此这是“鉴权看原始字符串、路由看规范化路径”的经典路径解析差异；用 `contains` 而非精确匹配放大了可利用面，任意含白名单片段的前缀都可作为跳板。

## 触发条件

- 目标为汉王e脸通综合管理平台（文章基于反编译源码审计，未标注具体版本）。
- `UserHandlerInterceptor` 按 `/**` 拦截且 `isWhiteUri` 使用 `contains` 子串匹配。
- 容器/框架按矩阵参数与 `..` 归一化路由（Tomcat 默认行为）。
- 目标存在 `/admin/...` 等受保护接口；无需任何账号或 token。

## 利用步骤

1. 选一个白名单片段作为前缀，例如白名单中的 `/manage/mobiMeetingApp`。
2. 在其后拼接 `..;/` 与目标后台路径：`/manage/mobiMeetingApp/..;/admin/info`。
3. 发送请求；拦截器看到原始 URI 含白名单片段，跳过 `__sessional_user__` 校验。
4. Tomcat 归一化后把请求路由到 `/admin/info`，返回后台页面/数据。
5. 若需跳到根路径下的其它后台接口，可叠加多级 `..;/`，如 `/manage/mobiMeetingApp/..;/..;/authMultiplePeople/queryManyPeopleGroupList.do`（原文 SQL 注入 PoC 即使用该前缀）。

## PoC

```http
GET /manage/mobiMeetingApp/..;/admin/info HTTP/1.1
Host: <target>
```

原文源码截图确认 `isWhiteUri` 为 `uri.contains(whiteUrl)` 的循环判断，且 `WHITE_LIST` 含 `/manage/mobiMeetingApp`；SQL 注入与文件上传章节的 PoC 均复用 `/manage/mobiMeetingApp/..;/..;/...` 前缀，说明该前缀可稳定绕过鉴权到达后台路由。原文未单独给出 `/admin/info` 的响应截图。

## 变体与关联

- 白名单片段变体：把前缀换成 `/manage/intercom/`、`/manage/m/`、`/manage/mobiVisit/` 等任意 `WHITE_LIST` 条目。
- 编码/分隔符变体：`..;/`、`..%3b/`、`;/../`、双写 `..;/..;/`，取决于容器对矩阵参数与编码的解析。
- 关联：绕过鉴权后可访问本文章中的 MyBatis 排序注入、任意文件上传、任意文件读取与 fastjson 反序列化接口。
- 同类：华夏ERP `contains` 白名单 + `/doc.html/..`、jshERP 原始 URI 前缀 + 分号路径参数归一化。

## 检测与防御

- 修复：白名单改用规范化后的路径做精确匹配或前缀边界匹配；在鉴权前用 `path.normalize()` / 容器规范化 API 归一化，并拒绝含 `;`、`..`、编码分隔符的异常路径。
- 检测：访问日志中出现 `..;/`、`..%3b`、`;/../`、含白名单前缀但随后接后台路径的请求；同一 IP 未登录却访问 `/admin/*` 或后台 `.do` 接口。
- 加固：使用 Spring Security 等成熟框架做路径匹配；不要用 `contains` 判断 URI；对矩阵参数与编码路径做统一规范化后再鉴权。
