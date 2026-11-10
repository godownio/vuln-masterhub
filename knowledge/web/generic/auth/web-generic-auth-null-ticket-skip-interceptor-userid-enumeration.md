---
id: web-generic-auth-null-ticket-skip-interceptor-userid-enumeration
title: 登录拦截器凭证为空直接放行 + SecurityConfig 路由未覆盖：匿名遍历 userId 获取全站用户资料
type: scenario
domain: web
path: web/generic/auth
technique: null-ticket-skip-interceptor-userid-enumeration
aliases:
- 拦截器鉴权绕过
- ticket 为空放行
- 未授权 userId 遍历
- Spring Security 路由缺口
tags:
- web
- auth
- authz
- interceptor
- spring-boot
- idor
- enumeration
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: Echo2.3
verification:
  verified_by: verifier-T1-25
  verified_at: '2026-11-08T14:23:41+08:00'
  notes: 已对照原文与20张图核对；ticket=null匿名访问profile/102、discuss/101、comment/102均有数据回显(图11/13/15)；uploadMdPic半链(上传成功落盘但404、XSS仅本地file://弹窗)已作变体记录未独立成卡正确；setDelete被admin权限拦截作反向对照正确；affected_versions按原文标题『Echo2.3』设置；未验证点：仅本地环境复现
---

## 一句话结论

Spring Boot 登录拦截器的 `preHandle` 只在有凭证时才构建 SecurityContext，凭证为 null 时不做任何拒绝、直接 `return true`，而 SecurityConfig 又只对少数路由声明了权限要求，二者叠加使 `/user/profile/{userId}`、`/user/discuss/{userId}`、`/user/comment/{userId}` 等未列入权限清单的接口可匿名访问，遍历 userId 即可拉取全站用户资料、帖子和评论。

## 原理

该系统把"认证"放在 HandlerInterceptor 中：`preHandle` 从 Cookie 读 `ticket`，仅在 `ticket != null` 且查到有效 LoginTicket 时才 `hostHolder.setUser()` 并写入 SecurityContextHolder；ticket 缺失时代码既不 redirect 也不 return false，请求继续进入 Controller，此时 hostHolder 为 null。授权则依赖 Spring Security 的 `configure` 中 `.antMatchers(...).hasAnyAuthority(...)` 显式列举的受保护路由——只列举了 `/discuss/delete`、`/data/**` 等少数路径。凡是 Controller 方法不主动判空 hostHolder、又不在 SecurityConfig 权限清单里的接口，匿名请求就能以"无用户"状态正常执行业务逻辑：以 URL 路径变量 userId 查询任意用户的资料/帖子/评论（水平越权+信息枚举），同理 `/discuss/uploadMdPic` 也处于清单外，匿名即可上传任意后缀文件。

## 触发条件

- 认证逻辑在拦截器中实现且凭证缺失分支直接放行（不 return false / 不重定向）。
- SecurityConfig 只对显式列举的路由做权限校验，存在未覆盖的业务路由。
- 目标接口以路径变量/参数 userId 定位数据且无属主校验。

## 利用步骤

1. 审计拦截器 `preHandle`，确认 ticket 为 null 时直接 `return true`。
2. 审计 SecurityConfig `configure` 的 antMatchers 清单，找出未覆盖的 Controller 路由。
3. 携带 `Cookie: ticket=null`（或不带凭证）直接 GET `/user/profile/102`，返回该用户个人主页（注册时间、关注/赞数）。
4. 同法 GET `/user/discuss/101`、`/user/comment/102`，获取任意用户的全部帖子与评论/回复。
5. 对 userId 线性遍历即可批量收集全站用户数据。

## PoC

```http
GET /user/profile/102 HTTP/1.1
Host: localhost:9090
Cookie: ticket=null
```

响应正常渲染 admin 用户个人页；`/user/discuss/101`、`/user/comment/102` 同样匿名返回他人帖子和回复。

## 变体与关联

- 同链变体：`POST /discuss/uploadMdPic`（`editormd-image-file` 字段）无文件内容/后缀校验，配合本绕过实现匿名任意文件上传；实测文件落盘成功，但通过 `/editor-md-upload/xxx.html` 访问返回 404，远程触发未验证，不应按存储型 XSS 上报。
- 反向对照：`POST /discuss/delete` 在权限清单内，匿名/普通用户访问被 Spring Security 拦到 /denied，说明清单内路由防护有效，问题集中在清单缺口。
- 关联：拦截器/过滤器路径混淆类绕过（前缀 ..、分号、白名单 contains）是同目录常见变体，但机制不同（本卡是"凭证缺失分支放行"而非路径解析歧义）。

## 检测与防御

- 拦截器 `preHandle` 对未认证请求必须显式拦截（return false/401/重定向），不能只把认证当作"尽力而为"的上下文填充。
- 安全清单默认拒绝：SecurityConfig 用 `anyRequest().authenticated()` 兜底，再对公开路由逐个放行。
- 以 userId 定位数据的接口做登录态与属主/可见性校验；对匿名可达的业务路由建立检测（无 Cookie 访问 /user/* 告警）。
