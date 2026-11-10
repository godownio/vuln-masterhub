---
id: web-generic-auth-ajax-header-only-interceptor-bypass
title: 拦截器只在 AJAX 请求时校验登录：省略 X-Requested-With 头即绕过认证（flink-streaming-platform-web 添加用户）
type: scenario
domain: web
path: web/generic/auth
technique: ajax-header-only-interceptor-bypass
aliases:
- X-Requested-With 绕过登录
- 非 AJAX 请求跳过鉴权
- LoginInterceptor 绕过
- flink-streaming-platform-web 权限绕过
- isAjaxRequest 鉴权缺陷
tags:
- web
- auth-bypass
- interceptor
- spring
- header
- flink-streaming-platform-web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V453
  verified_at: '2026-11-10T02:15:49+08:00'
  notes: 已对照原文与 25 张图核对：LoginInterceptor.preHandle 把 checkLogin 包在 WebUtil.isAjaxRequest(request) 分支内、isAjaxRequest 仅比较 X-Requested-With 是否为 XMLHttpRequest，不带该头即跳过校验；/api/addUser 表单字段与 {code:200,success:true} 回显、test3 登录成功均与原文一致；绕过请求未在本机复跑；原文未给受影响版本（仅目录 tag v20230610），affected_versions 已清空。
---

## 一句话结论

flink-streaming-platform-web 的 `LoginInterceptor.preHandle` 把登录校验整个包在 `if (WebUtil.isAjaxRequest(request))` 分支里，而 `isAjaxRequest` 只判断请求头 `X-Requested-With` 是否等于 `XMLHttpRequest`；攻击者直接发送**不带该头**的普通 POST，就走到 `return true`，未登录即可调用受保护接口（如 `/api/addUser` 创建账号），再用新账号登录后台。

## 原理

- **鉴权被错误地绑定到请求类型**：`preHandle` 先处理根路径重定向，再从 Cookie 解析 `UserSession`；随后只有命中 `isAjaxRequest(request)` 时才检查 `userSession == null || !userService.checkLogin(userSession)`，不满足则返回未登录；非 AJAX 分支只打一条“未知请求”日志后 `return true` 放行。
- **请求头完全可控**：`isAjaxRequest` 的实现是 `"XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"))`。浏览器前端用 jQuery/Axios 时会自动带该头，但 curl、Burp、脚本请求可以随意省略或修改，服务端没有任何独立于该头的鉴权。
- **为什么成立**：“是否 AJAX”只是请求格式的区分，不是身份凭据；把认证放在这个分支里等价于“只有带特定头的请求才需要登录”。攻击者只需移除这个头，就走到了设计者认为“无需鉴权”的放行路径。
- **影响面**：拦截器对所有受保护路由生效，因此任何未在 Controller/Service 层二次校验的接口都变成匿名可达；本案利用添加用户接口创建 `test3` 账号并成功登录，进而可进入任务管理。

## 触发条件

- 目标使用 Spring MVC 拦截器做统一鉴权，且鉴权逻辑位于“是否为 AJAX/是否带某请求头”的分支内。
- 受保护接口的 Controller/Service 没有独立的会话或权限校验。
- 能直接发送 HTTP 请求（curl/Burp/脚本），自由控制 `X-Requested-With` 等请求头。

## 利用步骤

1. 正常访问登录页，确认站点与拦截器行为（未登录访问其他路径会被重定向/返回未登录）。
2. 直接向业务接口发送不带 `X-Requested-With` 的 POST。本案添加用户接口为 `/api/addUser`，表单字段 `name`、`fullname`、`pwd1`、`pwd2`。
3. 观察响应为 `{"code":"200","success":true,...}`，说明未登录请求已通过拦截器并完成用户创建。
4. 用新建账号登录后台；如站点同时接受 `Admin-Token`、`flink-streaming-platform-web-sessionid` 等 Base64 Cookie，登录后即可获得完整功能。
5. 以新账号继续利用后台任务提交等功能（本案可继续到 flink JAR 任务 RCE，见关联卡）。

## PoC

```http
POST /api/addUser HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Content-Length: 50

name=test3&fullname=test&pwd1=test321&pwd2=test321
```

注意：请求中故意不携带 `X-Requested-With: XMLHttpRequest`；其余头（User-Agent、Referer 等）可仿照正常页面。发送后若返回成功，再用 `test3/test321` 登录验证。

## 变体与关联

- [[web-generic-auth-null-ticket-skip-interceptor-userid-enumeration]]、[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]、[[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]：同属拦截器鉴权逻辑缺陷，但绕过点分别为空 ticket、路径前缀与白名单正则。
- [[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]、[[web-generic-auth-tmall-adminpermissionfilter-contains-login-account-bypass]]：Filter 层类似的“条件不满足就放行”缺陷。
- [[web-java-component-flink-streaming-platform-web-job-jar-rce]]：本案绕过后的后续利用链。
- 变体：判断条件可能是 `Accept: application/json`、`Content-Type: application/json`、`Sec-Fetch-Mode`、`Referer` 含站内地址等；凡是“按请求格式决定是否鉴权”的实现都可用同样思路绕过。
- 边界：若 Controller/Service 层有独立鉴权（注解、AOP、方法级权限），绕过拦截器只能访问到这些接口的未授权逻辑，危害需按实际返回判断。

## 检测与防御

- 检测：访问日志或 WAF 中出现“未登录却访问业务接口且不带 `X-Requested-With`”的请求；同一 IP 先匿名 POST `/api/addUser` 等管理接口，随后用新账号登录；返回 200 的匿名 API 调用。
- 检测：关注拦截器日志中的“未知请求”放行记录与紧邻的敏感接口调用。
- 防御：认证与授权必须独立于请求格式/请求头，对所有路由默认拒绝、显式白名单放行；在 Controller/Service 层增加方法级权限校验；对敏感接口（添加用户、任务提交）做二次身份与角色检查。
- 响应：删除攻击者创建的账号，审计其后续操作（任务提交、命令执行、数据访问），并修复拦截器逻辑。
