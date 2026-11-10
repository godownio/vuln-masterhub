---
id: web-generic-auth-weaver-ecology10-appthirdlogin-eteamsid-bypass
title: 泛微 e-cology 10 前台认证绕过：appThirdLogin 任意用户名无密码创建 TGT + generateEteamsId 换取会话
type: scenario
domain: web
path: web/generic/auth
technique: weaver-ecology10-appthirdlogin-eteamsid-auth-bypass
tags:
- web
- java
- weaver
- ecology10
- auth-bypass
- kerberos
- cas
- tgt
- eteamsid
- xve-2024-20913
cve: []
severity: high
confidence: medium
affected_versions: 泛微 e-cology 10（XVE-2024-20913 补丁前版本）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:40:26+08:00'
  notes: 已对照原文与全部9张图核对：图01 appThirdLogin 的 loginType→CasLoginEnum、无票据时 username 分支 new WeaverUsernamePasswordCredential(username,"authPasswordFlag")+setNoPassword(true)+createTicketGrantingTicket+grantServiceTicket→serviceTicketId；图02 createTicketGrantingTicket→authenticate→authenticateInternal；图03 noPassword 为真时走 else 分支 handler.getUserByEmpId(credential)；图04 generateEteamsIdBySt 的 validateSt→loadUserDetails→generateTokenId→CasAuthenticationToken→securityContextCache.put。generateTokenId 算法（空 loginType 用 MD5(credential)；非空用 loginType_MD5，APP/H5 加 _appType）与原文代码一致；手动拼接 EteamsId 因无缓存写入而失败也与原文一致。原子性：本卡只覆盖认证绕过链（appThirdLogin→generateEteamsId），JDBC 利用在同篇另一卡，拆分正确。affected_versions 已规范为『泛微 e-cology 10（XVE-2024-20913 补丁前版本）』。未验证点：原文未给完整 HTTP 路由与最终回显，卡片已注明按代码还原、confidence medium，未本机复现；frontmatter 无 sources/source_url。dedup 仅自身草稿命中，mobilemode/e9 卡为不同端点/票据链；dup-scan 中与同篇 JDBC 卡 pair 判定 related（认证绕过 vs 注入利用），两张均保留。
url: /docs/web/generic/auth/web-generic-auth-weaver-ecology10-appthirdlogin-eteamsid-bypass/
draft: false
kb_aliases:
- XVE-2024-20913 认证绕过
- appThirdLogin
- generateEteamsId
- EteamsId
- ETEAMS_TGC
- 泛微 e-cology 前台绕过
---

## 一句话结论

泛微 e-cology 10 的 `RestLoginController#appThirdLogin()` 从请求中取 `loginType`，在没有 ETEAMS_TGC 票据时直接用调用者提供的 `username` 构造 `WeaverUsernamePasswordCredential`、设置 `noPassword=true` 并调用 `createTicketGrantingTicket()` 创建 TGT，随后 `grantServiceTicket()` 返回 `serviceTicketId`；再用该 ST 调用 `PassportLoginController#generateEteamsId()`，服务端 `generateEteamsIdBySt()` 校验 ST、加载用户信息、生成 `EteamsId`（`loginType + "_" + MD5(stTicket)`）并把认证上下文写入 `securityContextCache`，攻击者拿到 EteamsId 后即可作为会话访问后台接口。手动拼接 EteamsId 无效，因为缺少服务端缓存写入，必须走该接口。

## 原理

- **appThirdLogin 的无密码 TGT 创建**：`appThirdLogin(loginType, tgtId, response, username, service, ip, language)` 先按 `loginType` 取 `CasLoginEnum`；若 cookie 中没有有效 `ETEAMS_TGC` 票据，则进入 `username` 分支：
  ```java
  WeaverUsernamePasswordCredential credential = new WeaverUsernamePasswordCredential(username, "authPasswordFlag");
  credential.setNoPassword(true);
  tgtId = casLoginTicketService.createTicketGrantingTicket(credential, casLoginEnum);
  result.put("serviceTicketId", casLoginTicketService.grantServiceTicket(tgtId, getService(null), casLoginEnum));
  ```
  `setNoPassword(true)` 让后续 `authenticateInternal` 走免密分支：当 `!CasLoginEnum.notCheckPassword(casLoginEnum)` 且 `credential.getNoPassword()` 为真（或类似条件）时，调用 `handler.getUserByEmpId(credential)` 直接按用户名取用户信息，而不是校验密码。TGT 创建成功后立即用 `grantServiceTicket` 签发 ST，因此攻击者无需知道任何口令即可获得一个绑定到任意用户名的 ST。
- **generateEteamsId 的缓存写入**：`PassportLoginController#generateEteamsId(stTicket, service, request)` 调用 `passportEteamsIdService.generateEteamsIdBySt()`：
  ```java
  Assertion assertion = validateSt(stTicket, service);
  TeamsUserDetails teamsUserDetails = userDetailsService.loadUserDetails(assertion);
  String tokenId = SecurityCasUtils.generateTokenId(stTicket, teamsUserDetails.findLoginType());
  CasAuthenticationToken cat = new CasAuthenticationToken("eteams432534gfdg", teamsUserDetails, stTicket, authorities, teamsUserDetails, assertion);
  SecurityContext context = SecurityContextHolder.getContext();
  context.setAuthentication(cat);
  securityContextCache.put(tokenId, context);
  ```
  `generateTokenId` 的算法是 `loginType.replace("_","").toUpperCase() + "_" + MD5(stTicket).toLowerCase()`（`loginType` 为空时直接用 `MD5(credential)`；`APP`/`H5` 前缀再追加 `_appType`）。关键不是哈希算法，而是 `securityContextCache.put(tokenId, context)`：EteamsId 必须对应服务端缓存中的已认证上下文。
- **为什么不能手算 EteamsId**：原文测试过按 `generateTokenId` 手工拼接 `loginType + MD5(ST)`，但服务端校验时找不到 `securityContextCache` 中对应的上下文，因此失败。攻击者必须实际调用 `generateEteamsId`，让服务端完成 `validateSt` + `securityContextCache.put`，才能得到可用的 EteamsId。
- **从 ST 到会话**：`validateSt` 验证 ST 是否由 KDC/票据服务签发、是否对应该 `service`；`loadUserDetails(assertion)` 从 ST 中取出用户名/属性并加载为 `TeamsUserDetails`；最终 EteamsId 作为会话标识返回，客户端后续请求携带它即可通过认证，访问需要登录的 API（原文的 JDBC 数据源测试接口就是其中之一）。
- **漏洞本质**：登录接口把 `username` 当作可信输入、把 `noPassword=true` 作为内部标志暴露在外部可控的第三方登录路径上；`loginType` 只影响票据类型/域，不校验调用方身份。整个链不需要密码、不需要已有会话，属于前台认证绕过。

## 触发条件

- 目标为泛微 e-cology 10（XVE-2024-20913 补丁前版本），对外暴露 `appThirdLogin` 与 `generateEteamsId` 对应的 HTTP 路由。
- 攻击者能提供一个可被 `getUserByEmpId` 解析的 `username`（通常为已存在用户，如管理员），以及一个能映射到免密分支的 `loginType`。
- 服务端 CAS/TGT 组件正常工作，能签发 TGT/ST；`validateSt` 对 `service` 的校验可通过（原文调用 `getService(null)`，即空 service）。
- 目标未对这两个接口做额外鉴权/频率限制，或 WAF 未拦截异常 `loginType`/`username` 组合。
- 攻击者需要已认证 API 的访问能力（如后续 JDBC 数据源测试），但没有有效账号口令。

## 利用步骤

1. 向 `RestLoginController#appThirdLogin` 对应路由发送请求，参数包含 `loginType`（选择一个走免密分支的值）、`username`（目标用户，如 admin）、`service`（可为空/默认），不携带有效 `ETEAMS_TGC` cookie。
2. 服务端按 `username` 创建 TGT 并签发 ST，响应中返回 `serviceTicketId`（如 `ST-...`）。
3. 向 `PassportLoginController#generateEteamsId` 对应路由发送请求，参数 `stTicket=上一步的 ST`（`service` 可选）。
4. 服务端 `validateSt` → `loadUserDetails` → `generateTokenId` → `securityContextCache.put`，响应返回 `EteamsId`（形如 `LOGINTYPE_<md5>`）。
5. 后续请求携带该 EteamsId 作为会话标识（cookie/header，按应用实际读取方式），访问需要认证的接口；原文以此调用 `DataConnController#testConnByBasePassword` 进入 JDBC 注入链（见关联卡）。
6. 若返回“TGT 失效/未认证”，检查 loginType 是否命中免密分支、username 是否存在、ST 是否被一次性消费、service 是否需与生成时一致。

## PoC

原文只给出控制器方法名、参数与关键代码，未给出完整 HTTP 路由和请求包；以下为按代码还原的请求骨架（路由需按目标部署确认，未在本机复现）：

```http
# 1) 无密码创建 TGT 并获取 serviceTicketId
POST /<passport>/appThirdLogin
Content-Type: application/x-www-form-urlencoded

loginType=<免密分支类型>&username=admin&service=

# 响应：{"success":"true","serviceTicketId":"ST-...","tgtId":"TGT-..."}

# 2) 用 ST 换取 EteamsId
POST /<passport>/generateEteamsId
Content-Type: application/x-www-form-urlencoded

stTicket=ST-...

# 响应：EteamsId（如 LOGINTYPE_<md5>）

# 3) 携带 EteamsId 访问已认证接口（示例为 JDBC 数据源测试）
POST /<api>/dataconn/testConnByBasePassword
EteamsId: <上一步结果>
Content-Type: application/json

{"dbType":"mysql","dbUrl":"...","dbPassword":"<base64>"}
```

> 说明：`loginType` 的可用值、`username` 是否存在、`service` 校验均依赖目标版本与配置；原文未附最终 HTTP 回显，卡片按代码分析整理，confidence medium，未在本机复跑。

## 变体与关联

- **同产品其他认证绕过**：[[web-generic-auth-weaver-ecology-mobilemode-token-chain-login-bypass]] 通过 DWR 读取 `security.key` 伪造 `mToken` 再换 `ecology_JSessionid`；[[web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass]] 是 e9 `islogin` 正则绕过。本卡是 e-cology 10 的 appThirdLogin/generateEteamsId 免密 TGT + 缓存 STS 链，端点、票据类型与 PoC 均不同。
- **后续利用链**：[[web-java-component-weaver-ecology10-dataconn-jdbc-h2-init-rce]]（用本卡得到的 EteamsId 访问 DataConnController，构造恶意 JDBC URL 实现 H2 init RCE 或 MySQL 文件读取）。
- **同类 TGT/ST 伪造思路**：AD Kerberos 的黄金/白银票据是离线伪造 TGT/ST；本卡是应用层 CAS 实现直接签发 TGT/ST 并转换为 EteamsId 会话，原理不同但都利用“票据信任”。
- 边界：补丁后 `generateEteamsId` 无法直接获取 EteamsId；若 loginType 不再走免密分支、username 不存在或 service 校验失败，链失效。

## 检测与防御

- 修复：升级到 XVE-2024-20913 补丁版本；`appThirdLogin` 必须校验调用方身份/签名，禁止外部传入 `noPassword=true` 的等价语义；`generateEteamsId` 限制来源/一次性 ST，且不要把认证上下文写入可被外部枚举的缓存键。
- 加固：对 `loginType` 使用白名单；对 `username` 与当前会话/租户绑定；对 passport 接口做速率限制与异常参数检测；关闭不必要的第三方登录入口；WAF 拦截 `loginType`/`username` 异常组合及 `ETEAMS_TGC` 缺失但返回 ST 的请求。
- 检测：同一 IP/短时间大量 `appThirdLogin` 请求、`generateEteamsId` 返回 EteamsId 但无对应登录日志、EteamsId 首次使用来自新 IP、登录成功但无密码校验/AD 认证事件、随后调用数据源/JDBC 测试接口。
- 该场景为授权渗透测试/漏洞分析；生产环境不能把“内部方法/参数”当作外部不可达的安全边界。
