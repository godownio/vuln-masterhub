---
id: web-generic-file-inclusion-artery-erp-loginservlet-errorpage-forward
title: Artery ERP LoginServlet 用 errorpage 参数做内部转发：op=login 触发异常后读取 /WEB-INF/web.xml
type: scenario
domain: web
path: web/generic/file-inclusion
technique: erp-loginservlet-errorpage-forward-file-read
aliases:
- LoginServlet errorpage 文件读取
- getRequestDispatcher 内部转发
- op=login errorpage
- WEB-INF web.xml 读取
- ERP 敏感文件读取
tags:
- web
- file-inclusion
- java
- servlet
- internal-forward
- erp
- unauth
- file-read
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V237
  verified_at: '2026-11-07T09:20:32+08:00'
  notes: 已对照原文核对（33 图）；op=login&errorpage=/WEB-INF/web.xml 实测回显 web.xml；未复现。
---

## 一句话结论

ERP 的 `com.artery.portal.LoginServlet` 在登录校验抛出 `AuthenticationException` 后，会取 `errorpage` 参数作为 `getRequestDispatcher(...).forward()` 的目标；攻击者用 `op=login&errorpage=/WEB-INF/web.xml` 让内部转发到 WEB-INF 下的敏感文件，从而读取容器本不允许直接访问的配置/资源。

## 原理

- `LoginServlet.doPost` 解析 `op` 参数并按 `|` 拆分成多个操作，执行登录/校验流程；校验失败会抛出 `AuthenticationException`。
- `catch (AuthenticationException e)` 分支：
  ```java
  entid = request.getParameter("errorpage");
  if (entid != null && entid.length() > 0) {
      request.setAttribute("exception", e);
      request.getRequestDispatcher(entid).forward(request, response);
  } else {
      request.setAttribute("javax.servlet.jsp.jspException", e);
      request.getRequestDispatcher("/WEB-INF/jspx/error.jsp").forward(request, response);
  }
  ```
- `errorpage` 完全由外部传入，且没有做白名单/路径规范化；`getRequestDispatcher` 的 `forward` 是服务器内部转发，可访问 `/WEB-INF/` 等浏览器无法直接请求的资源（Tomcat 默认禁止直接访问 WEB-INF，但允许内部 forward）。
- 触发异常只需要构造 `op=login`（或使校验失败），例如缺少/错误的 username、password；异常被 catch 后即进入可控转发。
- 影响：读取 `/WEB-INF/web.xml`、`/WEB-INF/` 下的配置、JSP 源码片段、classes 目录中的资源等，泄露路由、类名、数据源、密钥等信息；若转发到可执行的 JSP，还可能触发额外逻辑。

## 触发条件

- 目标部署该 ERP/框架，`/login` 可访问。
- `LoginServlet` 按上述逻辑处理 `errorpage`，且攻击者可触发 `AuthenticationException`（如 `op=login` 且凭据缺失/错误）。
- 目标资源在容器内部可转发（`/WEB-INF/...`、`/META-INF/...`、JSP/静态资源）。
- 响应会返回转发目标的内容（forward 直接输出）。

## 利用步骤

1. 请求 `POST /login`，body `op=login&errorpage=/WEB-INF/web.xml`，username/password 留空或填错以触发异常。
2. 观察响应是否为 `web.xml` 内容（`<web-app>`、`<servlet>`、`<filter>` 等），确认内部转发生效。
3. 依次尝试 `/WEB-INF/` 下的配置、`/WEB-INF/classes/` 资源、`/META-INF/context.xml`、其他 JSP/模板路径。
4. 若 `errorpage` 指向的 JSP 可执行，评估是否会触发额外业务逻辑/回显；配合其他漏洞扩大。
5. 记录请求与响应内容作为证据，避免读取与业务无关的大量敏感数据。

## PoC

```http
POST /login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

op=login&errorpage=/WEB-INF/web.xml
```

响应（原文）直接返回 `web.xml` 片段：

```xml
<servlet>
  <servlet-name>formlocalizer</servlet-name>
  <servlet-class>org.apache.pluto.container.driver.PortletServlet</servlet-class>
  ...
</servlet>
<servlet-mapping>
  <servlet-name>formlocalizer</servlet-name>
  <url-pattern>/PlutoInvoker/formlocalizer</url-pattern>
</servlet-mapping>
```

## 变体与关联

- 变体：`errorpage` 指向其他 `WEB-INF` 资源、JSP、模板；若容器允许，亦可转发到外部 URL（取决于 `RequestDispatcher` 实现与容器行为）。
- 变体：`op` 支持 `|` 分隔的多操作，可尝试其他会抛 `AuthenticationException` 的分支，确保进入 catch。
- 关联：FormService 机制 [[web-java-framework-formservice-reflection-dispatch-unauth]]；同系统文件读取 [[web-generic-file-inclusion-artery-erp-formstudioupdater-getstudiofile]]；通用文件包含/读取 [[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]。
- 边界：`errorpage` 被白名单/固定为错误页、异常不被 catch、或容器禁止 forward 到目标资源时，读取不成立。

## 检测与防御

- 检测：`/login` 请求中出现 `errorpage=`；`errorpage` 值包含 `/WEB-INF/`、`..`、绝对路径或非错误页资源；登录失败响应长度异常且包含 XML/JSP 源码。
- 修复：错误页使用固定映射（如 `error.jsp`），禁止用请求参数作为 `getRequestDispatcher` 目标；若必须动态，使用错误码到页面的白名单映射。
- 加固：`WEB-INF` 资源不包含敏感明文配置；容器禁止 forward 到任意路径；登录接口对异常信息统一处理，不回显内部路径。
