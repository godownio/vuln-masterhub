---
id: defense-detection-websocket-memshell-arthas-remove
title: Arthas 查杀 Tomcat WebSocket 内存马：枚举 WsServerContainer.configExactMatchMap 并移除恶意 Endpoint
type: scenario
domain: defense
path: defense/detection
technique: arthas-websocket-memshell-detect-remove
tags:
- java
- tomcat
- memshell
- websocket
- arthas
- incident-response
- detection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V136
  verified_at: '2026-11-06T05:38:02+08:00'
  notes: 已对照原文与25张图片核对：wsMemShell经ServerEndpointConfig.Builder.create+WsServerContainer.addEndpoint动态注册，addEndpoint将path与ExactPathMatch写入configExactMatchMap（图15-17）、vmtool枚举key与config.endpointClass.name（图18）、remove后新连接404但已建立连接不断（图19-21）均与卡一致；PoC中路由/类名/上下文路径为示例值。未实际复现注入/卸载。
url: /docs/defense/detection/defense-detection-websocket-memshell-arthas-remove/
draft: false
kb_aliases:
- WebSocket 内存马
- wsMemShell
- WsServerContainer
- configExactMatchMap
- ServerEndpointConfig
- ExactPathMatch
- 动态注册 WebSocket
---

## 一句话结论

WebSocket 内存马通过 `ServerEndpointConfig.Builder.create(...).build()` 加 `WsServerContainer#addEndpoint` 动态注册恶意 Endpoint，路由与配置保存在 `configExactMatchMap`（`ConcurrentHashMap<path, ExactPathMatch>`）；用 Arthas `vmtool` 枚举该 map 的 key 和 `config.endpointClass.name` 即可定位，确认恶意类名后直接 `configExactMatchMap.remove(path)` 卸载。

## 原理

- **注入逻辑**：攻击者从 `ServletContext` 属性 `javax.websocket.server.ServerContainer` 取得 `WsServerContainer`，用 `ServerEndpointConfig.Builder.create(MyWebSocketEndpoint.class, "/evil").build()` 构造配置，再调用 `serverContainer.addEndpoint(config)` 动态注册。Tomcat 提供该 API，属于正常能力，因此内存马不需要修改字节码。
- **存储位置**：`org.apache.tomcat.websocket.server.WsServerContainer#addEndpoint` 把 `path` 与 `ExactPathMatch(sec)` 写入 `configExactMatchMap`；`ExactPathMatch` 是简单 bean，持有 `ServerEndpointConfig`，其中 `endpointClass` 就是恶意 Endpoint 类。
- **检测**：`configExactMatchMap` 的 key 是注册路由，value 的 `config.endpointClass.name` 是处理类。只按路由判断不可靠（可能与正常业务路由重名/相似），必须同时输出路由与 Endpoint 类名，再人工确认是否为恶意类。
- **卸载**：`configExactMatchMap.remove(path)` 即可让新连接无法再匹配到该 Endpoint；已经建立的 WebSocket 连接不会被切断（连接已建立），但无法建立新连接。
- **为什么有效**：动态注册的 Endpoint 没有对应的 `web.xml`/注解声明，也不在磁盘 class 路径中；`configExactMatchMap` 是运行时注册表的唯一事实来源，删除即撤销路由。

## 触发条件

- 目标为 Tomcat（含 `org.apache.tomcat.websocket.server.WsServerContainer`），已注入 WebSocket 型内存马（wsMemShell 等）。
- 可 attach Arthas 到目标 JVM，能执行 `vmtool`。
- 能确认恶意 Endpoint 的类名/路由，避免误删正常 WebSocket 业务。

## 利用步骤

1. attach Arthas，执行 `vmtool` 获取 `WsServerContainer` 实例。
2. 枚举 `configExactMatchMap` 的所有 key（路由），并输出每个路由对应的 `config.endpointClass.name`：
   ```text
   vmtool --action getInstances --className org.apache.tomcat.websocket.server.WsServerContainer --express '#container=instances[0],#name=#container.configExactMatchMap.keySet().toArray().{#name=#this,#this+":"+#container.configExactMatchMap[#name].config.endpointClass.name}'
   ```
3. 对可疑路由用 `jad` 反编译其 Endpoint 类，确认是否读取消息并执行命令/回显。
4. 仅在类名与恶意类匹配时删除路由：
   ```text
   vmtool --action getInstances --className org.apache.tomcat.websocket.server.WsServerContainer --express '#container=instances[0],#className=#container.configExactMatchMap["恶意路由"].config.endpointClass.name,#className,{#className.equals("恶意类名")?#container.configExactMatchMap.remove("恶意路由"):"failed"}'
   ```
5. 验证：再次枚举 map，恶意路由应消失；用 `websocat ws://target/恶意路由` 新建连接应返回 404/握手失败；已建立的连接仍可能存活，需结合业务侧断开或重启。

## PoC

```text
# 1) 枚举路由与 Endpoint 类名
vmtool --action getInstances --className org.apache.tomcat.websocket.server.WsServerContainer --express '#container=instances[0],#name=#container.configExactMatchMap.keySet().toArray().{#name=#this,#this+":"+#container.configExactMatchMap[#name].config.endpointClass.name}'

# 2) 确认后删除恶意路由
vmtool --action getInstances --className org.apache.tomcat.websocket.server.WsServerContainer --express '#container=instances[0],#className=#container.configExactMatchMap["/evil"].config.endpointClass.name,#className,{#className.equals("com.MyWebSocketEndpoint")?#container.configExactMatchMap.remove("/evil"):"failed"}'

# 3) 验证新连接失败
websocat "ws://127.0.0.1:8080/app/evil"
```

## 变体与关联

- **多路由/多 Endpoint**：一次注入可能注册多个路由；枚举结果需逐条核对，删除时逐个 remove。
- **路由伪装**：恶意路由可能伪装成正常业务路径（如 `/ws`、`/chat`），不能只凭路径判断，必须看 `endpointClass`。
- **连接残留**：`remove` 只影响新连接，已建立的 WebSocket 会话仍存活；需要业务侧主动关闭或重启才能彻底断开。
- **关联卡片**：[[web-java-classloader-websocket-endpoint-memshell]]（WebSocket Endpoint 内存马注入）、[[defense-detection-tomcat-memshell-scanner-arthas]]（Tomcat 组件枚举与 Arthas 排查）、[[defense-detection-proxyvalve-memshell-arthas-remove]]（另一类动态代理型内存马查杀）。

## 检测与防御

- **检测**：`WsServerContainer.configExactMatchMap` 中出现未在 `web.xml`/注解声明的路由；`endpointClass` 为随机/伪装类名、不在应用 classpath 中；WebSocket 握手日志出现异常路径；Endpoint 类反编译后含 `Runtime`/`ProcessBuilder`/命令读取逻辑。
- **防御**：对 WebSocket 路由做启动基线并定期比对；监控 `WsServerContainer.addEndpoint` 调用（RASP/Agent）；限制运行期动态注册；限制 Arthas/attach 的生产可用性；发现内存马后删除路由、断开连接并排查初始入口。
- **注意**：删除前必须确认 `endpointClass` 类名，避免误删正常 WebSocket 业务；卸载后已建立连接仍可通信，需评估是否需要重启或主动断开。
