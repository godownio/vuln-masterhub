---
id: defense-detection-tomcat-servlet-listener-valve-memshell-arthas-vmtool-remove
title: Arthas vmtool 查杀 Tomcat Servlet/Listener/Valve 内存马：StandardContext 注册表定位与容器 API 移除
type: scenario
domain: defense
path: defense/detection
technique: arthas-vmtool-tomcat-servlet-listener-valve-memshell-remove
aliases:
- Arthas 杀 Servlet 内存马
- Arthas 杀 Listener 内存马
- Arthas 杀 Valve 内存马
- removeServletMapping
- applicationEventListenersList.remove
- removeValve
- vmtool 内存马查杀
tags:
- java
- tomcat
- memshell
- arthas
- vmtool
- servlet
- listener
- valve
- incident-response
- detection
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

对 Tomcat 中的基础 Servlet/Listener/Valve 内存马，可在 attach Arthas 后用 `vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express '...'` 直接读取 `servletMappings`、`applicationEventListenersList`、`getPipeline().getValves()` 定位恶意组件，再调用容器自带的 `removeServletMapping`、`List.remove`、`removeValve` 在不重启的情况下移除；Servlet 不能只删 `servletMappings`，否则 Wrapper 的映射仍在，且后续再调 `removeServletMapping` 会因取不到 name 而跳过清理。

## 原理

- Tomcat 把应用级组件保存在 `StandardContext`：
  - Servlet：`servletMappings`（`HashMap<urlPattern, servletName>`）+ `children`（`Wrapper`）；`addServletMappingDecoded` 同时把 pattern→name 写入 map，并在 Wrapper 上 `addMapping(pattern)`。
  - Listener：`applicationEventListenersList`（`CopyOnWriteArrayList`），`addApplicationEventListener` 只做 `list.add(listener)`。
  - Valve：`StandardPipeline` 的 `first`/`basic` 与 Valve 数组，`addValve` 追加，`removeValve` 从链中摘除。
- **Servlet 坑点**：`StandardContext.removeServletMapping(pattern)` 的实现是 `name = servletMappings.remove(pattern); Wrapper wrapper = findChild(name); if (wrapper != null) wrapper.removeMapping(pattern);`。如果先手工 `servletMappings.remove("/exec")`，map 已无该键，再调用 `removeServletMapping` 时 `remove` 返回 `null`，`findChild(null)` 为 null，`wrapper.removeMapping` 不会执行；结果是恶意 Wrapper 仍持有 `/exec` 映射，路由仍可访问。
- **补救**：已经误删 map 时，直接调用 `findChild("execServlet").removeMapping("/exec")`（或对 Wrapper 调用等价的移除）即可让路由失效；或者先 `removeServletMapping` 再确认 map/Wrapper 都已清理。
- **Listener**：`applicationEventListenersList` 是 List，只能按索引 `remove(index)`；移除后列表为空即生效。要先确认索引对应恶意 Listener，避免误删业务 Listener。
- **Valve**：`StandardPipeline.getValves()` 返回 Valve 数组（含 `NonLoginAuthenticator`、恶意 Valve、`StandardContextValve` 等）；`getPipeline().removeValve(valve)` 从链中摘除恶意 Valve，之后请求不再经过它。
- **多 Context**：一个 Tomcat 可能有多个 `StandardContext`（如 `/manager` 与业务应用），`instances[i]` 的索引随应用数量和加载顺序变化；案例中曾用 `instances[1]` 与 `instances[0]`，必须按 `StandardContext` 的 path/name 确认目标应用，不能机械照抄索引。

## 触发条件

- 已获得目标 JVM 的 attach 权限（同用户/同主机，或已通过漏洞拿到命令执行），可启动 Arthas 并 attach 到 Tomcat 进程。
- 目标为 Tomcat/Servlet 容器，内存马属于 Servlet/Listener/Valve 等基础组件型（非 Agent transformer 型）。
- 知道或能枚举出 `StandardContext` 实例；业务应用上下文可写/可访问。
- 处置前已确认恶意组件（类名、路由、Listener 类型、Valve 类），避免误删业务组件。

## 利用步骤

1. 启动 Arthas 并 attach 目标 Tomcat：`java -jar arthas-boot.jar`，选择对应 PID。
2. 枚举 `StandardContext`，确认业务应用的索引：
   ```bash
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[i]'
   ```
3. **Servlet**：查看 `servletMappings`，找出恶意路由（如 `/exec` → `execServlet`）：
   ```bash
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[i].servletMappings'
   ```
   用容器 API 移除：
   ```bash
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[i].removeServletMapping("/exec")'
   ```
   若已误删 map，补做 Wrapper 清理：
   ```bash
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[i].findChild("execServlet").removeMapping("/exec")'
   ```
4. **Listener**：查看 `applicationEventListenersList`，确认恶意 Listener 的索引后移除：
   ```bash
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[i].applicationEventListenersList'
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[i].applicationEventListenersList.remove(0)'
   ```
5. **Valve**：查看 `getPipeline().getValves()`，找到恶意 Valve 后移除：
   ```bash
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[i].getPipeline().getValves()'
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express '#valve=instances[i].getPipeline().getValves()[k],#ctx=instances[i],#ctx.getPipeline().removeValve(#valve)'
   ```
6. 逐项验证：再次访问原恶意路由应返回 404/不再执行命令；再查一次对应容器结构，确认恶意项已消失。
7. 清理攻击入口（JSP、上传点、反序列化入口、WebShell），否则攻击者可重新注入。

## PoC

```bash
# 0) 枚举 StandardContext，确认业务应用索引
vmtool --action getInstances --className org.apache.catalina.core.StandardContext

# 1) Servlet：查看映射并移除
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[1].servletMappings'
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[1].removeServletMapping("/exec")'
# 误删 map 后的补救
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[1].findChild("execServlet").removeMapping("/exec")'

# 2) Listener：查看并移除第 0 个（恶意）Listener
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[0].applicationEventListenersList'
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[0].applicationEventListenersList.remove(0)'

# 3) Valve：查看并移除恶意 Valve
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[0].getPipeline().getValves()'
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express '#valve=instances[0].getPipeline().getValves()[1],#ctx=instances[0],#ctx.getPipeline().removeValve(#valve)'
```

验证：原恶意路由从可执行命令变为 404；`servletMappings`/`applicationEventListenersList`/`getValves()` 中不再出现恶意项。

## 变体与关联

- Filter 内存马：用 `filterMaps.array` + `removeFilterMap(FilterMap)`/`filterMaps.remove`，已有专卡 `defense-detection-tomcat-filter-memshell-hotpatch-vmtool-remove`。
- ProxyValve（动态代理替换 first/basic）：需解包 `Proxy.getInvocationHandler` 还原原始 Valve，见 `defense-detection-proxyvalve-memshell-arthas-remove`。
- Upgrade/Executor 内存马：见 `defense-detection-tomcat-upgrade-executor-memshell-arthas-vmtool-remove`。
- Agent/transformer 型内存马：`vmtool` 读 `InstrumentationImpl` transformer 列表，见 `defense-detection-arthas-agent-memshell-detect-remove`。
- 检测侧可先用 `sc *.Servlet`、`sc javax.servlet.Filter`、`sc org.apache.catalina.core.StandardContext`、`jad`、`sc -d` 的 `code-source` 为空/匿名类等特征确认，见 `defense-detection-tomcat-memshell-scanner-arthas`。

## 检测与防御

- 监控 `StandardContext.addChild`/`addServletMappingDecoded`/`addApplicationEventListener`/`Pipeline.addValve` 等运行期注册调用；部署 RASP 或 Java Agent 记录调用栈与来源类。
- 排查无磁盘 class 文件的 Wrapper/Listener/Valve、陌生 URL 映射、`code-source` 为空的类；结合 Arthas `sc`/`jad` 人工确认。
- 业务侧最小化动态注册能力，Web 目录只读，及时修复上传/反序列化/表达式注入入口；处置后删除入口并复查容器注册表。
- 保留 Arthas 等应急工具的受控访问权限，避免被攻击者利用同一工具反向操作。
