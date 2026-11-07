---
id: defense-detection-proxyvalve-memshell-arthas-remove
title: Arthas 查杀 ProxyValve 内存马：反射读取 first/basic 并解包 InvocationHandler 还原原始 Valve
type: scenario
domain: defense
path: defense/detection
technique: arthas-proxyvalve-memshell-detect-remove
tags:
- java
- tomcat
- memshell
- valve
- dynamic-proxy
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
  verified_at: '2026-11-06T05:38:01+08:00'
  notes: 已对照原文与25张图片核对：注入逻辑（getPipeline→Valve接口→first/basic→Proxy.newProxyInstance）、invoke透传invoke并调用恶意equals、equals经getParameter/getHeader取参并以getInputStream执行回显、OGNL stricter invocation报错与FieldUtils置_useStricterInvocation=false、Proxy.getInvocationHandler解包遍历Valve字段还原first、卸载后命令失效（图12-14）均与卡一致；KMBA工具卡未单独建卡合理。未实际复现注入/查杀。
url: /docs/defense/detection/defense-detection-proxyvalve-memshell-arthas-remove/
draft: false
kb_aliases:
- ProxyValve
- ProxyValve 内存马
- MemShellParty ProxyValve
- StandardPipeline first/basic
- InvocationHandler 还原
- rawValve
- OGNL strict 绕过
---

## 一句话结论

ProxyValve 内存马把 `StandardPipeline.first`（`first` 为 null 时改 `basic`）替换成动态代理，代理的 `invoke` 会调用恶意对象的 `equals` 执行命令；应急时用 Arthas `vmtool` 反射读取被 `protected` 保护的 `first`/`basic`，取 `Proxy.getInvocationHandler` 解包代理，遍历 handler 字段找到原始 `Valve` 并用 `Field.set` 还原，即可在不重启业务的情况下查杀。

## 原理

- **注入逻辑**：MemShellParty 的 ProxyValve 通过 `StandardContext#getPipeline` 拿到 `StandardPipeline`，以 `org.apache.catalina.Valve` 为接口、原始 Valve 为 `rawValve`、恶意对象为 `proxyValve` 调用 `Proxy.newProxyInstance`，再把代理设置到 `first`；若 `first` 为 null 则改设置 `basic`。`basic` 负责指向下一个 Pipeline，处理不当易导致 Tomcat 崩溃，所以注入器优先改 `first`。
- **执行逻辑**：代理的 `InvocationHandler.invoke` 对 `invoke` 方法直接透传；其他调用先执行 `proxyValve.equals(new Object[]{request, response})`，恶意 `equals` 从请求参数/请求头取命令，经 `getInputStream`/`getOutputStream` 执行并回显。
- **检测难点**：必须同时输出 `first` 和 `basic`，因为 `first` 为 null 时恶意代码会改 `basic`；而 `StandardPipeline#getFirst()` 在 `first == null` 时会返回 `basic`，用 OGNL 直接取属性会误判。`first`/`basic` 都是 `protected`，必须反射并 `setAccessible(true)`。
- **Arthas OGNL 限制**：Arthas 的 OGNL 默认 `_useStricterInvocation=true`，在 `invokeMethod` 中调用 `setAccessible` 会抛 `IllegalAccessException: ... under stricter invocation mode`。可用 Arthas 自带 `FieldUtils` 反射把 `ognl.OgnlRuntime._useStricterInvocation` 的 `final` 修饰去掉并置为 false；需要先取 ArthasClassLoader 的 hash。
- **还原逻辑**：`Proxy.getInvocationHandler(first)` 拿到 handler（恶意类实例，如 `com.google.gso.nKODi.HttpUtil`），其中保存 `rawValve`（原始 Valve）与 `proxyValve`（恶意对象）。变量名可能被混淆/每日变更，不能写死字段名；应遍历 handler 的所有 `Field`，取值为 `org.apache.catalina.Valve` 实现类的那个字段，再用 `Field.set(pipeline, value)` 还原 `first`（`basic` 同理）。

## 触发条件

- 目标为 Tomcat（`org.apache.catalina.core.StandardContext`/`StandardPipeline`），且已被注入 ProxyValve 型内存马（MemShellParty 等）。
- 可 attach Arthas 到目标 JVM，具备 `vmtool` 与 OGNL 执行能力。
- 能获取 ArthasClassLoader 的 hash 以执行 `FieldUtils` 修改 `_useStricterInvocation`。
- 知道或能确认恶意代理类名（用于卸载前的校验，避免误伤正常代理）。

## 利用步骤

1. attach Arthas，执行 `classloader -l | grep taobao` 取得 ArthasClassLoaderHash。
2. 关闭 OGNL strict（否则后续 `setAccessible` 失败）：
   ```text
   ognl -c <ArthasClassLoaderHash> '#field = @com.taobao.arthas.core.util.reflect.FieldUtils@getDeclaredField(Class.forName("ognl.OgnlRuntime"),"_useStricterInvocation",true), #modifiers = @com.taobao.arthas.core.util.reflect.FieldUtils@getDeclaredField(#field.getClass(),"modifiers",true),#modifiers.setInt(#field, #field.getModifiers() & ~@java.lang.reflect.Modifier@FINAL),#field.set(null,false)'
   ```
3. 用 `vmtool` 取 `StandardContext` 实例，反射读取 `first` 与 `basic` 的类名：
   ```text
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext -classLoaderClass java.net.URLClassLoader --express '#pip=instances[0].getPipeline,#basicField=#pip.class.getDeclaredField("basic"),#basicField.setAccessible(true),#basic=#basicField.get(#pip),#firstField=#pip.class.getDeclaredField("first"),#firstField.setAccessible(true),#first=#firstField.get(#pip),#x={(#first!=null)?{"first"+":"+#first.class.name,"basic"+":"+#basic.class.name}:{"basic"+":"+#basic.class.name}},#x[0]'
   ```
4. 若 `first` 是 `com.sun.proxy.$Proxy*` 等代理类，取 `InvocationHandler` 并确认恶意类名：
   ```text
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext -classLoaderClass java.net.URLClassLoader --express '#pip=instances[0].getPipeline,#firstField=#pip.class.getDeclaredField("first"),#firstField.setAccessible(true),#first=#firstField.get(#pip),#evil=@java.lang.reflect.Proxy@getInvocationHandler(#first)'
   ```
5. 遍历 handler 字段，找到 `instanceof org.apache.catalina.Valve` 的值，并仅在代理类名匹配恶意类名时还原：
   ```text
   vmtool --action getInstances --className org.apache.catalina.core.StandardContext -classLoaderClass java.net.URLClassLoader --express '#pip=instances[0].getPipeline,#firstField=#pip.class.getDeclaredField("first"),#firstField.setAccessible(true),#first=#firstField.get(#pip),{(#first.class.name.equals("恶意代理类名"))?(#evil=@java.lang.reflect.Proxy@getInvocationHandler(#first),#f=#evil.class.getDeclaredFields().{(#this.setAccessible(true),#value=#this.get(#evil),#value instanceof org.apache.catalina.Valve)?(#firstField.set(#pip,#value)):("false")}):("failed")}'
   ```
6. 验证：执行原来的命令请求应不再回显；业务页面正常。若 `first` 为 null 且恶意代理在 `basic`，把上述 `first` 替换为 `basic` 重复第 3–5 步。

## PoC

```text
# 1) 取 Arthas classloader hash
classloader -l | grep taobao

# 2) 关闭 OGNL strict（把 <hash> 换成上一步结果）
ognl -c <hash> '#field = @com.taobao.arthas.core.util.reflect.FieldUtils@getDeclaredField(Class.forName("ognl.OgnlRuntime"),"_useStricterInvocation",true), #modifiers = @com.taobao.arthas.core.util.reflect.FieldUtils@getDeclaredField(#field.getClass(),"modifiers",true),#modifiers.setInt(#field, #field.getModifiers() & ~@java.lang.reflect.Modifier@FINAL),#field.set(null,false)'

# 3) 查看 first/basic 类名
vmtool --action getInstances --className org.apache.catalina.core.StandardContext -classLoaderClass java.net.URLClassLoader --express '#pip=instances[0].getPipeline,#firstField=#pip.class.getDeclaredField("first"),#firstField.setAccessible(true),#first=#firstField.get(#pip),#basicField=#pip.class.getDeclaredField("basic"),#basicField.setAccessible(true),#basic=#basicField.get(#pip),{"first:"+#first.class.name,"basic:"+#basic.class.name}'
```

卸载命令见“利用步骤”第 5 步；执行后原命令请求应失效。

## 变体与关联

- **first/basic 变体**：`first` 非空时注入 `first`；为 null 时注入 `basic`，检测与还原都必须覆盖两者。
- **字段名混淆**：handler 中的 `rawValve` 变量名可能被更改；用“值为 `Valve` 实现类”遍历匹配，不要依赖字段名。
- **多实例**：`StandardContext` 可能有多个（不同 host/context），需逐个处理；`instances[0]` 仅示例。
- **代理类型**：JDK 动态代理为 `com.sun.proxy.$Proxy*`；若为 CGLIB/Javassist 代理，`Proxy.getInvocationHandler` 不适用，需按实际代理框架取回调对象。
- **关联卡片**：[[web-java-component-tomcat-valve-memshell]]（Valve 内存马注入）、[[defense-detection-arthas-agent-memshell-detect-remove]]（Agent/transformer 型内存马查杀）、[[defense-detection-tomcat-memshell-scanner-arthas]]（Tomcat 组件枚举与 Arthas 排查）。

## 检测与防御

- **检测**：`StandardPipeline.first`/`basic` 出现 `com.sun.proxy.$Proxy*` 或未知动态代理类；代理的 `InvocationHandler` 类名为随机/伪装类（如 `com.google.gso.nKODi.HttpUtil`）；handler 字段中同时存在原始 Valve 与可疑对象；请求头/参数触发命令执行。
- **防御**：对 Tomcat 关键容器对象做完整性基线（Pipeline first/basic 类名、Valve 链）；部署 RASP/Java Agent 监控 `Proxy.newProxyInstance` 与 `StandardPipeline` 属性修改；限制 Arthas/attach 的生产可用性；发现内存马后先卸载代理再排查初始入口，单纯重启只能暂时清除。
- **注意**：修改 `_useStricterInvocation` 会降低 Arthas OGNL 的隔离强度，操作后应恢复或结束 Arthas 会话；卸载前务必校验恶意类名，避免误替换正常 Valve 导致业务中断。
