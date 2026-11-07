---
id: defense-detection-arthas-agent-memshell-detect-remove
title: Arthas 检测与卸载 Java Agent 型内存马
type: scenario
domain: defense
path: defense/detection
technique: arthas-instrumentation-transformer-memshell-response
aliases:
- Arthas 查杀内存马
- Agent 内存马排查
- Instrumentation transformer 检测
- retransform 还原字节码
- Java 内存马应急
tags:
- java
- arthas
- memshell
- javaagent
- instrumentation
- transformer
- incident-response
- jvm
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:46:49+08:00'
  notes: 已对照原文与13张图核对；transformer 注册/两份列表、retransform 缓存字节实验（SEED-A/BB 三次回调）、dump 内部 retransform、先移除再还原的顺序、JDK9+ Unsafe 路径及10组查杀实测均一致；已修正卡片中 JDK 私有字段拼写为实际的 mRetransfomableTransformerManager（原卡少一个 r 的命令会失败）；未本地复现
---

## 一句话结论

Java Agent 型内存马通过 `Instrumentation#addTransformer(canRetransform=true)` 注册恶意 `ClassFileTransformer` 篡改字节码；应急时可用 Arthas 的 `vmtool` 读取 `sun.instrument.InstrumentationImpl` 的两份 transformer 列表定位恶意类，先 `removeTransformer` 再用 `dump`/`retransform` 还原目标类字节码，实现不影响业务的查杀。

## 原理

- Agent 内存马通过 JavaAgent 的 `agentmain` 拿到 `Instrumentation`，注册一个 `canRetransform=true` 的 `ClassFileTransformer`，再调用 `retransformClasses` 触发 `transform`，在其中用 ASM/javassist 插入恶意逻辑（如 `ApplicationFilterChain.doFilter`、`StandardContextValve.invoke`、`ServletHandler.doHandle`）。
- 从查杀角度分两类：
  - **redefine 型**：直接 `redefineClasses` 替换类字节码，一次性生效，改写后不再自动重放；较少见。
  - **transformer 型**：注册 transformer 后可复用。每次 `define`/`redefine`/`retransform` 都会遍历执行 `canRetransform=true` 的 `transform`，因此只还原字节码而不移除 transformer，后续任何类重定义都会被再次污染。主流武器化工具（memshellparty、jmg 等）属于此类。
- 注册痕迹在 `sun.instrument.InstrumentationImpl`：
  - `mTransformerManager.mTransformerList` 保存 `canRetransform=false` 的 transformer；
  - `mRetransfomableTransformerManager.mTransformerList` 保存 `canRetransform=true` 的 transformer；
  - 每个 `TransformerInfo` 持有 `mTransformer`，其类名就是可疑注入器。
- 字节码缓存细节：`retransformClasses` 从 “initial class file bytes” 开始。若在第一次 `retransformClasses` 之前调用了 `redefineClasses`，缓存字节可能不是原始字节。实测结论是缓存只在 `transform` 被调用且返回非 null 字节的那一刻落定；`redefineClasses` 本身不改缓存。第一次 `retransform` 拿到的是当前类字节（可能是 redefine 后的），该次返回后缓存定格，之后再用 `redefine` 也改不了缓存。
- Arthas 的 `dump` 命令内部会注册一个 `ClassDumpTransformer` 并调用 `InstrumentationUtils.retransformClasses`，因此 `dump` 顺手完成了一次 `retransformClasses`，可把目标类按缓存字节重新走一遍 transformer 链并安装回去。
- 卸载顺序必须是：**先移除恶意 transformer，再还原字节码**。否则残留 transformer 会在之后任何 `define`/`redefine` 时重新注入。
- JDK 9+ 模块化后，`sun.instrument` 位于 `java.instrument` 模块且默认不 `opens` 给 unnamed module，直接反射读取私有字段会抛 `InaccessibleObjectException`；可用 `sun.misc.Unsafe` 的 `theUnsafe` + `objectFieldOffset`/`getObject` 绕过模块访问限制。

## 触发条件

- 目标 JVM 可被 attach Arthas（与目标进程同用户、具备 attach 权限，或已内置 Arthas）。
- 内存马为 transformer 型（主流），且能通过 transformer 列表定位到注入器类。
- 能确定被篡改的容器类（Tomcat/Jetty/WebLogic 常用注入点），以便还原字节码。
- JDK 9+ 需要 Unsafe 路径绕过模块封装；JDK 8 可直接反射。

## 利用步骤

1. attach Arthas 到目标 JVM，确认 `vmtool`、`jad`、`dump` 可用。
2. 获取 `sun.instrument.InstrumentationImpl` 实例，读取两份 transformer 列表，列出所有 transformer 类名。JDK 8 可用：
   ```text
   vmtool -l -1 --action getInstances --className sun.instrument.InstrumentationImpl \
     --express '#ins=instances[0],#tm1=#ins.mTransformerManager,#tm2=#ins.mRetransfomableTransformerManager,"n="+#tm1.mTransformerList.length'
   ```
3. 排除 Arthas 自身的 transformer，重点看未知类名，例如 `org.apache.nZcPC.HttpClientUtil`、`jmg.core.template.TomcatAgentTransformer`、`org.chabug.MyTransformer`、`self.HttpServletTransformer`，以及伪装成 `OAuthAgentHandler` 的类。
4. 用 `jad <className>` 反编译可疑 transformer，检查 `transform` 方法是否在向目标类插入命令执行/回显逻辑。
5. 通过 `vmtool` 调用 `sun.instrument.InstrumentationImpl#removeTransformer`，按类名过滤两份列表并逐一移除；同名多实例（如 javax/jakarta 双变体）需要循环移除，直到列表清零。
6. 还原被篡改类的字节码：对常见注入点执行 `dump`（内部触发 retransform），或用 `retransform` 重新加载。常见目标包括 `ApplicationFilterChain`、`StandardContextValve`、`ServletHandler`、`WebAppServletContext`、`HttpServlet.service` 及其容器版本变体。
7. 验证：transformer 列表只剩 Arthas 自身；带原触发头/参数的请求不再执行命令；业务页面正常返回。
8. JDK 9+ 若第 2 步报模块 `opens` 错误，改用 Unsafe 读取 `mTransformerManager`/`mRetransfomableTransformerManager`，卸载逻辑同样改为 Unsafe 访问。

## PoC

JDK 8 下读取 transformer 列表（OGNL 示意）：

```text
vmtool -l -1 --action getInstances --className sun.instrument.InstrumentationImpl \
  --express '#ins=instances[0],#tm1=#ins.mTransformerManager,#tm2=#ins.mRetransfomableTransformerManager,"normal="+#tm1.mTransformerList.length+",retransformable="+#tm2.mTransformerList.length'
```

按类名移除恶意 transformer（OGNL 伪代码，实际需按 Arthas OGNL 语法转换）：

```java
for (InstrumentationImpl ins : instances) {
    TransformerManager tm1 = ins.mTransformerManager;
    TransformerManager tm2 = ins.mRetransfomableTransformerManager;

    for (TransformerInfo ti : tm1.mTransformerList) {
        if (ti.mTransformer.getClass().getName().equals("恶意注入器类名")) {
            ins.removeTransformer(ti.mTransformer);
        }
    }
    for (TransformerInfo ti : tm2.mTransformerList) {
        if (ti.mTransformer.getClass().getName().equals("恶意注入器类名")) {
            ins.removeTransformer(ti.mTransformer);
        }
    }
}
```

JDK 9+ 用 Unsafe 绕过模块封装：

```java
InstrumentationImpl ins = getAllInstances(InstrumentationImpl.class)[0];
Class<?> uc = Class.forName("sun.misc.Unsafe");
Field uf = uc.getDeclaredField("theUnsafe");
uf.setAccessible(true);
Unsafe u = (Unsafe) uf.get(null);

Field f = ins.getClass().getDeclaredField("mTransformerManager");
long off = u.objectFieldOffset(f);
TransformerManager tm = (TransformerManager) u.getObject(ins, off);
```

还原字节码：

```text
# dump 内部会 addTransformer(ClassDumpTransformer) + retransformClasses + removeTransformer
dump org.apache.catalina.core.ApplicationFilterChain
dump org.apache.catalina.core.StandardContextValve
```

验证预期：

```text
# 卸载前
curl -H "User-Agent: QIIEpvLN" "http://target/?FFFsHHii=id"   -> uid=0(root)
# 卸载后
curl -H "User-Agent: QIIEpvLN" "http://target/?FFFsHHii=id"   -> 正常首页/业务响应，命令不执行
```

## 变体与关联

- 变体：redefine 型内存马没有 transformer 列表痕迹，需直接检查目标类字节码或对比磁盘原始 class；较少见，本文未实现自动查杀。
- 变体：JDK 9+ 模块限制下，Arthas 直接读取 `mTransformerManager` 失败，必须走 Unsafe；JDK 17 + Tomcat 10.1 实测可用。
- 变体：同一注入器存在 javax/jakarta 双实例或多个同名 transformer，单次 `removeTransformer` 只移除一个匹配项，需要循环直到清零。
- 变体：`dump` 还原依赖缓存字节；若此前发生过 `redefineClasses`，缓存可能不是最初原始字节，需结合磁盘原始 class 对比确认。
- 关联：Java ClassLoader/内存马相关的攻击卡描述注入与驻留；本卡描述应急侧从 `Instrumentation` 注册表发现并卸载。

## 检测与防御

- 检测：监控 JVM 动态 attach、`-javaagent` 启动参数、临时 agent jar 落地、`VirtualMachine.attach` 相关系统调用；非预期时间出现的 agent 进程/文件是强信号。
- 检测：定期枚举 `InstrumentationImpl` 的 transformer 列表，对未知类名、随机类名、伪装成 OAuth/Util 的类告警；结合 `jad` 查看 transform 逻辑。
- 检测：对比容器关键类（FilterChain、Valve、ServletHandler、HttpServlet）在内存中的字节码与磁盘原始 class；`dump` 产物哈希异常即可疑。
- 响应：先移除恶意 transformer，再还原字节码，最后验证触发请求失效；只还原字节码会留下可复用的注入器。
- 加固：限制 Arthas/jcmd/jattach 等诊断工具的生产可用性与访问权限；诊断端口仅本地/跳板机可达并强认证。
- 加固：JVM 启动加 `-XX:+DisableAttachMechanism`（评估业务影响）或限制 attach 用户；启用模块化时显式管理 `--add-opens`，不要为图方便全局开放。
- 加固：应用层对内存马常见注入点做完整性校验与启动基线比对；发现注入后按入侵事件排查初始入口（反序列化、表达式注入、文件上传、供应链）。
