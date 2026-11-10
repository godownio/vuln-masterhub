---
id: web-java-rce-beanshell-eval-method-map-preheat
title: 命令执行被 RASP/杀软拦截时改调 BeanShell Interpreter.eval：以 String[] 预热 method_map 消除 String/Reader 重载歧义
type: scenario
domain: web
path: web/java/rce
technique: beanshell-eval-reflection-overload-preheat-rasp-bypass
aliases:
- bsh.Interpreter.eval
- BeanShell 代码执行替代 Runtime.exec
- method_map 预热
- 反射重载方法选择
- RASP 命令执行拦截绕过
tags:
- java
- rce
- beanshell
- bsh
- rasp-bypass
- reflection
- code-execution
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:45:47+08:00'
  notes: 已对照原文核对：bsh.Interpreter 存在 eval(Reader)/eval(String) 两重载（截图）、数组参数使调度器按元素类型 getMethod(String.class) 并写入 method_map、第二包普通 String 命中缓存执行，原文两包请求及 C:\yonyou\home 目录回显截图佐证；标题 String[] 与 PoC Object[]{String} 等价（元素类型均为 String）；未验证点：BeanShell 脚本示例为卡内构造非原文原样，原文未给受影响版本
---

## 一句话结论

当目标机器不出网且杀软/RASP 拦截 `Runtime.exec`/`ProcessBuilder` 等命令执行函数时，可通过同一个“反射任意方法调用”原语改调 classpath 里的 BeanShell `bsh.Interpreter.eval`，在 JVM 内执行 Java 代码（文件读写、目录列举、反射调用等）；由于 `eval` 同时存在 `eval(String)` 与 `eval(Reader)` 两个重载，而反射调度器冷启动时用 `getMethod(name, Object.class)` 匹配失败后会按方法名取第一个同名方法，直接传 String 可能错误绑定到 `eval(Reader)`——先发一个 `Object[]{脚本}` 数组包，让调度器按元素类型 `getMethod("eval", String.class)` 并把 `eval(String)` 写入静态 `method_map` 缓存，第二个包再传普通 String 即可稳定命中 `eval(String)`。

## 原理

- **为什么换 sink**：`Runtime.exec`/`ProcessBuilder` 是杀软与 RASP 的重点 hook 对象；BeanShell 是纯 Java 实现的解释器，`Interpreter.eval(String)` 在 JVM 进程内求值 Java 语句，不必然经过被 hook 的命令执行 API。代码执行能力可替代命令执行完成读文件、列目录、加载类、反射调用等动作；即使最终仍要起进程，也可换用未被 hook 的调用路径。
- **为什么重载会出问题**：`bsh.Interpreter` 至少有 `eval(Reader)` 与 `eval(String)` 两个单参方法。反射调度器冷启动时先构造 `new Class[]{Object.class}` 去 `getMethod("eval", Object.class)`，两个重载都不匹配，抛 `NoSuchMethodException`；随后遍历 `getMethods()`，只按方法名 `eval` 相等取第一个命中，**完全不比较参数类型**。若先命中的是 `eval(Reader)`，再以 String 参数 `invoke` 会类型不匹配或抛异常；`getMethods()` 顺序不保证，利用结果不稳定。
- **为什么数组参数能定点**：调度器在 `paramter` 为数组时会遍历元素、用每个元素的 `getClass()` 构造 `paramClzs`，再 `getMethod(methodName, paramClzs)`。传 `Object[]{ "脚本" }` 得到 `paramClzs=[String.class]`，准确取到 `eval(String)`；该方法以 `类名:方法名:参数个数`（此处 `bsh.Interpreter:eval:1`）为 key 写入静态 `method_map`。
- **为什么第二个包稳定**：第二个包传普通 String，参数个数仍为 1，key 相同；调度器先查 `map_method` 直接命中缓存的 `eval(String)`，跳过重载解析，稳定执行脚本。数组长度为 1 时首个包也会以 `arr[0]` 调用一次 `eval(String)`，所以首个包可放无害脚本预热，第二个包再放真实 payload。
- **通用性**：任何“类名+方法名+参数个数”做 key 的反射调度器/静态方法缓存，都可用“数组参数预热、普通参数复用”的手法固定重载；反之也可能是攻击面（缓存污染）。

## 触发条件

- 存在可控制类名、方法名与参数对象的反射调用入口（如反序列化后的业务调度器、定时任务 invokeTarget、表达式/脚本网关）。
- classpath 中存在 BeanShell（`bsh` 包，`bsh.Interpreter`），目标未移除或沙箱化。
- 命令执行函数被 RASP/杀软拦截或机器不出网，需要进程内代码执行。
- 调度器使用静态 map 以“类名:方法名:参数个数”缓存 Method，且未对可用类/方法做白名单。

## 利用步骤

1. 确认反射调度入口可用，并能指定类 `bsh.Interpreter`、方法 `eval`、参数对象。
2. 第一个包把 `paramter` 设为 `Object[]{ "<无害脚本>" }`（数组长度 1）：调度器按元素类型解析出 `eval(String)`，写入 `method_map`，并执行一次无害脚本验证可用。
3. 第二个包把 `paramter` 设为普通 String 的真实 BeanShell 脚本，命中缓存直接执行；需要返回值时依赖调度器把方法结果序列化/回显。
4. 脚本内按环境选择动作：读文件、列目录、反射调用未被 hook 的 API、加载字节码等；确认效果后停止，避免落地持久化文件。
5. 若目标不存在 `eval(String)` 或已被移除，可改用 `eval(Reader)` 重载，直接传 `new StringReader(script)`（但需确保兜底命中 Reader 版本）。

## PoC

```java
// 第一个包：数组参数预热，精确取到 eval(String) 并写入 method_map
oos.writeObject("bsh.Interpreter");
oos.writeObject("eval");
oos.writeObject(new Object[]{ "print(\"warmup\");" }); // 元素类型为 String
oos.writeObject("zh_CN");
oos.writeObject(null);

// 第二个包：普通 String 参数，key 相同（bsh.Interpreter:eval:1）
// 调度器命中缓存的 eval(String)，不再做重载解析
oos.writeObject("bsh.Interpreter");
oos.writeObject("eval");
oos.writeObject("<真实 BeanShell 脚本>");
oos.writeObject("zh_CN");
oos.writeObject(null);
```

BeanShell 脚本示例（按需替换，仅为验证思路）：

```java
// 列目录 / 读文件等进程内动作，避免直接调用被 hook 的 Runtime.exec
print(new java.io.File("C:\\yonyou\\home").list().length);
```

说明：两个包需按目标调度器的序列化顺序与协议封装（如 GZIP + Java 序列化）。原文以数组预热后第二个包普通 String 参数的方式完成 `eval` 调用并回显执行结果。

## 变体与关联

- 变体（其他重载）：`eval(String)`/`eval(Reader)` 之外，任何同名不同参方法都可用数组元素类型定点选择；也可用数组长度控制 `invoke` 时传单元素还是整组参数。
- 变体（其他脚本引擎）：Nashorn `ScriptEngine.eval`、Groovy、JEXL 等，只要 classpath 存在且有无参构造/静态入口。
- 变体（RASP 绕过思路）：进程内反射调用 `ProcessImpl` 构造器、FFM 直调 libc、线程上下文切换等（见关联卡），与本卡同属“避开被 hook 的命令执行入口”。
- 关联：[[web-java-deserialization-ufida-zior-actionexecutor-reflection]]（本卡的反射调度器载体与 method_map 机制）、[[web-java-rce-oa-beanshell-interpreter-eval]]（BeanShell eval 作为通用代码执行 sink 的其它入口）、[[web-java-rce-processimpl-constructor-reflect-exec]]、[[web-java-rce-ffm-native-system-rasp-bypass]]、[[web-java-rce-rasp-http-thread-context-new-thread-bypass]]（其它 RASP 命令执行拦截绕过）。

## 检测与防御

- 检测：反序列化/请求体中出现 `bsh.Interpreter`、`eval`、`StringReader`、`bsh.` 类名；同一入口短时间内出现“数组参数包 + 普通参数包”且类名/方法名相同的成对请求；JVM 中 `Interpreter.eval` 调用与异常 `NoSuchMethodException` 集中在同名方法。
- 检测：RASP 只 hook `Runtime.exec`/`ProcessBuilder` 不够，应同时监控脚本引擎求值（BeanShell/Nashorn/Groovy/JEXL）、反射 `Method.invoke`、`Class.forName` 与文件/网络 API。
- 防御：移除不必要的 BeanShell/脚本引擎依赖与反射调度入口；对反射调用做类名/方法名白名单；反序列化入口加对象过滤器；对脚本引擎做沙箱或禁用。
