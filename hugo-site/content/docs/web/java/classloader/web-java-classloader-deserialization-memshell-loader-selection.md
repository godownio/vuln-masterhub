---
id: web-java-classloader-deserialization-memshell-loader-selection
title: 反序列化打内存马的类加载原语选型：TemplatesImpl/Groovy 走构造器、BCEL 只走静态块
type: scenario
domain: web
path: web/java/classloader
technique: deserialization-memshell-loader-selection
tags:
- java
- deserialization
- classloader
- memory-shell
- templatesimpl
- bcel
- groovy
- bytecode
- jdk
cve: []
severity: high
confidence: medium
affected_versions: JDK 8u251 之前（BCEL ClassLoader 仍内置）；Groovy 2.4.15（原文依赖）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V236
  verified_at: '2026-11-07T09:30:44+08:00'
  notes: 已对照原文及全部 20 张图核对：TemplatesImpl getTransletInstance 第 559 行 getConstructor().newInstance()、BCEL test11 仅触发静态代码块、Groovy test12 同时触发静态块与构造器、ScriptEngine/EL/SpEL/gzip+Base64 变体与原文一致；BCEL 版本表述原文正文为 8u251 之前、导图标注 <=8u251，卡按正文；本机 JDK 8u381 rt.jar 已无 com.sun.org.apache.bcel.internal.util.ClassLoader.class（其余 BCEL 类仍在）。未验证点：原文为原理教程，未在真实反序列化目标打通完整内存马，未执行文中代码。
url: /docs/web/java/classloader/web-java-classloader-deserialization-memshell-loader-selection/
draft: false
kb_aliases:
- 反序列化内存马
- 无文件落地内存马
- TemplatesImpl 加载内存马
- BCEL ClassLoader 内存马
- GroovyClassLoader defineClass
- 构造器 vs 静态代码块
---

## 一句话结论

反序列化能打内存马的本质是“在运行期让程序加载任意字节码”；链尾可选 `TemplatesImpl`、BCEL `ClassLoader`、`GroovyClassLoader` 等现成 `defineClass` 入口。选型的关键差异是触发阶段：`TemplatesImpl.getTransletInstance()` 会 `getConstructor().newInstance()` 触发无参构造器，`GroovyClassLoader.defineClass(...).newInstance()` 也触发构造器，因此内存马核心逻辑可写在构造器；BCEL `Class.forName("$$BCEL$$...", true, new ClassLoader())` 只完成类加载与初始化，不实例化，核心逻辑必须写在静态代码块。

## 原理

- **Java 的动态性入口**：Java 源码必须先编译成 `.class` 字节码，但 JVM 允许在运行期通过 `ClassLoader.defineClass(name, bytes, off, len)` 把字节数组定义成类。反序列化链只要能调用某个可达的 `defineClass`（直接或间接），就能把内存马字节码送进目标 JVM，实现“无文件落地”。
- **类加载的三个阶段**：加载（读取字节码）→ 链接（验证/准备/解析）→ 初始化（执行静态变量赋值与静态代码块）。初始化只执行 `<clinit>`，不会调用构造器 `<init>`；构造器只在 `new`/`newInstance` 时执行。这是选型的核心。
- **TemplatesImpl**：JDK 自带 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`。调用链为 `getOutputProperties()` → `newTransformer()` → `getTransletInstance()` → `defineTransletClasses()` → `TransletClassLoader.defineClass()`；在 `getTransletInstance()` 第 559 行附近执行 `_class[_transletIndex].getConstructor().newInstance()`，因此会触发恶意类的无参构造器。内存马逻辑写在构造器即可；同时恶意类需继承 `AbstractTranslet` 并通过 `_bytecodes`/`_name`/`_tfactory` 字段布置。
- **BCEL ClassLoader**：JDK 8u251 之前内置 `com.sun.org.apache.bcel.internal.util.ClassLoader`。其 `loadClass` 检测类名以 `$$BCEL$$` 开头时，去掉前缀后 `Utility.decode` → `ClassParser.parse` → `defineClass` 返回 Class 对象；`Class.forName(name, true, loader)` 会初始化该类，因此只触发静态代码块，不触发构造器。若内存马逻辑写在构造器里，用 BCEL 加载不会执行；必须写在 `static {}` 块。
- **GroovyClassLoader**：`org.codehaus.groovy.control.CompilationUnit` 相关依赖中的 `GroovyClassLoader` 继承 `URLClassLoader`，无参构造器取 `Thread.currentThread().getContextClassLoader()`，并提供 `public defineClass(...)`。`new GroovyClassLoader().defineClass(name, bytes).newInstance()` 会先加载/初始化再实例化，静态块与构造器都会执行。
- **为什么反序列化链能用到它们**：CC/CB/fastjson 等链可以把 `TemplatesImpl` 作为 `Transformer` 的输出对象；fastjson 可通过 `@type` 直接实例化 `TemplatesImpl` 或 BCEL `ClassLoader`；Groovy 依赖存在时可通过相应 gadget/表达式调用其 `defineClass`。链本身只负责“到达 loader”，内存马能否驻留取决于 loader 的触发阶段与字节码内容。
- **脚本引擎/表达式路线**：`ScriptEngineManager.getEngineByName("js")`（Nashorn，JDK 8-14）或 EL/SpEL 可以先执行一段脚本，再在脚本里反射调用 `ClassLoader.defineClass` 并 `newInstance`；字节码过大时用 gzip + Base64 压缩，SpEL 的 `ReflectUtils.defineClass` 在 JDK17 下还要求恶意类与 `org.springframework.expression` 同包。该路线与上面的 loader 选型互补，不是本卡重点。

## 触发条件

- 目标存在可触发的反序列化/表达式注入 sink，且链能到达 `TemplatesImpl`、BCEL `ClassLoader`、`GroovyClassLoader` 或 `ScriptEngineManager` 之一。
- 目标 JDK/依赖满足：
  - `TemplatesImpl` 在 JDK 内（JDK 8+ 普遍存在；高版本受模块封装影响，需确认链可用）；
  - BCEL `ClassLoader` 仅在 JDK 8u251 之前内置；
  - `GroovyClassLoader` 需要 classpath 中存在 Groovy（原文依赖 `groovy-all 2.4.15`）；
  - Nashorn 仅在 JDK 8-14 内置，JDK 15 起移除。
- 攻击者能生成内存马字节码，并按 loader 的触发阶段把核心逻辑放到构造器或静态代码块。
- 目标未部署能拦截 `defineClass`/`TemplatesImpl`/`$$BCEL$$`/异常类加载的 RASP 或模块化限制。

## 利用步骤

1. **确认 sink 与可用 loader**：枚举目标依赖与 JDK 版本；优先 `TemplatesImpl`（JDK 自带），其次 BCEL（JDK < 8u251），再考虑 Groovy（有依赖）或 ScriptEngine/表达式。
2. **生成内存马字节码**：按目标容器（Tomcat/Spring 等）生成 Filter/Servlet/Listener/Valve 型内存马；对 `TemplatesImpl`，恶意类必须继承 `AbstractTranslet`。
3. **决定逻辑放置位置**：
   - `TemplatesImpl` / `GroovyClassLoader.newInstance()`：把注册内存马的逻辑放在无参构造器（也可同时放静态块）；
   - BCEL：把逻辑放在 `static {}` 块，因为没有实例化。
4. **接入反序列化链**：
   - `TemplatesImpl`：设置 `_bytecodes`、`_name`、`_tfactory`，用 CC/CB/fastjson 等链触发 `getOutputProperties()`/`newTransformer()`；
   - BCEL：`Repository.lookupClass(Shell.class)` → `"$$BCEL$$" + Utility.encode(bytes, true)` → `Class.forName(encode, true, new com.sun.org.apache.bcel.internal.util.ClassLoader())`；fastjson 不出网场景可把 BCEL ClassLoader 作为 `@type` 的加载器；
   - Groovy：`new GroovyClassLoader().defineClass(name, bytes).newInstance()`。
5. **验证触发阶段**：在恶意类静态块与构造器中分别打印标记，确认目标 loader 实际执行了哪一个；BCEL 只出现静态块标记即符合预期。
6. **验证内存马驻留**：请求触发路由/Filter，确认命令执行或回显；记录 loader 名称、类名与注册方式。

## PoC

原文 BCEL 测试代码：

```java
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;

JavaClass javaClass = Repository.lookupClass(test3.class);
String encode = "$$BCEL$$" + Utility.encode(javaClass.getBytes(), true);
System.out.println(encode);
Class.forName(encode, true, new ClassLoader());   // 只触发静态代码块
```

原文 Groovy 测试代码：

```java
import groovy.lang.GroovyClassLoader;
import java.nio.file.*;

byte[] bytes = Files.readAllBytes(Paths.get("test3.class"));
new GroovyClassLoader().defineClass("com.test.test3", bytes).newInstance();
// 静态代码块与构造函数都会触发
```

原文 `TemplatesImpl` 只给出调用链，未给完整 PoC：

```text
TemplatesImpl#getOutputProperties()
  -> TemplatesImpl#newTransformer()
  -> TemplatesImpl#getTransletInstance()
  -> TemplatesImpl#defineTransletClasses()
  -> TransletClassLoader#defineClass()
  -> _class[_transletIndex].getConstructor().newInstance()   // 触发无参构造器
```

内存马逻辑放置对照：

```text
TemplatesImpl / GroovyClassLoader.newInstance() -> 构造器（<init>）执行
BCEL Class.forName(name, true, loader)          -> 仅静态代码块（<clinit>）执行
```

## 变体与关联

- **变体：ScriptEngine/EL**。`"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval(...)`，在 JS 中 `getContextClassLoader()` + `defineClass` + `newInstance`；JDK 8-14 可用。
- **变体：SpEL + ReflectUtils**。`T(org.springframework.cglib.core.ReflectUtils).defineClass(className, Base64.decode(bytes), TCCL, null, ExpressionParser.class)`；JDK17 需恶意类与 `org.springframework.expression` 同包，大马用 gzip+Base64。已有专门卡覆盖受限模式下的反射绕过。
- **变体：BCEL + fastjson 不出网**。fastjson 把 BCEL `ClassLoader` 作为加载器，类名以 `$$BCEL$$` 传入，避免远程 JNDI 外联。
- **关联**：[[web-java-deser-fastjson-templatesimpl-batchupdate-rce]]（TemplatesImpl 在 fastjson 中的实际利用）、[[web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl]]（CC4 触发 TemplatesImpl）、[[web-java-rce-nashorn-bcel-jsp-webshell-av-bypass]]（Nashorn + BCEL 绕过静态查杀）、[[web-java-expression-spel-restricted-reflection-memshell]]（SpEL 受限模式 + ReflectUtils.defineClass 内存马）、[[web-java-classloader-jsp-memory-servlet-webshell]]（自定义 ClassLoader 注册内存 Servlet）。
- **边界**：原文是原理性教程，BCEL/Groovy 只做了本地 `test3.class` 打印验证，没有在真实反序列化目标上打通完整内存马；`TemplatesImpl` 仅给调用链，未给 PoC。实际利用需结合目标链、JDK 模块限制与容器类型验证，不能把本文当已打通的端到端案例。

## 检测与防御

- **输入检测**：请求/反序列化数据中出现 `$$BCEL$$`、`com.sun.org.apache.bcel.internal.util.ClassLoader`、`TemplatesImpl`、`_bytecodes`、`GroovyClassLoader`、`defineClass`、`getOutputProperties`/`newTransformer` 等组合。
- **类加载监控**：RASP/Agent 监控 `ClassLoader.defineClass` 的调用者与字节码来源，重点告警来自反序列化/表达式/脚本引擎的 defineClass；对 `TemplatesImpl`、BCEL ClassLoader、GroovyClassLoader 建立黑名单/告警。
- **依赖与 JDK**：升级到不再内置 BCEL ClassLoader 的 JDK（8u251+），移除不必要的 Groovy 依赖；JDK 15+ 无 Nashorn，减少脚本引擎入口。
- **隔离与最小权限**：反序列化入口使用白名单/类过滤（fastjson safeMode、Jackson 白名单），禁止不可信数据触发任意类加载；应用容器启用模块化/安全管理器并限制反射。
- **内存马排查**：检查异常的 Filter/Servlet/Listener/Valve 注册、`defineClass` 调用栈、类名与字节码来源；发现后重启并轮换凭据。
