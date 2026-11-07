---
id: web-java-deser-jdk-xslt-process-main-chain
title: JDK8 原生链：SwingLazyValue 调 Process._main 加载落地 XSLT 注入内存马
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: jdk-native-xslt-process-main-chain
tags:
- java
- deserialization
- jdk-only
- xslt
- swinglazyvalue
- uidefaults
- pkcs9attributes
- memshell
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T01:59:35+08:00'
  notes: 已对照原文与14张图片核对：图07-12 逐段展示 PKCS9Attributes.toString→UIDefaults.get→SwingLazyValue.createValue→JavaWrapper/Process._main；图12确认 Process._main 用 newTemplates(new StreamSource(xslFileName)) 加载 XSLT；图13 Java Chains 的 XsltOnlyJdk 一键链；图14 目标 JDK 1.8.0_202 且工具已连接，原文称 sleep 验证成功、Listener 内存马注入成功。卡内把 BCEL 仅限 JDK 类的限制、JDK11+ SwingLazyValue 移除、字段/静态方法 sink 均如实记录，confidence medium 合适。原文未给受影响版本区间，未设 versions；PoC未本机执行；frontmatter无sources/source_url。
url: /docs/web/java/deserialization/jdk/web-java-deser-jdk-xslt-process-main-chain/
draft: false
kb_aliases:
- XSLT 落地链
- Process._main XSLT
- SwingLazyValue XSLT
- PKCS9Attributes toString 链
- Hessian XSLT 内存马
- JavaUtils writeBytesToFilename
---

## 一句话结论

在 JDK8 且无第三方 gadget 依赖时，可用 `PKCS9Attributes.toString` 触发 `UIDefaults.get` → `SwingLazyValue.createValue` 调任意静态方法：先 `JavaUtils.writeBytesToFilename` 落地恶意 XSLT，再 `Process._main` 编译加载该 XSLT，最终执行 Java 代码并注入内存马。

## 原理

- `PKCS9Attributes.toString()` 会遍历其内部 `attributes` 表并调用 `getAttribute` → `attributes.get(key)`；若 `attributes` 是 `javax.swing.UIDefaults`，则 `UIDefaults.get` 取到 `LazyValue` 时会调用 `createValue(this)`。
- `sun.swing.SwingLazyValue.createValue()` 用 Bootstrap ClassLoader `Class.forName(className)` 加载类，按参数类型 `getMethod(methodName, ...)`，`makeAccessible` 后 `method.invoke(null, args)`。因此它能调用任意 **JDK 类的 public static 方法**。
- 触发 `PKCS9Attributes.toString()` 的方式之一在 Hessian 输入侧：`Hessian2Input` 读取期望为字符串的位置时读到对象，异常拼接 `"... (" + obj + ")"` 会隐式调用该对象的 `toString`。原文把这套 toString 触发称为 CVE-2021-43297 触发点。
- 两条静态方法 sink：
  - **BCEL 加载**：`com.sun.org.apache.bcel.internal.util.JavaWrapper._main` → `runMain` → `loader.loadClass(class_name)` → 反射调用目标类 `_main(String[])`。类名可用 `$$BCEL$$...` 形式携带字节码；但该加载器只能加载 JDK 自身包内的类，无法加载攻击者自定义的内存马类。
  - **XSLT 加载（实际采用）**：`com.sun.org.apache.xalan.internal.xslt.Process._main` 调用 `tfactory.newTemplates(new StreamSource(xslFileName))`，编译并执行指定 XSLT 文件。先用 `com.sun.org.apache.xml.internal.security.utils.JavaUtils.writeBytesToFilename(filename, bytes)` 把恶意 XSLT 写到可写路径，再让 `Process._main` 加载它；XSLT 内通过 Xalan 的 Java 扩展函数执行任意 Java 代码（命令执行、注册 Listener 内存马）。
- 两条 sink 都来自同一 `SwingLazyValue` 原语，区别只在于最终调用哪个 public static 方法；整个过程不依赖 Spring、Groovy、Rome 等第三方链，也不需要目标出网。

## 触发条件

- 目标为 JDK8（`sun.swing.SwingLazyValue` 在 JDK 11+ 已移除；JDK 8u202 实测可用）；JDK 内部 Xalan（`com.sun.org.apache.xalan.internal.xslt.Process`）存在。
- 存在可控的反序列化入口（如 XXL-Job Admin `/api` 的 Hessian 入口），且未对 `PKCS9Attributes`、`UIDefaults`、`SwingLazyValue`、`Process`、`JavaUtils` 做类过滤。
- 进程对某个目录有写权限（可用 `/tmp` 等），且 XSLT 编译未被禁用。
- 无需目标出网。

## 利用步骤

1. 确认入口可反序列化，并确认目标 JDK 为 8（版本信息、错误页、`java.version`）。
2. 构造 `UIDefaults`：放入两个 key，对应 `SwingLazyValue` 分别指向 `JavaUtils.writeBytesToFilename` 与 `Process._main`。
3. 把该 `UIDefaults` 作为 `PKCS9Attributes` 的 `attributes` 字段，构造反序列化对象图。
4. 通过 Hessian 输入侧的“期望字符串却读到对象”异常路径触发 `PKCS9Attributes.toString()`，依次执行写文件与 XSLT 加载。顺序敏感时可拆成两次请求：先写 XSLT，再加载。
5. 先用 `sleep`/延时命令验证链路，再在 XSLT 中执行内存马注入逻辑（原文最终用 Listener 型成功，Tomcat Filter 型未打通）。
6. 通过内存马连接或命令回显确认权限。

## PoC

最小静态方法调用结构（不含 Hessian 序列化与完整 XSLT 内容）：

```java
UIDefaults ui = new UIDefaults();

// 1) 落地恶意 XSLT
ui.put("write", new sun.swing.SwingLazyValue(
    "com.sun.org.apache.xml.internal.security.utils.JavaUtils",
    "writeBytesToFilename",
    new Object[]{"/tmp/evil.xsl", xslBytes}));

// 2) 让 Xalan 编译加载该 XSLT
ui.put("load", new sun.swing.SwingLazyValue(
    "com.sun.org.apache.xalan.internal.xslt.Process",
    "_main",
    new Object[]{new String[]{"/tmp/evil.xsl"}}));

// 3) 把 ui 放入 PKCS9Attributes.attributes，再让 toString 被触发
```

等价的 BCEL 变体（仅能加载 JDK 内的类，原文判定无法注入自定义内存马）：

```java
new sun.swing.SwingLazyValue(
    "com.sun.org.apache.bcel.internal.util.JavaWrapper",
    "_main",
    new Object[]{new String[]{"$$BCEL$$..."}});
```

原文用 Java Chains 的 `XSLT Only Jdk (XSLT 整合链)` 一键生成，先以 sleep 验证延时成功，再注入 Listener 型内存马；未给出完整 XSLT 与序列化字节。

## 变体与关联

- `ProxyLazyValue` 是 `SwingLazyValue` 的跨版本替代（JDK 11+ 仍可用），可作为 `UIDefaults.get` 的另一个 LazyValue 实现。
- 静态方法 sink 不限于 XSLT：`System.load` 加载本地库、`ServerManagerImpl` 的 `Runtime.exec`、`ClassPathXmlApplicationContext` 加载 XML 等均可复用同一原语。
- 关联 Hessian JDK-only 链卡片（机制与触发点总览）、XXL-Job `/api` 入口卡片。
- 与外部 Xalan `TemplatesImpl` 链不同：本条不依赖 `TemplatesImpl._bytecodes` 反射，而是利用 JDK 内置 Xalan 的命令行入口编译 XSLT。

## 检测与防御

- 反序列化允许列表拒绝 `com.sun.org.apache.xml.internal.security.utils.JavaUtils`、`com.sun.org.apache.xalan.internal.xslt.Process`、`com.sun.org.apache.bcel.internal.util.JavaWrapper`、`sun.swing.SwingLazyValue`、`javax.swing.UIDefaults`、`PKCS9Attributes` 等类。
- 监控 Hessian 异常信息中 `expected ... at 0x` 且携带对象 `toString` 的日志；监控进程写入 `.xsl` 文件后立即被 XSLT 编译的行为。
- 限制应用写权限与临时目录执行；关闭不必要的 XSLT 扩展函数（`TransformerFactory` 的 extension function 开关），并对 XSLT 来源做白名单。
- 升级 JDK 只能移除 `SwingLazyValue`（JDK 11+），`ProxyLazyValue` 仍可复用同一路径，不能替代类允许列表。
- 根本措施是消除不可信 Hessian/Java 反序列化入口并做入口鉴权。
