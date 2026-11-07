---
id: web-java-classloader-sealed-package-type-injection
title: 自定义 ClassLoader 缺失 Sealed Package 校验导致包内类型注入
type: scenario
domain: web
path: web/java/classloader
technique: classloader-sealed-package-type-injection
tags:
- java
- classloader
- sealed-package
- package-private
- defineclass
- jar
- access-control
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:36:17+08:00'
  notes: 已对照原文与 16 张截图核对：LooseJarLoader 未按 Manifest 调用 definePackage(sealBase)、包 sealed=false、同加载器跨 JAR 注入类可直接调用包级私有方法；URLClassLoader/FixedJarLoader 对照组 sealed=true 且拒绝；同 JAR 来源一致允许，均与原文一致。未独立编译复现。
url: /docs/web/java/classloader/web-java-classloader-sealed-package-type-injection/
draft: false
kb_aliases:
- Sealed Package 绕过
- 包内类型注入
- 自定义 ClassLoader 封闭包失效
- definePackage sealBase 缺失
---

## 一句话结论

自定义 `ClassLoader` 若只读取 JAR 中的 `.class` 字节并直接 `defineClass`，既不读取 Manifest、也不在定义前用 `definePackage(..., sealBase)` 记录封闭来源，JAR 中声明的 `Sealed: true` 会在运行时退化为普通包；此时外部 JAR 里的同包名类只要由同一个加载器定义，就能进入同一运行时包，直接访问包级私有类、方法或字段，无需反射或 `setAccessible(true)`。

## 原理

- Java 包级访问控制由“运行时包”决定：`运行时包 = 包名 + 定义该类的 ClassLoader 实例`。两个类只有包名相同且定义加载器是同一个对象，才能互相访问包级私有成员。
- `URLClassLoader` 等标准加载器在定义类前会读取 JAR Manifest：解析 `Sealed` 属性，调用 `definePackage(pkgName, ..., sealBase)` 把包绑定到 JAR 来源，再调用 `defineClass`。之后来自其他来源的同包类会被 `SecurityException` 拒绝。
- 自定义加载器（插件、热更新、脚本桥接、内存字节码加载）常直接 `readClassBytes` + `defineClass`。`defineClass` 本身不会读取 Manifest，也不会自动补充封闭包校验；若它用 `definePackage(pkg, ..., null)` 创建了未封闭包，Manifest 中的 `Sealed: true` 就完全失效。
- 失效后，攻击者把同包名的类放进另一个 JAR，交给同一个自定义加载器定义。两个类落在同一运行时包，攻击者类可直接 `invokestatic` 调用目标包级私有方法、访问包级私有字段或实例化包级私有类。
- sealed package 限制的是“来源一致性”，不是“同一来源内不能有多个同包类”。把核心类和注入类放进同一个封闭 JAR，仍然允许访问；跨 JAR 才被拒绝。
- 包级私有不是安全边界：它适合表达模块内部协作，不能用于隔离不可信代码。只要不可信字节码能由同一加载器定义到同名包，封装假设就会失效。

## 触发条件

- 目标使用自定义 `ClassLoader` 从多个 JAR/字节源加载类，且同一个包可能由多个来源提供。
- 受保护 JAR 的 Manifest 声明了 `Sealed: true`（主属性或包条目属性），但加载器没有解析/执行该语义。
- 目标包中存在包级私有类、方法或字段，且其访问具有安全意义（内部 token、管理接口、状态修改等）。
- 攻击者能让自己的类/JAR 被同一个自定义加载器加载（插件上传、扩展目录、脚本桥接、热更新、反序列化/字节码入口等）。
- 注入类有可执行入口（插件入口、ServiceLoader、脚本调用、反射调用等），否则即使定义成功也不会自动执行。

## 利用步骤

1. 确认目标使用自定义加载器，且 `findClass`/`loadClass` 路径直接 `defineClass`，没有 `definePackage(..., sealBase)` 或 Manifest 解析。
2. 找到受保护 JAR 中声明 `Sealed: true` 的包，以及包级私有的目标类/方法/字段。
3. 构造同包名注入类，直接调用包级私有成员；编译时把受保护 JAR 放入 classpath 即可通过编译（编译期只检查包名，不检查运行时来源）。
4. 将注入类打包成独立 JAR，通过插件/扩展/上传等入口交给同一个自定义加载器。
5. 先让加载器定义受保护包中的类（使包创建为未封闭），再触发注入类加载；观察 `getPackage().isSealed()` 为 `false`，注入类调用成功。
6. 对照验证：同一场景下 `URLClassLoader` 或修复后的加载器应显示 `isSealed()=true` 并拒绝跨 JAR 的同包类；同一 JAR 内应允许。

## PoC

```java
// 缺陷加载器：只创建未封闭包，再 defineClass
protected Class<?> findClass(String name) throws ClassNotFoundException {
    byte[] bytes = readClassBytes(jar, name.replace('.', '/') + ".class");
    int pos = name.lastIndexOf('.');
    String pkg = name.substring(0, pos);
    if (getDefinedPackage(pkg) == null) {
        definePackage(pkg, null, null, null, null, null, null, null); // sealBase=null
    }
    return defineClass(name, bytes, 0, bytes.length);
}
```

```java
// 注入类：同包名，直接调用包级私有方法（无反射）
package com.acme.sealed;

public final class Injected {
    public static String steal() {
        return "Injected=" + PackageSecret.read(); // PackageSecret 与 read() 均非 public
    }
}
```

```java
// 修复：defineClass 前读取 Manifest，按来源定义/校验 Package
Package existing = getDefinedPackage(pkg);
URL sealBase = jar.toUri().toURL();
boolean sealed = isSealedByManifest(className, manifest);

if (existing == null) {
    definePackage(pkg, null, null, null, null, null, null,
        sealed ? sealBase : null);
    return;
}
if (existing.isSealed() && !existing.isSealed(sealBase)) {
    throw new SecurityException("sealing violation: package " + pkg + " is sealed");
}
if (!existing.isSealed() && sealed) {
    throw new SecurityException("sealing violation: package " + pkg + " was already loaded as unsealed");
}
```

```text
# 预期对照
URLClassLoader / 不同 JAR : package sealed=true  -> SecurityException（拒绝）
LooseJarLoader / 不同 JAR : package sealed=false -> Injected 执行成功
FixedJarLoader / 不同 JAR : package sealed=true  -> SecurityException（拒绝）
同 JAR（URL/Fixed）        : package sealed=true  -> Injected 执行成功（同来源允许）
```

说明：PoC 为最小结构，`isSealedByManifest` 需同时检查 Manifest 主属性与包条目属性（包条目优先）；未在目标环境执行。

## 变体与关联

- 变体：加载器完全不调用 `definePackage`，由 JVM 在 `defineClass` 时隐式创建未封闭包，效果相同。
- 变体：包条目属性 `Name: com/acme/sealed/` + `Sealed: true` 可覆盖主属性；修复逻辑必须按包条目优先解析。
- 变体：同一 JAR 内合并核心类与注入类仍可访问（来源一致），说明 sealed package 不是“禁止同包多类”。
- 关联：[[web-java-classloader-jsp-memory-servlet-webshell]]（自定义 ClassLoader/defineClass 的内存马用法）；[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]（Unsafe 定义匿名类的另一种类定义入口）；[[web-java-classloader-tccl-nested-jar-type-loading]]（类加载器选择对类型解析的影响）。
- 关联：[[defense-hardening-jar-signature-repackage-verification]]（JAR Manifest/签名完整性，与 sealed package 同属 JAR 元数据约束，但目的不同）。

## 检测与防御

- 检测：代码审计所有继承 `ClassLoader` 并覆写 `findClass`/`loadClass` 的实现，搜索 `defineClass` 前是否调用 `definePackage` 且传入非 null 的 `sealBase`；搜索是否读取 Manifest 的 `Sealed` 属性。
- 检测：运行期对关键包断言 `getPackage().isSealed()` 为 true；对同包多来源加载记录告警。
- 防御：在 `defineClass` 前读取类来源 JAR 的 Manifest，按包条目优先解析 `Sealed`，用 `definePackage(..., sealBase)` 绑定来源；包已存在时校验 `isSealed(sealBase)`，拒绝跨来源混入。
- 防御：若加载器不支持 sealed package，发现 Manifest 含 `Sealed: true` 时直接拒绝加载，或禁止多个 JAR 定义同一包名。
- 防御：不要把包级私有当作安全边界；对不可信插件/代码使用独立 ClassLoader（不同运行时包）、进程/容器隔离、权限最小化。
- 防御：插件/扩展目录做签名与来源校验，限制不可信 JAR 进入同一加载器。
