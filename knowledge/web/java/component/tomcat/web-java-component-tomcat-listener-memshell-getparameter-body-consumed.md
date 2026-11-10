---
id: web-java-component-tomcat-listener-memshell-getparameter-body-consumed
title: Listener 内存马调用 request.getParameter 提前耗尽 CoyoteInputStream：Jersey MultivaluedMap 收不到表单参数，改用 URI/User-Agent 做 gate
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-listener-memshell-getparameter-body-consumption
aliases:
- 内存马参数获取错误
- request.getParameter 消耗请求体
- CoyoteInputStream 只能读一次
- Jersey MultivaluedMap 参数为空
- readPostBodyFully
- Listener 内存马接口失效
tags:
- java
- tomcat
- memshell
- listener
- jersey
- servlet
- request-body
- coyoteinputstream
- compatibility
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T11:32:11+08:00'
  notes: 已对照原文与图01-09核对：正常与注入后 formData size 1→0、request.jsp new AesBase64TomcatListenerShell、run() 内 getParameter(request,password)、readPostBodyFully/getStream()=CoyoteInputStream、ReaderWriter.readFromAsString 同一流，均与卡片一致；触发条件与 URI/UA 修复、检测部分为原文/补充合理归纳。未实际执行 PoC；原文未给受影响版本，未设 affected_versions。
---

## 一句话结论

Tomcat 的请求体 `CoyoteInputStream` 只能读一次：Listener/Filter 型内存马在请求入口调用 `request.getParameter()` 时，会经 `Request#readPostBodyFully` 把 `application/x-www-form-urlencoded` body 读空并缓存到参数表；随后 Jersey 通过 `ReaderWriter#readFromAsString` 从同一个 `CoyoteInputStream` 读取表单，只能得到空的 `MultivaluedMap`，导致原有接口参数全部丢失。把内存马的 gate 改为 URI、User-Agent 等非 body 来源即可避免。

## 原理

- **请求体一次性**：Servlet 的 `getInputStream()`/`getReader()` 底层是 Tomcat 的 `CoyoteInputStream`，数据只能顺序读取一次；读完后流指针到末尾，后续读取得到 EOF/空。
- **getParameter 会读 body**：`org.apache.catalina.connector.Request#getParameter` 在 `Content-Type: application/x-www-form-urlencoded`/multipart 时解析请求参数，调用 `readPostBodyFully(byte[] body, int len)`，其中 `this.getStream().read(body, offset, len - offset)` 把 body 从 `CoyoteInputStream` 读出；参数被缓存进 `Request` 的参数表。
- **Jersey 也读同一流**：Jersey 的 form 参数注入使用 `MultivaluedMap<String,String>`，内部 `org.glassfish.jersey.message.internal.ReaderWriter#readFromAsString` 用 `InputStreamReader` 包装的 `CoyoteInputStream` 读取表单文本（调试可见 `input = (CoyoteInputStream@...)`，与 `request.getStream()` 是同一个对象）。
- **内存马为什么触发**：Listener 内存在每个请求的 `requestInitialized`/`requestDestroyed` 中执行，通常会按 `request.getParameter("<password>")` 判断是否是攻击请求并解密 payload；这一步先于 Jersey 的参数绑定，读空 body。
- **为什么日志/业务表现是“参数为空”**：Jersey 的 `formData` 大小为 0，接口逻辑拿不到任何字段；调试断点会同时看到 `readPostBodyFully` 与 `readFromAsString` 指向同一个 `CoyoteInputStream`。
- **解决思路**：内存马 gate 不依赖 body —— 用 `request.getRequestURI()`、`User-Agent`、自定义 Header、Cookie 等；若确实需要 body，可先缓存/包装（`ContentCachingRequestWrapper` 等）再交给后续框架，但实现复杂且易留痕。

## 触发条件

- 目标为 Tomcat（或行为一致的 Servlet 容器），注入 Listener/Filter 型内存马，且内存马在入口调用 `request.getParameter` 读取 body。
- 业务接口使用 Jersey/JAX-RS `MultivaluedMap` 或任何在内存马之后才读取原始 body 的框架（Spring `@RequestBody`、Servlet `getInputStream` 等同样受影响）。
- 请求为 `application/x-www-form-urlencoded`（或 multipart）等需要容器解析 body 的类型。
- 触发只在“同一请求同时经过内存马 gate 与业务参数解析”时出现；仅 GET query 参数不受影响（query 在 URL 中，不走 body 流）。

## 利用步骤（复现/验证）

1. 搭建 SpringBoot MVC + Jersey：`@POST @Path("/demo") @Consumes("application/x-www-form-urlencoded") demo(MultivaluedMap<String,String> formData)`；正常 POST `map=hello` 应看到 `formData.size()==1`。
2. 通过 JSP（如 `request.jsp` 中 `new AesBase64TomcatListenerShell()`）注入 Listener 内存马，其 `run()` 用 `getParameter(request, password)` 读取并判断 payload。
3. 再发同一请求，观察 `formData.size()==0`、接口逻辑参数为空。
4. 在 `Request#readPostBodyFully` 与 `ReaderWriter#readFromAsString` 下断点，确认两者读取的是同一个 `CoyoteInputStream`。
5. 修改内存马：把 gate 改成 `request.getRequestURI()` 或 `User-Agent` 判断，重新验证业务接口参数恢复。

## PoC

Jersey 接口（原文）：

```java
@Path("/")
public class JerseyMultiValueMapController {
    @POST
    @Path("/demo")
    @Consumes("application/x-www-form-urlencoded")
    public Response demo(MultivaluedMap<String, String> formData) {
        formData.forEach((key, value) -> System.out.println("Key: " + key + ", Value: " + value));
        return Response.ok("Processed data").build();
    }
}
```

Listener 内存马中导致问题的 gate（原文）：

```java
private void run(Object servletRequestEvent) {
    Object request = invokeMethod(servletRequestEvent, "getServletRequest");
    String contentType = getContentType(request);
    if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
        String value = getParameter(request, password); // 读取 body，耗尽 CoyoteInputStream
        if (value != null) {
            byte[] data = base64Decode(value);
            data = aes(data, key, false);
            // ... defineClass 加载 payload
        }
    }
}
```

修复思路：

```java
String uri = request.getRequestURI();   // 或 User-Agent / Header
if (uri != null && uri.contains("/gate-path")) {
    // 处理内存马请求，不再调用 getParameter
}
```

## 变体与关联

- **同类内存马**：Tomcat Listener 内存马注入方式见 [[web-java-component-tomcat-listener-memshell]]；Filter 型、Agent 型内存马在入口读 body 也会有同样问题。
- **框架差异**：Jersey/JAX-RS 用 `MultivaluedMap`；Spring MVC `@RequestBody` 通过 `HttpMessageConverter` 读 `InputStream`；Servlet 应用直接 `getInputStream()`——只要在内存马之后读 body 都会受影响。
- **缓解**：`ContentCachingRequestWrapper`/自定义可重复读 Request 包装器可缓存 body，但需在读取前包装并注意内存/大文件风险；内存马场景更推荐无 body 的 gate。
- **边界**：GET/query 参数、请求头、URI 不受影响；若内存马只解析 `application/json` 且业务同为 JSON，同样会耗尽 body，需按目标框架验证。

## 检测与防御

- **红队/武器化**：内存马 gate 用 URI/UA/Header；上线前对业务接口做回归（表单、JSON body 均测），避免“注入成功但业务全挂”。
- **蓝队检测**：内存马扫描（如 tomcat_memshell_scanner 的 Listener 列表检查，dump 无磁盘 class 的 `com.sun.proxy.$Proxy`）；关注请求参数为空但 body 非空的异常；结合 JVM 类加载/Listener 列表审计。
- **防御**：升级容器、限制 JSP 上传/执行、RASP 监控 `addApplicationEventListener`/`defineClass` 等内存马特征；对业务接口做参数完整性监控。
