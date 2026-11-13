---
id: web-java-component-tomcat-webappclassloader-getresources-null-context
title: Tomcat 8.5.78+ WebappClassLoaderBase#getResources() 恒返回 null：TCCL 取 StandardContext 的内存马注入路径失效与版本边界
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-webappclassloader-getresources-version-boundary
aliases:
- getResources 返回 null
- WebappClassLoaderBase 获取 context 失败
- TCCL 取 StandardContext
- Tomcat 8.5.78 内存马不生效
- unable to deserialize argument byte array
- Filter 内存马 NPE clinit
tags:
- java
- tomcat
- memshell
- standardcontext
- webappclassloader
- version-compatibility
- troubleshooting
- filter
cve: []
affected_versions: Tomcat 8.5.78 及以后（8.5 分支）getResources() 恒返回 null；原文实测 8.5.37/8.5.60/8.5.70/8.5.77 可用，8.5.78/8.5.79/8.5.81 不可用
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V612
  verified_at: '2026-11-12T19:48:17+08:00'
  notes: 已对照原文全文与14张图核对：图10/14 确认 Tomcat 8.5.79 WebappClassLoaderBase#getResources() 被@Deprecated并return null，图12 确认8.5.50 return this.resources，图09/11 确认静态块取context处NPE经TemplatesImpl.getTransletInstance包装为Shiro Unable to deserialize argument byte array；分界点8.5.78及实测清单（8.5.37/60/70/77可，8.5.78/79/81不可）为原文明确表述，affected_versions一致。与web-java-deserialization-jndi-tomcat-filter-memshell、dynamic-filter-memshell不同链：前者仅用反射resources字段绕过并在验证备注提及Tomcat9，本卡专述8.5.78版本边界与失败排查。未验证点：反射resources字段绕过为原文外补充、未本机实测；嵌入式容器差异未实测。
---

## 一句话结论

网上广泛复制的一段内存马取 context 代码 `((WebappClassLoaderBase) Thread.currentThread().getContextClassLoader()).getResources().getContext()` 只在 Tomcat 8.5.78 之前有效：从 8.5.78 起 `WebappClassLoaderBase#getResources()` 被标记 `@Deprecated` 并直接 `return null`，在静态块/构造器中调用即空指针，导致 Filter 内存马注入失败；外层看到的 `Unable to deserialize argument byte array` 只是 Shiro 的包装报错，根因是恶意类 `<clinit>` 里的 NPE，选型时必须先确认 Tomcat 8.5 小版本 < 8.5.78 或改用反射 `resources` 字段等替代路径。

## 原理

- **这段代码为什么流行**：非 JSP 型内存马（反序列化、JNDI 等触发）执行时拿不到 `HttpServletRequest`，最常见的替代是从线程上下文类加载器取容器内部对象。Tomcat 的 Web 应用 TCCL 是 `WebappClassLoaderBase`，它持有 `resources` 字段（`WebResourceRoot`，通常为 `StandardRoot`），`StandardRoot.getContext()` 返回 `StandardContext`——动态注册 Filter/Servlet/Listener 内存马的入口。旧版本里最短写法就是 `getResources().getContext()`。
- **8.5.78 的破坏性变更**：该版本的 `WebappClassLoaderBase#getResources()` 被标记为 `@Deprecated`，实现从 `return this.resources;` 变成 `return null;`。字节码/源码层面它仍可编译通过，运行期也不报错，只是永远返回 null；随后调用 `.getContext()` 直接抛 `NullPointerException`。
- **字段其实还在**：同一版本中 `setResources(WebResourceRoot)` 仍在给 `this.resources` 赋值，`getContextName()` 仍读取 `this.resources`，说明对象关系没有被移除，只是公开 getter 被“废掉”。因此改走反射读取 `resources` 字段仍可取到 `StandardRoot` 与 `StandardContext`（Tomcat 9 上的同类实践见关联卡）——这次变更不是安全边界，只是打断了依赖公开 API 的现成 payload。
- **为什么报错看起来像反序列化失败**：恶意类的注册逻辑写在静态块里，`TemplatesImpl.getTransletInstance()` 在类初始化阶段触发 `<clinit>`，NPE 被包装成 `ExceptionInInitializerError` 向上抛出；Shiro 的 `DefaultSerializer.deserialize()` 捕获所有异常后统一包装为 `SerializationException("Unable to deserialize argument byte array.")`，堆栈最内层才是 `java.lang.NullPointerException at ...<clinit>` 以及 `TemplatesImpl.getTransletInstance`。逐行加 `System.out.println` 调试可看到代码只打印到获取 ClassLoader 就中断，说明 gadget 链与 TemplatesImpl 加载都正常，问题出在取 context 的那一行。
- **版本边界**：原文在 Tomcat 8.5 分支逐版本实测——8.5.37、8.5.60、8.5.70、8.5.77 可正常取到 context 并注入；8.5.78、8.5.79、8.5.81 均因 `getResources()` 返回 null 失败。分界点即 8.5.78。该结论只覆盖 Tomcat 8.5 分支的实测样本，嵌入式容器或其他大版本需另行确认。

## 触发条件

- 攻击链（Shiro rememberMe、JNDI、fastjson、表达式注入等）注入的内存马类使用 `WebappClassLoaderBase#getResources().getContext()` 获取 `StandardContext`。
- 目标为 Tomcat 8.5.78 及以后的小版本（8.5 分支），且运行时 TCCL 为 `WebappClassLoaderBase`（普通 Web 应用部署方式）。
- 表现：注入请求后服务端日志出现 `Unable to deserialize argument byte array`（Shiro 场景）或类似包装异常，堆栈内层为 translet 类 `<clinit>` 的 `NullPointerException`；内存马未注册，`cmd` 参数无回显。
- 反向条件：Tomcat 8.5 < 8.5.78 时同一 payload 可成功，可作为版本边界验证。

## 利用步骤

1. **先确认版本**：攻击前通过错误页、`Server` 响应头、管理端或已知指纹判断 Tomcat 8.5 小版本；无法直接判断时，用一个可控的 TemplatesImpl/表达式执行点打印 `WebappClassLoaderBase` 类所在 jar 的版本信息，或直接观察注入失败堆栈。
2. **版本 < 8.5.78**：可直接使用 `getResources().getContext()` 的公开 API 写法（见关联卡），payload 最短。
3. **版本 >= 8.5.78**：不要用公开 getter。反射 `WebappClassLoaderBase.resources` 字段取 `StandardRoot` 再 `getContext()`（字段仍在，见关联卡），或改用从 request/ServletContext、Spring `ServletWebServerApplicationContext` 等其他路径拿 `StandardContext`。
4. **失败排查**：在恶意类静态块每行后加 `System.out.println`，重新发送 payload 并看控制台——若只输出到 ClassLoader 行，即命中本卡；再核对 Tomcat 版本与 `getResources()` 源码。
5. **不要被外层报错误导**：`unable to deserialize argument byte array` 不代表 gadget 链不可用，先看完整堆栈最内层的异常类型与行号，再决定换 gadget 还是换 context 获取方式。

## PoC

失败写法（Tomcat 8.5.78+ 在第二行 NPE）：

```java
WebappClassLoaderBase cl = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
StandardContext context = (StandardContext) cl.getResources().getContext();   // getResources() 返回 null
```

版本差异（反编译对照）：

```java
// Tomcat 8.5 < 8.5.78
public WebResourceRoot getResources() { return this.resources; }

// Tomcat 8.5.78+
@Deprecated
public WebResourceRoot getResources() { return null; }

// 同版本字段与 setter 仍在，getContextName() 仍读取 this.resources
public void setResources(WebResourceRoot resources) { this.resources = resources; }
```

典型堆栈（Shiro 场景，节选）：

```text
org.apache.shiro.io.SerializationException: Unable to deserialize argument byte array.
  ...
java.lang.NullPointerException
  at com.example.BehinderFilter.<clinit>(BehinderFilter.java:28)
  at com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getTransletInstance(...)
  at com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.newTransformer(...)
  at com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties(...)
  at org.apache.commons.beanutils.PropertyUtilsBean.invokeMethod(...)
```

绕过写法（反射字段，适用于新版本）：

```java
WebappClassLoaderBase cl = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
Field f = WebappClassLoaderBase.class.getDeclaredField("resources");
f.setAccessible(true);
StandardRoot root = (StandardRoot) f.get(cl);
StandardContext context = (StandardContext) root.getContext();
```

## 变体与关联

- **版本实测清单**：8.5.37 可用、8.5.60 可用、8.5.70 可用、8.5.77 可用；8.5.78 不可用、8.5.79 不可用、8.5.81 不可用。结论：8.5 分支以 8.5.78 为界。
- **关联**：[[web-java-framework-shiro-rememberme-filter-memshell-static-block]]（使用该 context 获取路径的 Shiro 单请求 Filter 内存马，含完整注入链）、[[web-java-component-tomcat-dynamic-filter-memshell]]（StandardContext 动态注册 Filter 的机制；其写法用反射 `resources` 字段，规避本问题）、[[web-java-deserialization-jndi-tomcat-filter-memshell]]（Tomcat 9 `getResources()` 返回 null 时反射 `resources` 字段的实践）、[[web-java-framework-shiro-rememberme-two-stage-memshell-loader]]（同为反射 `resources` 字段的 Shiro 内存马投递）。
- **其他获取路径**：有 request 时从 `request.getServletContext()` 反射取 context；Spring Boot 嵌入式 Tomcat 从 `ServletWebServerApplicationContext` 的 `webServer` 取 `TomcatWebServer`；不同版本字段名可能不同，需按目标调整。
- **嵌入式容器**：Spring Boot 内嵌 Tomcat 同样受该版本差异影响，但 TCCL 与 `resources` 的填充时机可能不同，需实测。
- **同类陷阱**：把 `pom.xml` 里依赖的 tomcat 版本换成 8.5.50 只在编译/本地调试时生效，运行时用的是 IDE/服务器上实际部署的 Tomcat，必须保证运行实例 < 8.5.78。

## 检测与防御

- **攻击视角的检测信号**：服务端日志出现 translet/内存马类 `<clinit>` 的 `NullPointerException`，堆栈含 `TemplatesImpl.getTransletInstance`、`getOutputProperties`、`PropertyUtilsBean.invokeMethod` 与 `Unable to deserialize argument byte array` 的组合——这是内存马注入尝试的强特征，即使注入失败也应告警并排查入口。
- **防御视角的边界**：升级到 8.5.78+ 只废掉公开 `getResources()` getter，`resources` 字段仍可反射访问，攻击者换一行代码即可绕过；**不能把 Tomcat 升级当作内存马防御手段**。
- **有效防御**：修复反序列化/表达式注入等上游入口（Shiro 换随机密钥、JEP 290/ObjectInputFilter、fastjson safeMode）；部署 RASP/Java Agent 监控 `TemplatesImpl`、`ClassLoader#defineClass`、`StandardContext.addFilterDef/addFilterMap` 与反射访问 `WebappClassLoaderBase.resources`；运行时枚举 `filterDefs`/`filterMaps`/`filterConfigs` 排查动态注册的异常 Filter。
- **应急**：确认被注入后重启应用可清除内存马，但必须先定位并修复入口与泄露密钥，否则会被再次注入。
