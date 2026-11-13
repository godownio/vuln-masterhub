---
id: web-java-component-jetty11-customizer-memshell-godzilla
title: Jetty 11 内存马：反射注册 HttpConfiguration.Customizer，逐请求执行命令并兼容哥斯拉协议
type: scenario
domain: web
path: web/java/component
technique: jetty11-httpconfiguration-customizer-memshell
tags:
- jetty
- java
- memshell
- customizer
- godzilla
- threadlocal
- unsafe
- jdk11
- webshell
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V676
  verified_at: '2026-11-13T12:05:41+08:00'
  notes: '已对照原文与8张截图核对：EvilCustomizer 实现 HttpConfiguration.Customizer、static 块用 Unsafe 遍历 ThreadGroup.threads→threadLocals.table→Entry.value 找到 org.eclipse.jetty.server.HttpConnection 并 addCustomizer(new EvilCustomizer(1))、customize() 按 x-client-data 分发 cmd（读 cmd 头、cmd /c 或 /bin/bash -c、getWriter 回显）与 godzilla（AES key 3c6e0b8a9c15224a/pass、MD5 校验、Base64+AES 回包、defineClass 缓存 payload）通道；img05 Burp 请求 Server: Jetty(11.0.14)、img06/08 哥斯拉连接成功与原文一致。affected_versions 未写：Jetty 11/JDK 11 为原文测试环境描述，无受影响区间。dedup：与 jetty11-threadlocal-header-memshell（每请求自取连接、不注册组件）等候选非同链，理由成立。未验证点：未在本机复跑；原文 Cmd 马为与注入请求同发的一次性回显，已在跳过项说明。'
url: /docs/web/java/component/web-java-component-jetty11-customizer-memshell-godzilla/
draft: false
kb_aliases:
- Jetty Customizer 内存马
- HttpConfiguration.addCustomizer
- Jetty Valve 型内存马
- EvilCustomizer
- Jetty 哥斯拉内存马
- 线程遍历注册 Customizer
---

## 一句话结论

Jetty 10/11 下可以把实现 `HttpConfiguration.Customizer` 的恶意类注册到当前连接的 `HttpConfiguration` 上（`HttpConnection.getHttpChannel().getHttpConfiguration().addCustomizer(...)`），容器随后对每个请求调用其 `customize()`，效果等价于 Tomcat 的 Valve 型内存马；恶意类在静态初始化块里用 Unsafe 遍历 ThreadGroup/threadLocals 找到 HttpConnection 完成自注册，`customize()` 按请求头分发命令执行或哥斯拉 AES 协议，实现无文件、无需新路由的持久控制。

## 原理

- **Customizer 调度点**：Jetty 的 `HttpConfiguration` 维护 Customizer 列表，请求处理时会依次调用 `customize(Connector, HttpConfiguration, Request)`；它独立于 servlet/filter 注册体系，Jetty 10+ 切换到 `jakarta.servlet` 后依然可用，也不受 `javax.servlet.Filter` 类不存在的影响。
- **自注册入口**：当前请求处理线程的 `Thread.currentThread().getThreadGroup()` → `threads` 数组 → 每个线程的 `threadLocals`（ThreadLocalMap）→ `table` 的 Entry.value，找到 `org.eclipse.jetty.server.HttpConnection`；再 `getHttpChannel()` 取 HttpChannel、`getHttpConfiguration()` 取配置对象，调用 `addCustomizer(new EvilCustomizer(1))`。恶意类把这段逻辑放在 static 块里，类被 newInstance 时立即执行，不需要第二次请求参与。
- **为什么用 Unsafe**：`threads`、`threadLocals`、`table`、`value` 都是私有字段，普通反射在高版本 JDK 受限；`sun.misc.Unsafe.objectFieldOffset/getObject` 可绕过访问控制直接读取对象图。原文在 JDK 11 + Jetty 11 环境实测。
- **命令通道**：`customize()` 检查请求头 `x-client-data`：值为 `cmd` 时读取 `cmd` 头，按操作系统用 `cmd /c` 或 `/bin/bash -c` 执行并把结果写入 `request.getResponse().getWriter()`；值为 `godzilla` 时按哥斯拉协议处理（AES 密钥/口令、MD5 校验、Base64+AES 回包），首次请求 defineClass 内层 payload 后复用。
- **前置条件**：必须已有一次 JVM 内代码执行/类加载入口（如 H2 INIT 的 Nashorn JavaScript、表达式注入、反序列化）。JDK 11 下加载该类需先绕过反射过滤表（见关联卡）；JDK 17 强封装下需 Class.module 伪装。
- **为什么可行**：Customizer 是 Jetty 正常扩展点，容器会主动遍历调用；注册后内存马随进程存活、对所有已注册路径生效，重启才失效。原文注入成功后哥斯拉客户端可稳定连接。

## 触发条件

- 目标使用 Jetty 10/11（jakarta.servlet 时代；原文为 Metabase 内置 Jetty 11 + JDK 11）。
- 已有任意代码执行或任意类加载能力，用于 defineClass + newInstance 恶意类。
- 进程内存在处理过请求的线程，其 ThreadLocal 中留有 HttpConnection（注入请求本身即可满足）。
- 目标未限制 `sun.misc.Unsafe`，且反射过滤/模块封装已按 JDK 版本处理。
- 未部署针对 addCustomizer、动态类定义或固定请求头的 RASP/WAF 规则。

## 利用步骤

1. 编写实现 `org.eclipse.jetty.server.HttpConfiguration.Customizer` 的恶意类：static 块执行自注册，`customize()` 实现命令/哥斯拉协议。
2. 通过已有 RCE 入口（如 H2 init 的 `//javascript`）调用 JS loader 完成 defineClass 并 newInstance（加载器见关联卡）。
3. 静态块遍历线程对象图找到 HttpConnection，向 HttpConfiguration 注册 customizer。
4. 之后访问任意已注册路径，携带 `x-client-data: cmd` 与 `cmd: whoami` 验证回显；或用哥斯拉客户端以约定口令连接。
5. 若注册失败，检查是否找到 HttpConnection（不同 Jetty 版本字段名/类型）、JDK 反射限制是否已绕过、类是否由合适的 ClassLoader 定义。

## PoC

```java
public class EvilCustomizer implements HttpConfiguration.Customizer {
    static {
        try {
            Unsafe u = getUnsafe();
            ThreadGroup g = Thread.currentThread().getThreadGroup();
            Field tf = g.getClass().getDeclaredField("threads");
            Thread[] ts = (Thread[]) u.getObject(g, u.objectFieldOffset(tf));
            for (Thread t : ts) try {
                Field lf = t.getClass().getDeclaredField("threadLocals");
                Object map = u.getObject(t, u.objectFieldOffset(lf));
                Field tab = map.getClass().getDeclaredField("table");
                for (Object e : (Object[]) u.getObject(map, u.objectFieldOffset(tab))) try {
                    Object v = u.getObject(e, u.objectFieldOffset(e.getClass().getDeclaredField("value")));
                    if (v.getClass().getName().equals("org.eclipse.jetty.server.HttpConnection")) {
                        ((HttpConnection) v).getHttpChannel().getHttpConfiguration()
                            .addCustomizer(new EvilCustomizer(1));
                        return;
                    }
                } catch (Exception ignored) {}
            } catch (Exception ignored) {}
        } catch (Exception ignored) {}
    }
    public EvilCustomizer(int s) {}
    public void customize(Connector c, HttpConfiguration cfg, Request req) {
        // 按 x-client-data 头分发：cmd 命令执行 / godzilla 加密协议
    }
}
```

（原文实现还包含 AES/哥斯拉协议与反射细节；此处为最小骨架，未在本机复跑。）

## 变体与关联

- [[web-java-component-jetty11-threadlocal-header-memshell]]：同样用 ThreadLocal 取 HttpConnection，但每个请求自行取连接、读请求头回显，不注册组件；本卡是注册型，由容器调度。
- 其他 Jetty 内存马：[[web-java-component-jetty9-servlethandler-servlet-memshell]]、[[web-java-component-jetty9-filterholder-initialize-bypass]]、[[web-java-component-xxl-job-executor-jetty-handler-collection-memshell]]、[[web-java-component-jetty-xml-bcel-filter-memshell]]。
- 加载链：[[web-java-classloader-jdk11-reflection-filter-unsafe-defineclass-bypass]]（JDK11）、[[web-java-classloader-jdk17-class-module-field-spoof]]（JDK17）。
- 变体：注册到全局 Server 的 HttpConfiguration 而非当前连接；customize 可按任意路径/头匹配；回显可写响应体、响应头或 Cookie。
- 边界：目标无代码执行入口、Unsafe 被限制、RASP 拦截 addCustomizer/defineClass 时不可用；重启失效。

## 检测与防御

- 检测：运行期出现实现 `HttpConfiguration$Customizer` 的动态类；`HttpConfiguration._customizers` 列表异常增长或含非框架类；固定请求头（如 `x-client-data`）配合命令参数；线程 ThreadLocal 的反射遍历堆栈；无磁盘来源的 defineClass。
- 防御：RASP 监控 `addCustomizer` 与动态类定义；封堵 H2 INIT、表达式注入、反序列化等前置入口；JEP 290 类白名单；限制 `sun.misc.Unsafe` 与反射访问；保持 JDK 强封装并升级 Jetty。
