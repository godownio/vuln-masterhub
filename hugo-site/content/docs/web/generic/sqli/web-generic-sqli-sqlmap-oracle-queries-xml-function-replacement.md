---
id: web-generic-sqli-sqlmap-oracle-queries-xml-function-replacement
title: sqlmap 适配报错 Oracle 库：改 data/xml/queries.xml 替换 CAST/NVL/COUNT 等不兼容函数并修正查询语句
type: scenario
domain: web
path: web/generic/sqli
technique: sqlmap-oracle-queries-xml-adaptation
tags:
- sqli
- oracle
- sqlmap
- queries-xml
- time-blind
- tool-adaptation
- data-dump
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V539
  verified_at: '2026-11-11T19:00:19+08:00'
  notes: 已对照原文 content.md 与全部 11 张图逐项核对：手工 DBMS_PIPE 5 秒延迟（图01）、sqlmap 识别 Oracle AND time-based blind 及 payload（图02）、取数阶段 500/invalid character/--no-cast/--hex 提示（图03）、v$version 查询报错跳转 /Error 与 DATABASE_NAME 查询正常返回（图04/05）、queries.xml Oracle 段原始模板 cast/length/isnull/count/banner/current_user/current_db（图06）、修改后的 cast/isnull/current_db（图07）、tables/columns/dump_table 的 %s 占位（图08）均一致。验证中修正：修改前示例的 current_db 原始值为 SELECT USER FROM DUAL（与 current_user 相同），SYS.DATABASE_NAME 是修改后写法；已按图06/07改正并补全修改后 current_user/current_db 行。affected_versions 按原文未标 Oracle/产品版本省略正确。dedup new，related 为报错注入原理与 sqlmap 启发式探测等，非同场景；dup-scan 无本卡 pair。未验证点：未实际修改 sqlmap XML/复跑取数；原文未给目标 Oracle 具体版本，函数报错原因仅为推测。
url: /docs/web/generic/sqli/web-generic-sqli-sqlmap-oracle-queries-xml-function-replacement/
draft: false
kb_aliases:
- sqlmap Oracle 跑不出数据
- sqlmap queries.xml 修改
- Oracle count 换成 sum(1)
- sqlmap invalid character detected
- sqlmap 数据库函数不兼容
---

## 一句话结论

目标 Oracle 库对 sqlmap 内置查询模板里的部分函数/视图报错（如 `CAST(%s AS VARCHAR(4000))`、`NVL(%s,' ')`、`COUNT`、`SELECT banner FROM v$version WHERE ROWNUM=1`），表现为 sqlmap 能确认时间盲注却一直 `invalid character detected`、500、连接中断、跑不出数据；把 sqlmap 的 `data/xml/queries.xml` 中 `<dbms value="Oracle">` 段的这些模板替换为目标库可执行的等价写法（原文示例：`count` 用 `sum(1)` 替代、`cast`/`isnull` 直接退化为 `%s`、分开修正 `current_user`/`current_db`），并按实际表名/列名调整 `%s` 查询语句后，同一注入点即可正常拖库。

## 原理

- sqlmap 按 DBMS 把探测与取数用的 SQL 片段模板化存放在 `data/xml/queries.xml`；`<dbms value="Oracle">` 段定义了 `cast`、`length`、`isnull`、`delimiter`、`limit`、`order`、`count`、`substring`、`case`、`inference`、`banner`、`current_user`、`current_db` 等模板，取数阶段再把表/列/数据查询语句（`<tables>`、`<columns>`、`<dump_table>`）中的 `%s` 替换成命令行参数（如 `-T` 的表名）。
- 不同 Oracle 版本/发行版（或中间件封装）对某些函数与数据字典视图支持不一致：本例中 `v$version` 查询、`CAST(... AS VARCHAR(4000))`、`NVL(...)` 与统计类写法会返回错误页，而 `SELECT SYS.DATABASE_NAME FROM DUAL` 正常返回。sqlmap 的取数依赖这些模板，模板报错就会出现“检测到了注入但取不到数据”。
- 由于模板是纯 XML 文本，修复方式就是“哪个函数报错就换成目标库可执行的等价式”，不改变 sqlmap 的检测/取数逻辑。原文把 `count` 改为 `sum(1)` 形式，并把 `cast`/`isnull` 简化为直接 `%s`；同时发现 `current_db` 与 `current_user` 使用了同一 payload，一并修正。
- 取数语句中的 `%s` 是命令行输入（如 `-T` 的表名），若目标库的对象名大小写/模式（schema）与默认模板不一致，需要按实际返回调整（例如加 `SYS.`/owner 条件、表名保持大写并用单引号包裹）。
- 这是一个迭代过程：跑 sqlmap → 看返回的错误/空结果 → 定位对应 XML 模板 → 换成可用写法 → 再跑，直到稳定拖出数据。

## 触发条件

- 已确认目标为 Oracle 注入（时间/布尔/报错盲注均可），sqlmap 能识别注入点（如 `Type: time-based blind`、`Title: Oracle AND time-based blind`）。
- 使用 sqlmap 取数时出现数据库报错（`invalid character detected`、HTTP 500、`connection dropped`、返回页为错误页等），且手工验证发现常见函数在该库不可用。
- 攻击者本地可编辑 sqlmap 的 `data/xml/queries.xml`（自建工具环境）。
- 需要取具体数据（表名、列、行），而非仅确认注入存在。

## 利用步骤

1. 用 sqlmap 确认注入点，例如时间盲注 payload：`1' AND 1652=DBMS_PIPE.RECEIVE_MESSAGE(CHR(117)||CHR(74)||CHR(76)||CHR(80),5) AND 'Tytq'='Tytq`。
2. 直接取数失败时，用 `--proxy` 让流量过 Burp，对比“报错语句”和“正常语句”的返回差异，定位哪些函数/视图在该库报错（原文：`SELECT banner FROM v$version WHERE ROWNUM=1` 报错，`SELECT SYS.DATABASE_NAME FROM DUAL` 正常；`CAST`/`NVL`/`COUNT` 也会报错）。
3. 打开 sqlmap 的 `data/xml/queries.xml`，找到 `<dbms value="Oracle">` 段，把报错模板替换为等价写法：
   ```xml
   <!-- 修改前（示例，图 06） -->
   <cast query="CAST(%s AS VARCHAR(4000))"/>
   <isnull query="NVL(%s,' ')"/>
   <count query="COUNT(%s)"/>
   <banner query="SELECT banner FROM v$version WHERE ROWNUM=1"/>
   <current_user query="SELECT USER FROM DUAL"/>
   <current_db query="SELECT USER FROM DUAL"/>   <!-- 与 current_user 相同 -->

   <!-- 修改后（按目标实测，图 07；原文 count 用 sum(1)，cast/isnull 退化为 %s，current_db 改为 SYS.DATABASE_NAME） -->
   <cast query="%s"/>
   <isnull query="%s"/>
   <count query="SUM(1)"/>
   <current_user query="SELECT USER FROM DUAL"/>
   <current_db query="SELECT SYS.DATABASE_NAME FROM DUAL"/>
   ```
4. 继续调整取数语句模板（`<tables>`/`<columns>`/`<dump_table>`）中的 `%s` 占位：如 `SELECT TABLE_NAME FROM SYS.ALL_TABLES WHERE OWNER='%s'`、`WHERE TABLE_NAME='%s'`，按目标返回的表名大小写/模式修改。
5. 重新运行 sqlmap 取数；根据新的报错继续替换函数，直到能稳定列出表、列并 dump 行。
6. 数据取完后按需保留修改后的 queries.xml 供同目标复用（不同目标库需重新验证）。

## PoC

sqlmap 原始报错样例：

```text
[ERROR] invalid character detected. retrying..
[CRITICAL] connection dropped or unknown HTTP status code received. sqlmap ...
[WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[WARNING] on Oracle you'll need to use schema names for enumeration as the counterpart to database names on other DBMSes
```

queries.xml（`data/xml/queries.xml`）修改示例见上；具体替换以目标库实测为准，原文还通过逐步修改 `<tables>`/`<columns>` 查询语句最终成功拖库。

- 先试 sqlmap 自带开关 `--no-cast`、`--hex`，不能解决再改 XML。
- 原文表名/列名/模式均来自目标返回，命令行的 `-T` 值会填入 `%s`，不要写死。

## 变体与关联

- 变体：只改 `--no-cast`/`--hex` 或通过 `--tamper` 调整编码即可解决时，无需改 queries.xml。
- 变体：其他 DBMS（MySQL/MSSQL/PostgreSQL）同样可改 queries.xml 适配非标准函数；也可为同一 DBMS 建多份 XML 切换。
- 关联：[[web-generic-sqli-sqlmap-heuristic-probe]]（sqlmap 探测阶段的行为）；[[pentest-recon-oracle-injection-version-user-privilege-enumeration]]（Oracle 注入后的信息收集查询，可与本卡配合确认可用函数/视图）；[[web-generic-sqli-oracle-case-divzero-error-boolean-oracle]]（同一文章中将时间盲注改为 1/0 布尔盲注以提升取数效率）。
- 边界：修改的是本地 sqlmap 数据文件，不影响目标；目标库禁用数据字典/函数权限时仍可能取不到数据，需要换用盲注提取。

## 检测与防御

- 检测（防守方视角）：请求中出现 `DBMS_PIPE.RECEIVE_MESSAGE`、`v$version`、`SYS.ALL_TABLES`、`SYS.DATABASE_NAME`、`CASE WHEN`、`1/0` 等 sqlmap/Oracle 取数特征；同一参数高频、规律性请求，响应时间阶梯化或返回错误页与正常页交替。
- 检测：数据库审计日志中出现对 `v$version`、`ALL_TABLES`、`ALL_TAB_COLUMNS` 的异常查询与 `SUM(1)`/`COUNT` 统计模式。
- 防御：参数化查询消除注入；数据库账号最小权限，限制数据字典视图访问；应用不把数据库错误页/错误信息返回给客户端，降低盲注 oracle 可用性；WAF 对上述函数/视图与编码变体做递归检测。
