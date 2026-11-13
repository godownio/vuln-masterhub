---
id: web-generic-sqli-json-unicode-escape-charunicodeescape-mssql
title: JSON 请求体 SQL 注入的 Unicode 转义绕过：\\u27 让单引号到达 MSSQL，sqlmap charunicodeescape 转义后拖库
type: scenario
domain: web
path: web/generic/sqli
technique: json-body-unicode-escape-waf-bypass-charunicodeescape
aliases:
- JSON 注入 \u27 绕过
- charunicodeescape
- JSON body SQL 注入
- Unicode 转义过 WAF
- sqlmap JSON 注入
tags:
- sqli
- json
- mssql
- sqlmap
- waf-bypass
- unicode
- tamper
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V598
  verified_at: '2026-11-12T17:03:01+08:00'
  notes: 已对照原文与44张截图核对：img09 POST /api/getColleagues {"name":""}=200 返回 3 条记录（字段 id/name/position/email/src）、img08 wfuzz 明文单引号=403、img10 \u27=500 An error has occurred、img11 sqlmap 识别 JSON name 5 列/布尔/堆叠/时间盲注且 UNION payload 用 CHAR(113)+CHAR(107) 拼接、img12/14 back-end DBMS MSSQL 2017 + IIS 10.0/ASP.NET 4.0.30319 + 库 Hub_DB/master/model/msdb/tempdb、img13 hashcat -m 17900（17 digests），均一致。已把标题与结论中不准确的“全量编码/整个 payload 逐字符编码”改为“非字母数字字符逐个编码”（charunicodeescape 实际只编码非字母数字字符）。dedup：与 PostgreSQL 注释绕过、Python JSON Unicode eval、Oracle/GraphQL/GBK 等候选均为 related/new，非同链；dup-scan 无 pair。无 affected_versions（原文未标注组件版本）。未实测注入。
---

## 一句话结论

当 POST 的 JSON 字段（如 `{"name":"..."}`）被后端直接拼接进 MSSQL 查询、而输入过滤只检查原始请求文本里的单引号时，发送 JSON Unicode 转义 `\u27` 就能让单引号穿过检查、在服务端 JSON 解析后还原进 SQL 并触发语法错误；确认后把请求交给 `sqlmap -r`，用 `--tamper=charunicodeescape` 把 payload 中非字母数字字符逐个编码成 `\uXXXX`，即可绕过过滤完成布尔/时间/UNION 注入并 dump 整库，MSSQL 哈希再交 hashcat `-m 17900` 离线爆破。

## 原理

- **JSON 的转义层与语义层分离**：JSON 规范允许字符串里用 `\uXXXX` 表示任意字符，解析器会先把它解码成真实字符再交给业务代码。过滤器若在原始字节上匹配 `'`、`union`、`select` 等字样，看到的只是 `\u27`、`%u0027` 之类的无害文本；数据库最终收到的仍是语义完整的 SQL。
- **本例的确认信号**：正常请求 `{"name":""}` 返回同事列表 JSON；把单引号直接放进 `name` 会被拦；发送 `{"name":"\u27"}` 时服务端返回 500 `{"Message":"An error has occurred."}`——说明引号已进入 SQL 并造成语法错误，注入点存在。请求头必须带 `Content-Type: application/json; charset=utf-8`，让服务端按 UTF-8 解析转义。
- **sqlmap 的 JSON 处理**：把完整请求保存为文件后 `sqlmap -r` 会把 JSON body 当作注入载体；`charunicodeescape` tamper 会把 payload 中除字母数字外的字符（含引号、空格、运算符）编码成 `\uXXXX`，既保持 JSON 合法又把关键字/符号藏起来。原文的 payload 还用了 `CHAR(113)+CHAR(107)` 之类字符拼接构造字符串，进一步避免明文关键字。
- **后端识别与利用深度**：sqlmap 识别出 MSSQL（IIS 10.0/ASP.NET，DBMS Microsoft SQL Server 2017），枚举出 `Hub_DB`、`master`、`model`、`msdb`、`tempdb`，并成功 dump `Hub_DB` 的表数据，其中包含可离线爆破的 MSSQL 口令哈希（`-m 17900` 即 SQL Server 2012+ 哈希模式）。
- **为什么过滤层容易漏**：围绕 JSON 的防护常在网关按字符串匹配、在业务层只检查解码后的部分字段，或在 WAF 上未对 JSON 正文做递归解码；只要任何一层只检查原始文本，Unicode 转义就能通过。

## 触发条件

- 请求为 `application/json`，某个字符串字段被拼接进 SQL（常见于 `name`、`filter`、`keyword`、`query` 等查询条件）。
- 过滤/WAF 对单引号或 SQL 关键字做文本匹配，但未对 JSON 解析后的值递归检查。
- 后端 MSSQL（或其它数据库，tamper 需按 DB 调整）；注入点权限足以读取目标库。
- 能保存原始请求交给 sqlmap，并能控制 `Content-Type` 与字符集。

## 利用步骤

1. 正常提交 `{"name":""}`，记录返回结构（本例返回 3 条同事记录）。
2. 探测过滤：分别尝试 `"`、`'`、`\u27`。若 `\u27` 触发 500/报错而明文单引号被拦，说明 Unicode 转义可绕过且引号进入 SQL。
3. 把该请求保存为文件（含 `Content-Type: application/json; charset=utf-8`），用 `sqlmap -r <file> --batch --tamper=charunicodeescape --level 5 --risk 3` 探测；必要时加 `--delay` 降低触发 WAF 的频率。
4. 确认注入类型（布尔/时间/UNION/堆叠）后 `--dbs`、`--dump-all --exclude-sysdbs` 取库表。
5. 从 dump 结果中提取口令哈希（本例为 MSSQL 2012+ 格式），用 `hashcat -m 17900 <hashes> <wordlist>` 离线爆破。
6. 用爆破出的口令做域内口令喷洒/登录验证（授权范围内），命中即停。

## PoC

探错请求（引号经 Unicode 转义到达 SQL）：

```http
POST /api/getColleagues HTTP/1.1
Host: target
Content-Type: application/json; charset=utf-8

{"name":"\u27"}
```

sqlmap 利用（请求文件已包含上面的 JSON body）：

```bash
sqlmap -r colleagues.request \
  --tamper=charunicodeescape \
  --delay 5 --level 5 --risk 3 --batch \
  --dump-all --exclude-sysdbs
```

哈希爆破：

```bash
hashcat -m 17900 hashes.txt /usr/share/wordlists/rockyou.txt
```

要点：`\u27` 是单引号在 JSON 中的转义；`charunicodeescape` 负责把 sqlmap 生成的 payload 全部转义后再放进 JSON，避免被原始文本过滤识别。

## 变体与关联

- **同思想的不同实现**：PostgreSQL 注入点可用 `/*"*/` 注释拆分关键字 + JSON Unicode 转义隐藏引号，见 `[[web-generic-sqli-postgres-waf-comment-quote-bypass]]`；本卡针对 MSSQL + sqlmap 自动 tamper，payload 构造与数据库语义不同。
- **转义变体**：`'`（前导零）、`\u{27}`（部分解析器）、双重转义 `\\u27`、URL 编码与 JSON 转义叠加；也可把关键字拆成 `CHAR()` 拼接或用 `/**/` 注释。
- **工具路线**：除 sqlmap 外，可用 Burp 插件自动把 payload 做 Unicode 转义；若 WAF 会递归解码 JSON，则需换用大小写/注释/等价函数等其它绕过。
- **延伸到域渗透**：MSSQL 注入点不仅能拖库，还能调用 `SUSER_SNAME` 等函数枚举域账号，见 `[[pentest-ad-mssql-suser-sid-rid-domain-account-enumeration]]`。

## 检测与防御

- **根治**：所有 SQL 一律参数化（`SqlParameter`/预编译），JSON 字段只作为参数值，不参与语句拼接。
- **解码后再检查**：WAF/网关对 JSON 正文做递归解析与解码（含 Unicode、URL、多重编码）后，再按解码值做语义检测；不要只匹配原始字节。
- **最小权限**：Web 应用连接数据库使用低权限账号，禁用不必要的堆叠查询、`xp_cmdshell` 与跨库读取。
- **检测信号**：JSON 请求体中出现大量 `\uXXXX` 转义且解码后含 SQL 关键字/引号；同一接口短时间触发数据库语法错误（500）后转为盲注探测；`sqlmap` 特征 User-Agent 与高 `--level/--risk` 探测流量。
- **口令安全**：数据库账号使用强口令与独立凭据，定期轮换；即使被拖库也应让离线爆破不可行。
