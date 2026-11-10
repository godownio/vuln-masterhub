---
id: web-generic-sqli-seacms-admin-datarelate-execute-none-query
title: SeaCMS 12.9 后台 admin_datarelate.php 任意 SQL 执行：ExecuteNoneQuery2 缺 CheckSql 绕过 SQL 安全检查
type: scenario
domain: web
path: web/generic/sqli
technique: seacms-admin-datarelate-execute-none-query-sqli
aliases:
- 海洋CMS 后台 SQL 执行
- admin_datarelate SQL 注入
- ExecuteNoneQuery2 无检查
- CheckSql 绕过
- sea_datarelate SQL 编辑器
- 后台数据关联执行 SQL
tags:
- php
- seacms
- cms
- sqli
- admin-panel
- sql-editor
- check-bypass
cve: []
severity: high
confidence: high
status: verified
affected_versions: SeaCMS 12.9（原文版本）
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T00:49:32+08:00'
  notes: 已对照原文与 img/07 核对：admin_datarelate.php?action=result 加载模板，非 select 分支按 ; 拆分交 ExecuteNoneQuery2（不调用 CheckSql），截图 SELECT * FROM sea_admin WHERE 1 返回管理员表。已修正正文对 select 分支的过度表述：select 走 Execute/getOne 仍受 CheckSql 约束，UNION/子查询/INTO OUTFILE 通常被拦；绕过仅适用于非 select 的 ExecuteNoneQuery2 路径。未复跑目标。
---

## 一句话结论

SeaCMS 12.9 后台 `admin_datarelate.php?action=result` 会加载 `admin_datarelate_result.htm` 执行用户提交的 SQL；该模板用 `stripslashes($sql)` 后仅判断是否以 `select` 开头，非 select 语句按 `;` 拆分交给 `$dsql->ExecuteNoneQuery2($sql)`，而 `ExecuteNoneQuery2` **不调用 CheckSql**（`Execute`/`getOne` 才调用），因此拥有后台权限的攻击者可执行任意非 select 语句（UPDATE/DELETE/TRUNCATE、多语句）并以 select 查询读取数据，造成数据泄露/篡改，视数据库权限还可进一步写文件或扩展提权。

## 原理

- 入口：`admin/admin_datarelate.php` 的 `action=result` 分支：
  ```php
  elseif($action=="result"){
      include(sea_ADMIN.'/templets/admin_datarelate_result.htm');
      exit();
  }
  ```
- 模板 `admin_datarelate_result.htm`：
  ```php
  $sql = stripslashes($sql);
  if(strtolower(substr(trim($sql),0,6))!='select')
  {
      $sqlArr = explode(';',rtrim(trim($sql),';'));
      foreach($sqlArr as $sql)
      {
          $num=$dsql->ExecuteNoneQuery2($sql);
          ...
      }
  }
  ```
  以 `select` 开头的语句走查询/展示路径（原文截图 `SELECT * FROM sea_admin WHERE 1` 直接返回 admin 表数据），非 select 语句按 `;` 拆分逐条执行。
- **安全检查缺失**：SeaCMS 的 `CheckSql()` 会对 `union`、注释、`sleep`、`benchmark`、`load_file`、`into outfile`、子查询等做过滤，但只有 `Execute()`/`getOne()` 等路径在 `$this->safeCheck` 为真时调用它；执行 SQL 的 `ExecuteNoneQuery2()`：
  ```php
  function ExecuteNoneQuery2($sql='') {
      ...
      if(!empty($sql)) { $this->SetQuery($sql); }
      if(is_array($this->parameters)) { ... str_replace ... }
      mysqli_query($this->linkID, $this->queryString);
      return mysqli_affected_rows($this->linkID);
  }
  ```
  直接 `mysqli_query`，没有 `CheckSql`，因此非 select 分支可提交被 CheckSql 规则禁止的关键字/多语句；select 分支仍走 `Execute`/`getOne`，受 `CheckSql` 约束（`UNION`、注释、`SLEEP`、`LOAD_FILE`、`INTO OUTFILE`、子查询等会被拦截）。
- 该功能本身是后台“数据关联/执行 SQL”工具，设计上允许管理员执行 SQL；漏洞在于低权限/被盗后台会话即可任意执行，并且 `ExecuteNoneQuery2` 完全绕过全站 SQL 安全检查，影响远大于普通业务注入。原文截图显示 `SELECT * FROM sea_admin WHERE 1` 查询出管理员账号/密码哈希等字段。

## 触发条件

- SeaCMS 12.9（原文版本）。
- 攻击者拥有后台管理员会话（后台目录可能被重命名，如 `/p8qca/`）。
- 后台“数据关联/SQL 执行”功能可访问（`admin_datarelate.php`）。
- 数据库账号具备相应权限（SELECT 必然可；UPDATE/DELETE/文件写入取决于 DB 用户权限）。

## 利用步骤

1. 登录后台，进入数据关联/执行 SQL 页面（`admin_datarelate.php`）。
2. 提交任意 SELECT 验证执行与回显（原文：`SELECT * FROM sea_admin WHERE 1` 返回管理员表）。
3. 读取敏感数据：`sea_admin` 的账号/密码哈希、`sea_member`、配置表等。`select` 分支经 `Execute`/`getOne` 会走 `CheckSql`，`UNION`/子查询/`SLEEP`/注释等通常被拦截，可直接查询的表/列以模板实际拼出的查询为准；非 select 分支可用 DML 改写数据。
4. 修改/破坏数据：`UPDATE sea_admin SET password='...' WHERE ...`、`DELETE`、`TRUNCATE` 等；`;` 分隔可一次执行多条。
5. 若数据库用户有 FILE 权限且 `secure_file_priv` 允许，可尝试把 `LOAD_FILE()` 嵌入非 select 的 DML 语句（如 `UPDATE ... SET c=LOAD_FILE('...')`）绕过 CheckSql；`SELECT ... INTO OUTFILE` 属 select 分支，通常会被 CheckSql 的 `into outfile` 检测拦截。其他提权/命令执行手法取决于 DB 类型与权限。
6. 也可先用该功能读出管理员密码哈希后离线破解，扩大后台控制。

## PoC

后台界面提交（原文截图）：

```sql
SELECT * FROM sea_admin WHERE 1
```

对应 HTTP 形态（参数名以页面表单为准，原文未给出原始请求）：

```http
POST /admin/admin_datarelate.php?action=result HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: <admin session>

sql=SELECT%20*%20FROM%20sea_admin%20WHERE%201
```

多语句/写数据示例：

```sql
UPDATE sea_admin SET password='<new hash>' WHERE id=1; SELECT * FROM sea_admin;
```

## 变体与关联

- 变体：非 select 语句按 `;` 拆分执行，可堆叠多条 UPDATE/DELETE/INSERT；select 分支经 `Execute`/`getOne` 受 CheckSql 约束，`UNION`/子查询不一定可用。
- 变体：`LOAD_FILE` 等函数可嵌入非 select 的 DML 语句以绕过 CheckSql；`SELECT ... INTO OUTFILE` 仍在 select 分支，通常会被 CheckSql 拦截（所有文件函数仍受 DB 权限与 `secure_file_priv` 约束）。
- 关联：[[web-generic-sqli-admin-report-sql-editor-xp-cmdshell]]（另一后台 SQL 编辑器 → xp_cmdshell 的 RCE 链）、[[web-generic-sqli-weaver-mobilemode-runsql-datasource-bypass]]（后台 runSql 类）、[[web-generic-sqli-seacms-admin-members-multi-param]]（同为 SeaCMS 后台注入但入口/参数不同）；同篇 SeaCMS 卡见 admin_ping 代码执行、admin_safe 任意文件下载、dmku 未授权 SQLi。
- 注意：该功能本质是管理员 SQL 工具，若后台账号本身即超管，则“任意 SQL”是预期能力；风险在于后台被弱口令/越权/CSRF 利用后放大为数据泄露与写文件。

## 检测与防御

- 修复：移除或严格限制后台任意 SQL 执行功能；如必须保留，使用只读数据库账号、语句白名单（仅允许受控 SELECT）并记录审计。
- 鉴权：后台强口令/MFA、目录改名、IP 白名单；对 `admin_datarelate.php` 增加二次确认与 CSRF Token。
- 检测：审计 `admin_datarelate.php?action=result` 的 SQL 内容，重点关注 `;`、`UNION`、`OUTFILE`、`LOAD_FILE`、`UPDATE`、`DELETE`、`TRUNCATE`；监控数据库高权限操作与异常查询。
- 数据面：数据库账号最小权限，禁用 FILE 权限；定期检查管理员表是否被篡改。
