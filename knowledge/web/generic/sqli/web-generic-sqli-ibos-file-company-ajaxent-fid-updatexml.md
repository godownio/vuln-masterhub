---
id: web-generic-sqli-ibos-file-company-ajaxent-fid-updatexml
title: IBOS 文件柜下载 fid 参数进入 CDbCommand where 拼接：updatexml 报错注入回显库名
type: scenario
domain: web
path: web/generic/sqli
technique: ibos-file-company-ajaxent-fid-error-sqli
aliases:
- IBOS 文件柜 SQL 注入
- file/company/ajaxent fid 注入
- IBOS 下载功能注入
- IBOS 报错注入
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
  verified_at: '2026-11-13T02:26:42+08:00'
  notes: 已对照原文与截图核对：/?r=file/company/ajaxent&op=download&fid=1' 单引号闭合、actionAjaxEnt->BaseController::download->buildQuery 的代码路径、图31 updatexml 报错回显 ~www_ibos_com~ 均一致；已按截图修正 PoC 缺失的单引号并改为 database()/-- a 形态。未验证点：未复跑；普通用户权限未验证；原文未标注 affected_versions；无 sources/source_url。
---

## 一句话结论

IBOS 文件柜"公司网盘"的下载接口 `/?r=file/company/ajaxent&op=download&fid=1` 中，`actionAjaxEnt()` 调用 `BaseController::download()`，把 `fid` 拼进 Yii `CDbCommand` 的 `where` 条件执行查询；`fid` 为单引号上下文且无过滤，用 `updatexml()` 报错可在页面错误信息中回读数据库名（`~www_ibos_com~`），构成报错注入。

## 原理

- 入口：`file/company` 控制器的 `actionAjaxEnt()` 根据 `op` 参数分发动作，`op=download` 时调用基类 `BaseController::download()`。
- `download()` 使用框架 `db` 类库的 `buildQuery()` 组装查询：`fid` 被直接放入 `where` 条件字符串（如 `WHERE fid = <fid>` 或经过 `CDbCriteria` 的字符串拼接），未做参数绑定/整型转换。
- `CDbCommand::buildQuery()` 把 `where` 原样并入 SQL 执行；`fid` 处于单引号/数值上下文，可用单引号与括号闭合后追加 `updatexml()`。
- 报错回显：Yii 的 `handleException()` 将 `CDbCommand 无法执行 SQL 语句` 与 SQLSTATE 错误渲染到响应页，MySQL 报错 `XPATH syntax error: '~...~'` 把 `select database()` 夹带出来，从而无需盲注即可取数据。

## 触发条件

- 已登录 IBOS 且能访问"文件柜 → 公司网盘"（文章以超级管理员测试；普通用户权限取决于共享设置）。
- `fid` 参数可控且目标 MySQL 支持 `updatexml()`。
- Yii 异常信息可见（debug 模式/错误页）。

## 利用步骤

1. 进入"文件柜 → 公司网盘"，对任一文件点击下载，Burp 抓取请求：`GET /?r=file/company/ajaxent&op=download&fid=1`。
2. 输入单引号（`fid=1'`）观察 400/500 与 SQL 报错，确认注入点。
3. 使用报错注入 payload（原文截图形态）：
   ```
   fid=1') and (updatexml(1,concat(0x7e,database(),0x7e),1)) -- a
   ```
4. 响应页面错误信息中出现 `XPATH syntax error: '~www_ibos_com~'`，即数据库名回显；替换子查询可继续回读表名与数据。
5. 同一 `ajaxent` 路由下其它 `op` 动作若复用 `download()`，注入点同样存在。

## PoC

```http
GET /?r=file/company/ajaxent&op=download&fid=1')%20and%20(updatexml(1,concat(0x7e,database(),0x7e),1))%20--%20a HTTP/1.1
Host: <target>
```

说明：URL 需按实际编码；`-- ` 用于注释掉后续条件（原文用 `-- a` 收尾）。`fid` 从截图看处于单引号上下文，`1')` 先闭合再补括号，具体闭合方式以目标版本 SQL 为准。不访问、不执行原文目标。

## 变体与关联

- 同产品另一处报错注入：工作汇报 `keyword.subject`，见 [[web-generic-sqli-ibos-report-getlist-keyword-updatexml]]。
- 关联：IBOS 的 `BaseController::download()` 同时还处理文件读取逻辑，若 `fid` 查询结果用于 `readfile`，注入后可尝试联合查询直接控制文件路径（原文未验证，仅作审计延伸）。
- 同类审计模式：Yii 1.x `CDbCommand::where()`、`CDbCriteria->condition` 的字符串拼接；`buildQuery()` 只是组装器，不做转义。

## 检测与防御

- 检测：`file/company/ajaxent` 请求的 `fid` 参数出现引号、括号、`updatexml`、`extractvalue` 等特征；响应含 `XPATH syntax error` 或 SQLSTATE 报错。
- 检测：文件柜下载接口的异常错误率与同账号高频请求。
- 防御：`fid` 强制 `intval()` 或参数化绑定；统一使用 `CDbCriteria` 的 `params` 绑定；生产关闭异常详情回显。
- 防御：数据库账号最小权限；WAF 拦截报错注入特征。
