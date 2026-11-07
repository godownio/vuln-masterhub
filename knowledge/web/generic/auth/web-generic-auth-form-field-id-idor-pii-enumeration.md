---
id: web-generic-auth-form-field-id-idor-pii-enumeration
title: 教育系统动态表单字段 ID 越权：篡改 field7186/triFieldid_181 遍历 10 万+ 学生身份证与学号
type: scenario
domain: web
path: web/generic/auth
technique: dynamic-form-field-id-idor-pii
aliases:
- 表单字段 ID 越权
- field7186 越权
- triFieldid 越权
- reqDataInputResult 越权
- 响应包字段回填越权
- 学生信息批量遍历
- 动态表单 IDOR
tags:
- idor
- broken-access-control
- horizontal-privilege-escalation
- pii
- enumeration
- dynamic-form
- api
- education
- burp-intruder
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V196
  verified_at: '2026-11-06T23:02:12+08:00'
  notes: 已对照原文与19张截图核对：reqDataInputResult 的 field7186=58521/triFieldid_181=7186 越权、响应回显 field190/field7186/field7187、修改字段后值变化、Intruder 双 payload 200 大量响应与 10万+ 估计均一致；无 affected_versions（文章未给产品版本）；无 sources 字段；未复跑
---

## 一句话结论

教育系统的动态表单查询接口 `reqDataInputResult` 从请求体接收 `field7186`（记录/行 ID）与 `triFieldid_181`（字段/表 ID）等参数，服务端按这些客户端可控的 ID 查库，却不校验当前登录用户是否有权访问该记录；响应包又会把当前记录的字段 ID 和值一起返回，攻击者据此回填并篡改 ID，即可越权读取其他学生的姓名、学号、身份证号等 PII，配合 Burp Intruder 双参数遍历可枚举 10 万+ 条记录。

## 原理

- **动态表单接口的参数语义**：低代码/动态表单系统通常把表单定义存成“字段 ID → 数据库列/查询片段”的映射，前端提交 `field<id>=<value>` 与 `triFieldid_<n>=<字段定义 id>`，后端据此拼出查询或赋值。表单 ID、记录 ID 都是客户端可改的普通参数，服务端必须额外做对象级授权。
- **响应包泄露参数结构**：接口响应 JSON 会回显 `assignInfo_181.linkageSql`、`result` 中的 `field190`、`field7186`、`field7187` 等字段及其 `value`；攻击者不需要猜参数名，直接从响应里复制 `field7186=58521&triFieldid_181=7186` 到下一次请求，再改动数值即可。
- **越权根因**：服务端只校验“已登录/请求格式正确”，没有校验 `field7186` 对应的学生记录是否属于当前用户，也没有把 `triFieldid_181` 限制在当前用户可见的表单范围内。于是任意登录用户都能用别人的记录 ID 查数据。
- **双参数联动**：`field7186` 与 `triFieldid_181` 存在对应关系（记录 ID 与字段定义 ID），只改一个可能查不到或报错；Burp Intruder 用两个 payload 集同步递增/映射，才能稳定遍历。示例中两个 ID 任意变化一位，响应值都会变化，说明二者都参与查询。
- **规模化**：单条请求返回一个学生的多项字段；把记录 ID 从 1 递增到 10 万+，按响应长度/字段差异筛选有效记录，即可批量导出学生姓名、学号、身份证号等 PII。文章估计泄露量 10 万+，报告定为高危。
- **为什么不是“正常功能”**：接口返回的是他人完整敏感信息，普通登录用户即可访问，且服务端没有按角色/归属过滤；前端页面只展示当前用户，不能替代后端对象级授权。

## 触发条件

- 目标系统存在动态表单/低代码查询接口（示例为 `reqDataInputResult`），接受 `field<id>`、`triFieldid_<n>` 等客户端参数。
- 攻击者拥有一个普通登录账号（示例通过统一身份认证登录）。
- 接口只校验登录态，未校验记录归属/字段可见范围；`field*` 与 `triFieldid*` 可被任意修改。
- 响应包回显字段 ID 与值，便于发现参数结构；无速率限制/批量审计。
- 记录 ID 连续或可预测，或可通过其他接口获得 ID 列表。

## 利用步骤

1. **登录并抓包**：用普通账号进入“在校基本信息/学生一张表”等功能，抓取查询请求与响应。
2. **读响应结构**：在响应 JSON 中找到 `assignInfo_181`、`linkageSql`、`result`、`field190`、`field7186`、`field7187` 等字段；记录当前用户对应的 `field7186`/`triFieldid_181` 值。
3. **回填并篡改**：把响应中的 `field7186=<记录ID>&triFieldid_181=<字段ID>` 放回请求体，先改一位数字重放，观察响应中的姓名/学号/身份证是否变成他人数据。
4. **确认越权**：对比修改前后响应，确认同一接口返回不同学生记录，且无需任何额外授权。
5. **双参数遍历**：在 Burp Intruder 中把 `field7186` 与 `triFieldid_181` 设为两个 payload 位置，按对应关系同步递增（或先用小范围确定映射规律），状态码 200、响应长度变化即命中不同记录。
6. **批量导出**：按响应字段提取姓名、学号、身份证号等，去重统计泄露量；抽样验证数据真实性后提交报告。
7. **扩展**：用泄露的学号/身份证继续尝试初始口令登录、密码重置、其他业务接口越权。

## PoC

请求模板（参数名与值来自文章截图，域名/部分值已打码）：

```http
POST /<path>/reqDataInputResult HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded
Cookie: <普通学生会话>

field724=1690&triFieldid_180=7181&rowIndexStr_181=1&
field7186=58521&triFieldid_181=7186&rowIndexStr_181=1
```

Burp Intruder 配置：

```text
位置1: field7186=§58521§
位置2: triFieldid_181=§7186§
Payload 类型: Numbers（或自定义映射表）
两个位置按记录 ID 与字段 ID 的对应关系同步变化
筛选: 状态码 200 且响应长度/内容随记录变化
```

响应关键片段（打码）：

```json
{
  "assignInfo_181": {
    "linkageSql": "...",
    "result": {
      "field190": {"value": "..."},
      "field7186": {"value": "88"},
      "field7187": {"value": "..."}
    }
  }
}
```

文章实测：修改 `field7186`/`triFieldid_181` 后响应值变化，确认越权；Intruder 双 payload 跑出大量 200 响应，估计泄露 10 万+ 学生记录。

## 变体与关联

- **参数名变体**：不同动态表单系统的字段前缀可能是 `field`、`fd`、`attr`、`prop`，表/表单 ID 可能是 `triFieldid`、`formId`、`tableId`；核心是“客户端可控的记录 ID + 字段 ID 直接进查询”。
- **只改记录 ID**：若 `triFieldid` 由服务端根据表单上下文固定，只需遍历记录 ID；若两者都参与查询，需要同步映射。
- **响应不回显字段 ID**：可从 JS 源码、接口文档、前端表单配置或报错信息中恢复字段 ID；也可观察请求体中的参数名。
- **写操作变体**：同类动态表单的保存接口若也只校验登录，可能把 `field*`/`triFieldid*` 用于 UPDATE，导致越权修改他人信息；测试时先用只读接口确认，避免破坏数据。
- **同源 IDOR**：与 `userId`、`personId` 等直接对象 ID 的越权本质相同，区别在于参数是表单字段/记录 ID，隐藏在一长串 `field*` 参数中，容易被测试者忽略。
- 关联：[[web-generic-auth-mobile-person-permission-userid-idor-pii]]（userId 越权遍历师生 PII）、[[web-generic-auth-api-param-fuzz-idcard-pii-enumeration]]（参数 fuzz 后发现 PII 越权）、[[web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak]]（用户列表缺角色校验导致全量泄露）、[[web-generic-auth-proxy-history-unauth-user-all-leak]]（未鉴权 user/all 返回全站用户对象）。

## 检测与防御

- **对象级授权**：所有按记录 ID/字段 ID 查询的接口都要校验“该记录属于当前用户/当前租户/当前角色可见范围”；不要信任客户端提交的 `field*`/`triFieldid*`，服务端应从表单定义中解析字段并绑定到受控查询。
- **参数白名单**：对字段 ID、表 ID 建立服务端白名单，拒绝不在当前表单定义中的 ID；记录 ID 使用不可预测的 UUID 或做归属校验。
- **日志检测**：监控同一账号短时间内对 `reqDataInputResult` 的 `field*`/`triFieldid*` 高频变化、响应长度差异大、单日访问记录数异常；对批量递增的 ID 序列告警。
- **收敛返回**：接口只返回当前业务需要的字段，避免把 `linkageSql`、内部字段 ID、完整 PII 一并回显；对身份证号/手机号做脱敏。
- **速率限制与审计**：对查询接口做用户级速率限制、异常枚举检测与审计日志；发现越权后及时评估泄露范围并通知受影响用户。
