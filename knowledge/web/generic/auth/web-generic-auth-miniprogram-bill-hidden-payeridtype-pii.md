---
id: web-generic-auth-miniprogram-bill-hidden-payeridtype-pii
title: 小程序票据查询隐藏枚举值：前端仅三种证件类型，payerIdType=4 用学号查身份证
type: scenario
domain: web
path: web/generic/auth
technique: hidden-enum-value-pii-query
aliases:
- payerIdType 隐藏查询方式
- 票据查询隐藏枚举
- 小程序隐藏参数值
- 学号查身份证
- 枚举值越权查询
tags:
- api
- enumeration
- pii
- unauth
- miniprogram
- parameter-fuzz
- bill
- education
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V71
  verified_at: '2026-11-05T16:45:11+08:00'
  notes: 已对照30张图片核对：前端证件类型仅身份证/统一社会信用代码/护照三种，抓包请求体为billType=0、payerIdType=4、payerIdNo=学号、payer=姓名，与卡片一致；原文明确改4后可用学号查出票据并获取学生身份证信息。注意：响应JSON截图中可见bill_batch_code/bill_code/bill_no/issue_date_time/pdf_url/bill_name/bill_state等，payer_id_no字段截图被遮挡、字段名系按原文结论推断；原文自评中危而卡片severity=high，属评级差异。小程序票据接口未提登录，PoC未本机执行。
---

## 一句话结论

小程序票据查询前端只展示“身份证/统一社会信用代码/护照”三种证件类型，但后端 `payerIdType` 还保留了隐藏的第四种（按学号查询）；把请求 JSON 中的值改成 `4`、`payerIdNo` 填学号，即可未授权查出该学生的电子票据，响应中包含其身份证号等 PII。

## 原理

- 前端下拉框只是 UI 白名单，不是服务端授权边界。后端通常用 `payerIdType` 的 switch/if 分支决定按哪个字段查询（1=身份证、2=统一社会信用代码、3=护照），开发测试时可能留下第 4 个分支（按学号/学工号）。
- 票据查询接口往往无需登录（面向缴费人自助查询），返回完整票据 JSON：交款人、证件号、金额、票据号、PDF URL 等；一旦隐藏分支可达，就把“凭票据号查询”变成了“按学号枚举学生身份信息”。
- 枚举值探测成本极低：抓包后把 `payerIdType` 从 1/2/3 改为 0、4、5、6 等，观察响应码、`msg`、`data` 长度与字段变化；隐藏分支通常返回与其他值明显不同的成功结构。
- 学号本身常通过 Google dorking、录取/公示名单、小程序其他页面泄露；两者结合即可批量获取“学号 → 身份证号”，再用于默认口令（身份证后 6 位）等后续攻击。
- 这类漏洞的根因是“前端限制 + 后端未做枚举白名单”，与 SQL 注入/越权不同，不需要构造特殊字符，只需一个合法但未公开的枚举值。

## 触发条件

- 目标小程序/APP 存在票据、缴费、证书等查询接口，请求体含枚举型参数（`payerIdType`、`queryType`、`idType`、`bizType` 等）。
- 后端对枚举值未做服务端白名单校验，保留了测试/历史分支。
- 接口无需登录或仅需低权限，且返回包含 PII 的完整对象。
- 攻击者能抓到请求体并重放（小程序抓包/反编译）。
- 学号等查询关键字可从公开渠道获得。

## 利用步骤

1. 在小程序中进入票据查询，选择一种证件类型并提交，抓取请求体，记录 `billType`、`payerIdType`、`payerIdNo`、`payer` 等字段。
2. 先测试前端可见的 1/2/3，确认正常响应结构；再枚举 `payerIdType=0,4,5,6...`，观察响应差异（`code`、`msg`、`data` 是否为空、返回字段）。
3. 发现隐藏值（如 4）后，把 `payerIdNo` 改为目标学号、`payer` 改为对应姓名（若必填），提交查询。
4. 解析响应中的票据对象：交款人、证件号、金额、票据号、开票日期、PDF URL 等；确认是否包含身份证号。
5. 用 Google dorking/公开名单收集更多学号，批量查询验证影响范围（注意授权与数据最小化，不要全量留存）。
6. 将泄露的身份证号用于默认口令/密码重置等后续测试（如身份证后 6 位）。

## PoC

```http
POST /ebill/query HTTP/1.1
Host: target.edu.cn
Content-Type: application/json
Origin: https://target.edu.cn
Referer: https://target.edu.cn/ebillh5/

{"billType":"0","payerIdType":4,"payerIdNo":"<学号>","payer":"<姓名>"}
```

```json
{
  "msg": "请求成功！",
  "code": 200,
  "data": [{
    "bill_batch_code": "...",
    "bill_code": "...",
    "bill_no": "...",
    "issue_date_time": "...",
    "bill_name": "政府非税收入专用票据（电子）",
    "payer_id_no": "<身份证号>",
    "payer": "<姓名>",
    "pdf_url": "https://.../xxxx.pdf",
    "bill_state": 1
  }]
}
```

```python
import requests

for t in range(0, 8):
    r = requests.post("https://target.edu.cn/ebill/query", json={
        "billType": "0", "payerIdType": t,
        "payerIdNo": "2022xxxx", "payer": "张三"
    }, timeout=10)
    j = r.json()
    print(t, j.get("code"), len(j.get("data") or []), str(j)[:120])
```

## 变体与关联

- 变体：其他枚举参数（`queryType`、`idType`、`certType`、`bizType`、`searchType`）同样可枚举隐藏值；隐藏值可能是 0、4、5 或字符串 `student`、`xh`。
- 变体：GraphQL 接口可通过枚举 schema/参数名发现隐藏查询；REST 接口可结合 Swagger/前端 JS 中的常量表推断。
- 变体：隐藏分支若只返回“查询成功”而不回显，可用响应长度、PDF 是否生成、票据号差异做布尔判断。
- 关联：[[pentest-recon-error-driven-api-param-discovery]]（通过报错补全参数）、[[web-generic-auth-miniprogram-appointment-daterange-querytype-pii]]（小程序 queryType 导致 PII 泄露的同类问题）、[[web-generic-auth-freshman-reset-id-last6-public-pii]]（拿到身份证后用于弱口令/重置）。
- 边界：后端对枚举值做严格白名单、隐藏分支已删除、接口要求登录且校验票据归属时，本路径失效；仅返回脱敏证件号时危害降低。

## 检测与防御

- 检测：同一接口在短时间内收到连续递增/异常枚举值；`payerIdType` 等参数出现前端未提供的值；同一来源用不同学号批量查询票据；响应返回完整身份证号/PDF。
- 修复：服务端对枚举参数做白名单校验，未知值直接拒绝；删除测试/历史分支；票据查询要求登录并校验查询人与票据的归属关系。
- 加固：返回字段最小化与脱敏（身份证号只显示后四位）；对查询接口做频率限制与审计；前端下拉框与后端白名单保持一致，但不要依赖前端做安全控制。
