---
id: web-generic-auth-patient-infocode-idor-pii-enumeration
title: 就诊人信息接口按 patMiCode 顺序枚举：三要素明文越权泄露
type: scenario
domain: web
path: web/generic/auth
technique: patient-infocode-idor-pii-enumeration
aliases:
- queryPatientBaseInfo 越权
- patMiCode 枚举
- 就诊人三要素泄露
- 医疗 PII 越权
- 顺序 IDOR
- 姓名身份证手机号明文
tags:
- web
- auth
- idor
- access-control
- pii
- api
- healthcare
- enumeration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V72
  verified_at: '2026-11-05T16:36:21+08:00'
  notes: 已对照原文与图11-13核对：POST /api/rest/ssrm/wxgzh/queryPatientBaseInfo 明文JSON传 patMiCode，响应含 name/identityCode/tel/sex/birthDate 等；Intruder 23100097 起递增均200、长度1024，注释显示手机号/用户名/身份证。卡内路径原写 ssm 少一个 r，已修正为截图所示 ssrm；未本地复现
---

## 一句话结论

医院服务号的就诊人信息接口 `POST /api/rest/ssrm/wxgzh/queryPatientBaseInfo` 只根据请求体里的 `patMiCode`（就诊卡/患者编号）返回数据，不校验该患者是否属于当前登录用户；而 `patMiCode` 是连续数字，登录任意账号后用 Intruder 顺序递增即可批量拿到全量就诊人的姓名、身份证号、手机号、出生日期等三要素明文。

## 原理

- 对象级授权（object-level authorization）要求服务端在返回某个对象前，确认当前会话主体有权访问该对象。该接口只做了“已登录”校验，没有做“这个 patMiCode 对应的患者是否属于当前用户”的校验。
- `patMiCode` 是患者主索引/就诊卡号，文章示例为 `23100097`、`23100098`……连续递增；攻击者只需在请求体里替换该值即可横向遍历不同患者。
- 响应 `data` 返回 `name`、`sex`、`identityCode`（身份证号）、`birthDate`、`patMiCode`、`cardList`、`tel`（手机号）、`createUser`、`maritalStatus`、`statusCode`、`createDate` 等字段；姓名+身份证+手机号即“三要素”，可直接用于实名认证绕过、社工、诈骗、账号注册等。
- 文章在通过短信验证码回显登录任意手机号后，进入业务页面抓到该接口；用 Burp Intruder 对 `patMiCode` 从 23100097 递增到 23100119 等，所有请求均 200、响应长度 1024，注释显示每条都含手机号/用户名/身份证，证明可批量枚举。
- 接口使用明文 JSON 传参（未加密/未签名），进一步降低了利用门槛；只要有一个有效会话（甚至可以是通过其他缺陷拿到的任意账号），就能拉取全量 PII。

## 触发条件

- 攻击者拥有一个有效会话（任意患者/普通账号即可；文章通过短信验证码回显获得）。
- `queryPatientBaseInfo`（或同类就诊人/患者信息接口）可达，请求体包含可预测的患者编号 `patMiCode`。
- 服务端未做对象级授权（不校验患者与当前用户/家庭的绑定关系），且返回身份证、手机号等敏感字段。
- 编号连续或可按规则预测；接口无限流/审计阻断。

## 利用步骤

1. 登录任意账号，进入“就诊人/个人中心/预约”等功能，抓取查询就诊人信息的请求。
2. 确认请求体字段：文章为 `{"patMiCode":"23100097","s_v_t":"<会话令牌>"}`，响应含 `data.name`、`data.identityCode`、`data.tel` 等。
3. 把 `patMiCode` 放入 Burp Intruder 的 payload 位置，设置数字递增（如 23100097→23100120），并发/顺序发送。
4. 按响应长度/状态码筛选成功记录（文章全部 200、长度 1024），导出响应中的姓名、身份证、手机号。
5. 扩大到更大范围前先评估限流与告警；仅在授权范围内测试，避免大规模拉取真实患者数据。
6. 用泄露的三要素评估影响：实名认证、账号注册/找回、社工与诈骗风险；报告中给出字段与样本（脱敏）。

## PoC

```http
POST /api/rest/ssrm/wxgzh/queryPatientBaseInfo HTTP/1.1
Host: <target>
Content-Type: application/json
Cookie: <有效会话>

{"patMiCode":"23100097","s_v_t":"<会话令牌>"}
```

```json
{
  "data": {
    "name": "<姓名>",
    "sex": "1",
    "identityCode": "<身份证号>",
    "birthDate": "1992-...",
    "patMiCode": "23100097",
    "cardList": [{"cardCode": "...", "cardType": "1"}],
    "nationality": "156",
    "identityType": "1",
    "tel": "<手机号>",
    "createUser": "...",
    "maritalStatus": "10",
    "statusCode": "ACTIVE",
    "createDate": "..."
  },
  "resultCode": 1,
  "resultMessage": "查询成功"
}
```

```text
# Burp Intruder：patMiCode = 23100097..23100120
# 结果均为 200、响应长度约 1024，注释含“手机号/用户名/身份证”
```

## 变体与关联

- 变体：其他对象标识（patientId、visitId、orderId、reportId、cardNo）同样可枚举；接口可能是 GET query 参数或 GraphQL 字段。
- 变体：接口要求 `s_v_t`/token，但 token 只校验登录不校验对象归属；任意有效会话即可。
- 变体：返回字段可能被部分脱敏；可继续找详情、导出、报告下载等接口获取完整值。
- 边界：服务端做对象级授权（患者与当前账号/家庭绑定）、编号为随机 UUID、接口限流/风控严格时，本手法不成立或只能拿到少量数据。
- 关联：[[web-generic-auth-sms-code-echo-response-arbitrary-login]]（本文获取任意会话的入口）、[[web-generic-auth-miniprogram-appointment-daterange-querytype-pii]]（同类医疗 PII 越权查询）、[[web-generic-auth-authenticated-change-password-idor]]（对象级授权缺失的另一表现）、[[web-generic-auth-multi-session-matrix-leakscore]]（登录后权限矩阵测试方法）。

## 检测与防御

- 检测（测试方）：抓取所有带对象 ID 的查询接口，替换为其他用户/其他编号，观察是否返回数据；用递增/递减 ID 与响应长度差异判断可枚举性。
- 检测（防御方）：监控同一账号短时间查询大量不同 `patMiCode`、响应 200 比例异常、单 IP 高频访问患者信息接口；对敏感字段访问做审计。
- 修复：所有患者数据接口做对象级授权，校验 `patMiCode` 属于当前登录用户/家庭/授权范围；使用不可预测的随机 ID 或服务端映射，不暴露连续主键。
- 加固：返回字段最小化/脱敏（身份证、手机号掩码）；接口限流与风控；敏感查询二次认证；日志审计与异常告警。
