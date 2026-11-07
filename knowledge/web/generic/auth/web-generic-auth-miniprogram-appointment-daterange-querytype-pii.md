---
id: web-generic-auth-miniprogram-appointment-daterange-querytype-pii
title: 小程序预约单查询：修改日期区间与 queryType 越权拉取全量用户预约与手机号
type: scenario
domain: web
path: web/generic/auth
technique: appointment-query-daterange-querytype-mass-data-exposure
aliases:
- 预约单越权
- startDate endDate 参数篡改
- queryType 越权
- 小程序预约数据泄露
- 查询范围未绑定用户
tags:
- idor
- access-control
- data-exposure
- miniprogram
- api
- pii
- business-logic
- date-range
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:24:08+08:00'
  notes: 已对照原文与10张截图核对：请求字段 startDate/endDate/queryType/dataSource、queryType=0 后响应 Content-Length 2,136,080、跨单位预约记录（含单位/手机号/车牌/状态）均与卡片一致；原文未展示后端代码与接口真实路径，卡片已标注按行为推断、confidence medium、字段名以目标为准。未复现。
---

## 一句话结论

小程序的“我的预约单”查询接口只按客户端提交的 `startDate`/`endDate`/`queryType` 过滤数据，没有把查询范围绑定到当前登录用户或租户；普通用户把日期区间扩大到数年、把 `queryType` 改为全量分支后，接口返回所有单位、所有用户的预约单，包含姓名、单位、手机号、车牌号等敏感信息。

## 原理

- 预约类业务接口通常接收时间区间与查询类型：`startDate`/`endDate` 控制返回范围，`queryType`/`dataSource` 选择“我的/全部/某状态”等查询分支。若后端直接把前端参数拼进查询条件，而没有强制附加 `user_id`/`tenant_id` 等会话身份条件，参数就成为数据范围的唯一边界。
- `queryType` 是权限分发的常见盲点：前端用它区分“我的预约”“部门预约”“全部预约”，后端若只按值分支查询、不校验当前用户是否有权查看该分支，普通用户传 `0`（或管理端取值）即可命中全量查询。
- 日期区间决定返回量。默认只查近期数据时泄露有限；把 `startDate` 提前到数年前、`endDate` 推后到未来，会一次性拉取全量历史记录。
- 响应直接把数据库行序列化返回，未做字段级脱敏，因此 PII（姓名、手机号、单位、车牌号、预约状态等）随记录一起泄露。返回体可达数 MB 量级，说明是全量而非当前用户数据。
- 泄露的手机号可直接作为其他系统的账号标识，与同单位的另一小程序登录缺陷组合后可进一步接管账号。

## 触发条件

- 存在面向小程序的预约/订单/记录查询接口，接受客户端可控的日期区间与查询类型参数。
- 服务端未把查询范围绑定当前会话用户/租户，或仅在前端做权限判断。
- `queryType` 等分支参数没有服务端权限校验，存在全量/管理分支可被普通用户命中。
- 响应返回未脱敏的敏感字段（姓名、手机号、单位、车牌等）。
- 攻击者拥有一个可正常登录的低权限账号。

## 利用步骤

1. 正常登录小程序，进入“我的预约单”等列表页，抓取查询请求。
2. 记录请求字段：`startDate`、`endDate`、`queryType`、`dataSource` 及分页参数。
3. 先小幅度修改日期区间，观察返回条数与内容是否变化，确认参数是否直接控制查询范围。
4. 将 `startDate` 改为数年前（如 2021-01-01）、`endDate` 改为未来日期，扩大返回量。
5. 枚举 `queryType` 取值（0/1/2/…），观察是否出现“全量/其他单位/其他状态”分支；关注响应长度与记录归属。
6. 确认返回记录来自其他用户/单位后，评估泄露字段（姓名、手机号、单位、车牌号等）与影响范围；按授权要求控制导出量。
7. 将泄露的手机号用于关联其他系统（如学员平台登录），验证是否能进一步接管账号。

## PoC

关键请求形态（字段名以目标为准）：

```http
POST /api/appointment/list HTTP/1.1
Content-Type: application/json
Cookie: <低权限用户会话>

{"startDate":"2021-01-01","endDate":"2026-05-06","queryType":0,"dataSource":"APPLET"}
```

响应为全量预约记录数组，单次响应可达 2 MB 以上，字段示例：

```json
{"code":200,"msg":"操作成功","data":[{"id":2,"name":"<单位名称>","telephone":"<手机号>","carNumber":"粤<...>","startDate":"2021-...","endDate":"2026-...","status":1,"statusEnum":"已通过"}]}
```

判定要点：返回记录中的单位/姓名/手机号明显不属于当前登录用户；响应长度随日期区间和 `queryType` 显著变化；分页拉取可覆盖多年历史数据。

## 变体与关联

- 变体（参数名）：`startDate`/`endDate`、`beginTime`/`endTime`、`startTime`/`endTime`、`dateRange`；`queryType`、`queryTypeId`、`type`、`scope`、`dataSource`、`source`。
- 变体（越权维度）：时间区间、状态、部门/单位 ID、`dataSource`（APPLET/PC/管理端）、导出接口；导出接口常绕过列表分页，泄露量更大。
- 变体（无认证）：部分小程序接口可能仅校验签名或完全不校验登录，未授权即可拉取。
- 关联：[[web-generic-auth-wechat-miniprogram-sessionkey-encrypteddata-takeover]]（本卡泄露的手机号可作为该链的目标账号标识，两链组合形成完整接管）。
- 关联：[[web-generic-auth-missing-function-level-role-check]]（功能级权限缺失的通用模式）。
- 关联：[[web-generic-auth-type-dispatch-unauth-data-exposure]]（按 type 分发返回全量数据的同类问题）。
- 边界：若服务端强制按会话用户过滤、`queryType` 由服务端映射且校验角色、或响应做字段脱敏，则本链不成立；原文未展示后端代码，根因按请求/响应行为推断，confidence 标 medium。

## 检测与防御

- 根本修复：查询条件由服务端根据会话用户/租户生成，客户端传入的日期、状态、部门等只能作为附加过滤，不能替代身份条件。
- 权限校验：`queryType`/`scope` 等分支必须在服务端做角色校验，普通用户只能命中“本人/本租户”分支；管理端分支使用独立接口与鉴权。
- 数据最小化：返回字段白名单，手机号/车牌号/身份证等按需脱敏；禁止直接序列化数据库行。
- 查询约束：限制最大日期跨度、强制分页与单页上限、对导出接口单独授权与审计。
- 检测：同一账号短时间内拉取跨越数年的数据；响应体异常增大（MB 级）；`queryType` 从默认值改为 0/管理值；访问记录中出现其他单位/租户的数据；分页遍历全量历史。
- 运营：对预约/订单查询接口做速率限制与数据量告警；定期审计接受日期区间/类型参数的接口是否存在数据范围越权。
