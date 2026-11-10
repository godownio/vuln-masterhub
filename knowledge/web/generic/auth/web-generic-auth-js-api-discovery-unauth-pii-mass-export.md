---
id: web-generic-auth-js-api-discovery-unauth-pii-mass-export
title: 前端接口发现 + 未授权 API 批量枚举：FindSomething 提取 JS 接口、Intruder 遍历控制器、HAE 标记身份证/手机号并分页导出全量用户 PII
type: scenario
domain: web
path: web/generic/auth
technique: js-api-discovery-unauth-pii-mass-export
aliases:
- FindSomething
- HAE 插件
- 未授权接口爆破
- 敏感信息泄露接口
- 分页批量导出 PII
- api list 未授权
tags:
- web
- api
- authz
- broken-access-control
- pii
- enumeration
- burp
- js
- hae
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V312
  verified_at: '2026-11-08T12:36:01+08:00'
  notes: '已对照原文 content.md 与18张图逐项核对：图10 FindSomething 输出含 IP/域名/身份证/手机号/URL 分类与 /cas/... 接口；图11 Burp Intruder 结果中含 api/sysBlacklist/getList（HAE: Chinese Bank Card ID）与 api/sys/importHistory/getList（HAE: Chinese Mobile Number/Chinese IDCard/Chinese Bank Card ID），响应 pageNum=1/pageSize=10/totalPage=1788/total=17875/list(id/name/idCard/telephone/companyName)，与卡片 PoC 和端点清单一致；原文正文称『成功获取到了上万条敏感信息』。卡片明确截图字段为 null/打码。dedup 除自身外 top 为 related-object 过返、Burp 历史未授权 user/all、const.js 管理员账号+手机号回显，发现方式与利用链均不同；dup-scan pair 26（vs 14381 关联对象过返 PII）与 pair 78（vs 16391 const.js 管理员账号）均为 related 非同一条链，裁决并列保留。未验证点：未实际复跑 Intruder/HAE，未独立确认无 Cookie 请求成功；原文未展示可读 PII 原文（字段为 null）；无版本信息；frontmatter 无 sources/source_url。'
---

## 一句话结论

用 FindSomething 一类插件从前端 JS/页面提取 API 路径，再把控制器与动作名做成字典用 Burp Intruder 批量请求，配合 HAE 对响应中的身份证号、手机号、银行卡号等字段高亮，可以快速发现未做服务端鉴权的 `list/getList` 接口；对返回 `total` 的分页接口逐页拉取，即可批量导出上万条用户 PII。

## 原理

- **接口暴露在前端**：SPA/后台系统的 JS 中通常写有完整 API 路径（`/api/sys/...`、`/api/.../list`），即使菜单/按钮被权限隐藏，路径字符串仍可从 JS 与页面资源中提取。
- **服务端只做“菜单隐藏”**：开发常把权限控制放在前端菜单，后端接口没有功能级/对象级授权；未登录或低权限用户直接请求 `list/getList` 也能返回数据。
- **HAE 降噪**：Burp 的 HAE 插件用正则匹配响应体中的身份证号、手机号、银行卡号、姓名等特征并高亮，攻击者无需逐条阅读响应就能从大量 200/403 中筛出泄露 PII 的接口。
- **分页放大**：响应含 `pageNum/pageSize/total/list` 时，`total` 直接给出数据量，按页参数遍历即可全量导出；接口若还支持 `pageSize` 放大，可进一步减少请求数。
- **为什么成立**：认证/授权缺口 + 前端泄露接口 + 可枚举分页，三者叠加使“无账号”也能批量取数。

## 触发条件

- 目标为前后端分离/后台类系统，前端 JS 与接口路径可访问。
- 列表/查询类接口没有服务端鉴权（未登录可直接请求），或仅校验登录不校验数据范围。
- 响应包含身份证、手机号、银行卡号等 PII 字段，且分页参数由客户端控制。
- 测试在授权范围内；批量拉取需控制速率，避免影响业务。

## 利用步骤

1. 浏览目标前端，使用 FindSomething（或手工在 JS/`app.*.js`/`chunk-*.js` 中搜索 `/api/`、`url:`）提取接口路径，记录控制器前缀与动作名。
2. 把控制器与常见动作（`list`、`getList`、`page`、`export`、`detail`、`statistics`）组合成字典，用 Burp Intruder 对接口路径做批量请求（无 Cookie/低权限 Cookie 各测一轮）。
3. 开启 HAE 规则（Chinese IDCard、Chinese Mobile Number、Chinese Bank Card ID、姓名等），在 Intruder 结果中按高亮/注释筛选返回 200 且含 PII 的接口。
4. 对命中的接口查看响应结构：`total/totalPage/pageSize/list`；用 `pageNum` 逐页请求，或用 `pageSize` 放大单页数量。
5. 抽样核对数据真实性与归属，记录请求/响应作为证据；不要长时间高频遍历。

## PoC

Burp Intruder 请求模板（示意，路径来自原文 Intruder 结果）：

```http
POST /api/sys/importHistory/getList HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 2

{"pageNum":1,"pageSize":10}
```

响应结构（原文截图，字段已打码/置空）：

```json
{
  "message": "操作成功",
  "data": {
    "pageNum": 1,
    "pageSize": 10,
    "totalPage": 1788,
    "total": 17875,
    "list": [
      {"id": "...", "name": null, "idCard": null, "telephone": null, "companyName": null}
    ]
  }
}
```

原文 Intruder 中其它同类端点：`api/sysBlacklist/getList`、`api/sysmag/report_statistics/list`、`api/sysmag/warn_detail/list`、`api/sys/systemParam/getList`、`algorithmEntity/listAlgorithm`；HAE 命中注释为 `Chinese Mobile Number / Chinese IDCard / Chinese Bank Card ID`。

## 变体与关联

- **接口来源**：JS 路由常量、sourcemap、Swagger/OpenAPI 文档、错误信息、目录扫描；见 [[pentest-recon-sourcemap-leak-frontend-source-restore-api-discovery]]、[[pentest-recon-webpack-apiurlkey-endpoint-extraction]]。
- **越权写操作**：同一批隐藏接口若返回 `id`，可继续测试 `update/delete/detail` 的对象级授权，见 [[web-generic-auth-js-route-leak-idor-update-delete]]。
- **参数级 PII 枚举**：[[web-generic-auth-api-param-fuzz-idcard-pii-enumeration]]。
- **边界**：接口有统一网关鉴权、按租户/用户过滤、PII 脱敏或加密、批量请求触发风控时，只能拿到空数据或受限数据；`total` 大不代表全部可拉取。

## 检测与防御

- **服务端授权**：所有接口在服务端做功能级与对象级授权；列表接口必须绑定当前用户/租户范围，不能依赖前端菜单隐藏。
- **最小返回**：列表接口默认脱敏（身份证/手机号掩码），敏感字段单独授权；导出接口加二次校验与审计。
- **限速与监控**：对分页遍历、异常高频请求、未登录访问敏感接口做限流与告警；HAE 类工具无法从服务端防，但请求模式可检测。
- **暴露面收敛**：生产环境关闭 Swagger/sourcemap，JS 不硬编码未使用接口；统一网关做鉴权与参数校验。
