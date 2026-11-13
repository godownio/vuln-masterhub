---
id: web-generic-auth-order-query-common-api-unmasked-phone
title: 页面脱敏≠接口脱敏：订单查询页手机号打码，但刷新抓 common 接口响应可读到原始号码
type: scenario
domain: web
path: web/generic/auth
technique: order-query-common-api-unmasked-pii
aliases:
- 前端打码 接口明文
- 页面脱敏绕过
- common 接口 手机号泄露
- 订单查询 PII 泄露
- 客户端掩码
- XHR 响应 原始手机号
tags:
- web
- auth
- pii
- data-exposure
- api
- masking
- xhr
- src
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V668
  verified_at: '2026-11-13T10:01:04+08:00'
  notes: 已对照原文与截图14核对：页面手机号显示为 182******40 等掩码，同时打开的 DevTools Network 中 common?changeFlow&rand... 请求的 Response 为 resultcode/resultinfo/list/output2 结构；原文文字明确称 common 接口可见原手机号，但文中贴出的 moblileNum 均被作者改写打码（175*******6 等），卡内 confidence=medium 并已如实注明依据，未夸大。接口名、output1/output2 结构与原文一致。未验证点：截图中响应可见部分未直接露出 moblileNum 明文，实际接口是否返回原始号码依赖原文陈述，未在原文之外复现。
---

## 一句话结论

充值/订单查询页把手机号显示成 `182******40` 这类掩码，但列表数据来自前端 XHR；刷新后在开发者工具里查看负责取数的 `common` 接口响应，`resultinfo.list[].output2` 的订单数组中仍带 `moblileNum` 等原始字段——掩码只做在展示层，数据层并未脱敏，任何能打开该页面（或被搜索引擎收录的 `openid`+`sign` 链接）的人都能读到原始号码。

## 原理

- **展示与数据两条路径**：页面渲染时由 JavaScript 对手机号做掩码（或后端返回两份字段，前端只展示脱敏字段），但填充列表的 XHR 响应本身携带完整数据；掩码只是渲染函数，不改变响应内容。
- **接口结构**：原文案例中页面请求 `common`（URL 形如 `Common?changeFlow&rand...`），响应为 `{"resultcode":0,"resultinfo":{"errMsg":"查询成功","list":[{"output1":"0","output2":"[{\"payTime\":...,\"payFee\":...,\"itemName\":...,\"moblileNum\":\"...\",\"dealId\":...,\"dealState\":...},...]"}]}}`——订单数组被序列化成字符串放在 `output2` 里，逐条包含手机号、金额、商品名、订单号。
- **访问入口可被索引**：该查询页 URL 带 `openid` 与 `sign`（`https://domain/xxxx?openid=xxxx&sign=xxxxx`），搜索引擎收录后链接本身即访问凭据；配合订单相关 dork 可批量找到同类页面。
- **为什么算泄露**：页面已用掩码向用户暗示“号码已保护”，但浏览器端能拿到原文；对共享设备、日志/代理、前端 JS 注入或任何能看到响应的人，掩码不构成安全边界。若后端返回的是他人订单数据，则同时构成越权 + PII 泄露。
- **边界**：原文贴出的响应中号码已被作者打码（`175*******6` 等），因此“接口返回原始号码”依据的是原文文字描述与截图，未在卡内复现；部分系统的掩码字段与完整字段并存（完整字段可能只在特定角色/接口出现），需按实际响应判断。

## 触发条件

- 业务页面展示打码的手机号/身份证等 PII，数据由前端 XHR 异步加载。
- 取数接口在响应中返回原始（未脱敏）字段，且接口可被当前访问者调用（或被收录的签名链接可直接访问）。
- 攻击者/测试者能使用浏览器开发者工具或代理查看响应；页面未被服务端字段级权限限制。

## 利用步骤

1. 打开订单/充值查询页，确认页面显示的手机号等字段为掩码。
2. 打开开发者工具 Network（或 Burp 等代理），清空记录后刷新页面。
3. 找到填充列表的 XHR（原文为 `common` 接口），查看 Response；展开 `resultinfo.list`，把 `output2` 字符串解析为 JSON 数组。
4. 检查 `moblileNum` 等字段是否为原始号码；若为原文则确认掩码仅前端渲染。
5. 结合搜索引擎语法找更多带 `openid`/`sign` 的同类页面（见关联卡），或在同一接口上测试参数变化能否取到他人订单。

## PoC

```http
GET /<path>/Common?changeFlow&rand=<随机数> HTTP/1.1
Host: <target>
Cookie: <会话/签名参数>
```

```json
{"resultcode":0,"resultinfo":{"errMsg":"查询成功","list":[{"output1":"0","output2":"[{\"payTime\":\"...\",\"payFee\":\"3000\",\"itemName\":\"...\",\"moblileNum\":\"<原始手机号，原文已打码>\",\"dealId\":\"...\",\"dealState\":\"5\"}]"}]}}
```

说明：请求路径与参数按原文截图（`common` 接口名、`output1`/`output2` 结构）整理，域名与手机号已脱敏；原文未给出完整可复现请求，卡内 confidence 为 medium。

## 变体与关联

- [[web-generic-auth-resume-download-unmasked-pii-leak]]：页面脱敏但下载文件含完整 PII，与本卡“展示层脱敏、数据层明文”同源，出口不同（文件 vs XHR）。
- [[web-generic-auth-related-object-pii-overreturn]]：接口过返关联对象 PII，本卡是同一接口列表中的主体字段未脱敏。
- [[web-generic-auth-js-api-discovery-unauth-pii-mass-export]]：从前端 JS 发现未授权 PII 批量导出接口。
- [[pentest-recon-search-dork-order-detail-idor-mass-hunt]]：用搜索引擎批量发现带 `openid`/`sign` 的订单查询页。
- 变体：掩码可能在 JS 中实现，可搜索 `substring`/`replace`/`****` 等前端掩码函数；也可测试导出、打印、分享、消息推送等旁路是否带完整字段；GraphQL/WebSocket 等通道同样要检查响应原文。
- 边界：接口若要求签名且签名绑定用户，则只能看到本人数据；需先确认越权或链接泄露范围再定级。

## 检测与防御

- 检测：前端代码中出现手机号/身份证掩码函数（`****`、`substr`、`replace`），而对应接口响应含完整字段；同一字段在响应中既存在明文又存在掩码版本。
- 检测：搜索索引中出现带 `openid`/`sign` 的查询页；未登录或低权限请求即可返回含 PII 的订单数组。
- 防御：在服务端做字段级脱敏（返回前替换中间位），不要依赖前端渲染；按角色返回不同字段；签名链接设置有效期、绑定会话并加 `noindex`；对接口响应做 PII 扫描。
- 响应：轮换泄露的 openid/sign、清理搜索索引、评估受影响订单范围并通知。
