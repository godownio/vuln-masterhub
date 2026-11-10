---
id: web-generic-auth-swagger-unauth-export-xlsx-pii-dump
title: Swagger 文档暴露未鉴权批量导出接口：startIndex/endIndex 控制行数，一次拉取 2000 条含身份证的 xlsx
type: scenario
domain: web
path: web/generic/auth
technique: swagger-unauth-mass-export-pii-dump
tags:
- web
- swagger
- openapi
- authz
- missing-auth
- mass-export
- pii
- data-exfiltration
- recon
cve: []
severity: high
confidence: high
status: verified
created: '2026-02-26'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T14:01:58+08:00'
  notes: 已对照原文核对：i-docs 暴露 api-docs.json、swagger-exp 起本地 UI 试接口、getIntegrationInfoData?startIndex=0&endIndex=2000 返回 {status:2000,msg:success,data:'xxx.xlsx'}、下载 xlsx 含身份证等字段且第 2000 行存在（图 05/06/08/09）均与原文一致。未验证点：文中目标地址与导出文件名未在卡中复现；未实际请求。
url: /docs/web/generic/auth/web-generic-auth-swagger-unauth-export-xlsx-pii-dump/
draft: false
kb_aliases:
- Swagger 导出接口未授权
- startIndex/endIndex 导出
- 人员信息批量导出
- api-docs.json 接口拼接
- swagger-exp
- getIntegrationInfoData
---

## 一句话结论

当 Swagger/OpenAPI 文档在公网暴露（`i-docs`、`api-docs.json`、`/v2/api-docs` 等）且文档里描述的“人员信息导出”接口没有任何鉴权时，攻击者可以直接按文档拼出请求，用 `startIndex=0&endIndex=2000` 让服务端一次性生成并返回 2000 行的 xlsx，文件里就是全量姓名、身份证号、联系方式等 PII；把 `endIndex` 再放大即可分片拉走整库。

## 原理

- Swagger 文档本身就是一份“可信的接口地图”：路径、方法、参数名、参数类型、是否 `required`、响应模型全都写在其中，攻击者无需猜测即可拼出可用请求。文档被暴露（未加访问控制）意味着攻击者拿到了完整接口清单，而接口本身是否鉴权是另一道独立防线。
- 分页参数被设计成“起始行 + 结束行”的直接区间（`startIndex`/`endIndex`），而非受限的 `pageSize`；服务端按区间一次性查询并生成 Excel。区间上限没有服务端裁剪，所以单次请求的返回量由客户端决定，`2000` 甚至更大都能成立。
- 导出接口在多数项目里被当成“内部工具接口”，往往不在网关的鉴权白名单里，或者直接配置为免登录（`permitAll`），因为它需要一个“导出 URL”供前端 `window.open` 直接下载——浏览器新窗口请求带不上自定义鉴权头，于是开发者干脆关掉鉴权，形成典型缺陷。
- 为什么危害大：单条详情接口一次只泄露一个人，导出接口一次泄露一整页 2000 人，且响应是二进制 xlsx，绕开了大部分针对 JSON 响应内容的安全审计与 DLP 规则。
- `api-docs.json` 的另一个价值是给出便于遍历的入口：拿到文档后用 swagger-exp 一类工具把每个接口一键填参试跑，可以快速筛出“200 + 有数据”的未鉴权接口，而不必逐个手工测试。

## 触发条件

- 目标暴露 Swagger/OpenAPI 文档（`/v2/api-docs`、`/swagger-ui.html`、`/doc.html`、`i-docs`、`api-docs.json`）且无访问控制。
- 文档中存在人员/名单类批量导出、报表下载接口。
- 该导出接口未鉴权（或仅前端做了登录校验），且分页区间参数由客户端控制、服务端不限幅。
- 导出文件落在可预测路径或直接以响应体返回，攻击者无需登录即可下载。
- 目标能生成 xlsx（服务端有 POI/EasyExcel 之类依赖）。

## 利用步骤

1. 信息收集阶段发现 `i-docs`/`doc.html`/`swagger-ui` 页面，抓包拿到 `api-docs.json`（或 `v2/api-docs`）并保存成本地文件。
2. 把文档喂给 swagger-exp 之类工具启动本地 Swagger UI，逐条“Try it out”；重点看路径名里带 `export`、`download`、`infoData`、`list`、`page` 的接口。
3. 找到一个返回人员数据的接口后，注意其中的 `startIndex`/`endIndex`（或 `pageNum`/`pageSize`）参数：先小范围试 `0..10`，确认返回结构与文档一致。
4. 放大区间到 `startIndex=0&endIndex=2000`（甚至更大），观察响应体：若返回 `{"status":2000,"msg":"success","data":"<uuid>.xlsx"}` 一类结构，说明服务端已生成文件，取 `data` 里的文件名/路径直接访问下载。
5. 打开 xlsx 抽样确认字段（姓名、身份证号、工号、缴费状态等），再按区间切片（`0-2000`、`2000-4000`…）分片拉取，量化泄露规模。
6. 把“未鉴权 + 单次导出量”两条证据组合成报告：前者证明无需账号，后者证明一次可取 2000 条。

## PoC

```http
GET /schoolOrder/getIntegrationInfoData?startIndex=0&endIndex=2000 HTTP/1.1
Host: target
Accept: */*
```

```json
{"status":2000,"msg":"success","time":"...","data":"<uuid>.xlsx"}
```

随后按 `data` 中的文件名下载：

```http
GET /schoolOrder/<uuid>.xlsx HTTP/1.1
Host: target
```

xlsx 前几行即姓名、身份证号、类别、状态等字段（原文截图可见 2000 行数据与第 2000 行存在）。

如导出接口直接以流返回（无中间文件名），则单请求即得到文件：

```http
GET /api/person/export?startIndex=0&endIndex=5000 HTTP/1.1
Host: target
Accept: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
```

## 变体与关联

- 变体：导出接口要求登录但只校验“有没有 session”，不校验角色/数据范围，任意学生账号即可导出全校名单。
- 变体：`endIndex` 有上限时，可用 `startIndex` 递增分片；也可并发多区间请求加速。
- 变体：文档被关闭但导出 URL 仍可访问（前端 JS 里硬编码导出路径），属于“文档下线 ≠ 接口下线”。
- 变体：同一份文档中的详情接口（如按 id 查人员）也可未授权调用，可与导出接口交叉验证数据真实性。
- 关联：[[web-generic-auth-swagger-unauth-user-management]]（同因 Swagger 暴露导致未授权接口可调，本卡危害为批量 PII 导出）。
- 关联：[[pentest-recon-spring-swagger2-unauth-api-doc-exposure]]（同一次信息收集中的文档暴露阶段；本卡把危害推进到数据导出）。
- 关联：[[web-generic-auth-edu-registration-notice-xsid-idor-enumeration]]（同属教育系统 PII 批量泄露，差别是本卡走导出接口、单请求即整页）。

## 检测与防御

- 防御：Swagger/OpenAPI 文档与 Swagger UI 只在内网/开发环境开放，生产环境关闭或加鉴权（`springfox` 的 `Docket` 只对特定 profile 开启）。
- 防御：导出类接口必须鉴权 + 授权，校验当前用户可导出的数据范围（机构/批次/本人权限），不能以“浏览器直接打开 URL”为由免鉴权；如需免鉴权下载，用一次性签名 token 绑定数据集与有效期。
- 防御：服务端对 `endIndex - startIndex` 做硬上限（如 ≤1000），并限制导出频次、记录审计日志（谁导出了多少行）。
- 防御：响应加 `Content-Disposition`、审计导出行为；对 xlsx 中敏感字段做脱敏（身份证中间位、手机号中间位）。
- 检测：同一 IP/账号短时间多次调用导出接口且区间递增；`endIndex` 参数异常大；导出接口在未登录状态返回 200 并产生文件；`/v2/api-docs`、`/doc.html` 的外网访问日志。
