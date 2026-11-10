---
id: web-generic-auth-endpoint-granularity-unauth-list-bulk-pii
title: 接口粒度权限校验不一致：替换路径段 queryById 为 list 绕过鉴权批量拉取 PII
type: scenario
domain: web
path: web/generic/auth
technique: 接口级鉴权不一致未授权访问
aliases:
- queryById 改 list 未授权
- 鉴权粒度不一致
- jeecg list 未授权
tags:
- auth
- unauthorized
- idor
- bulk-data-leak
- jeecg
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-26
  verified_at: '2026-11-08T14:25:27+08:00'
  notes: 已对照原文核对：图7 queryById 归属校验 401、图8 list 接口可枚举、图14 queryById 替换为 list 未授权返回、图15 total 7802、图16 pageSize=7802 全量 PII，请求/响应截图证据齐全，链路成立；与 user-all 卡鉴权缺口类型不同（接口粒度不一致 vs 无鉴权接口）；未验证点：目标为授权渗透现场，无法复测
---

# 接口粒度权限校验不一致：替换路径段 queryById 为 list 绕过鉴权批量拉取 PII

## 一句话结论

单条查询接口（如 `/uniapp/wxUser/queryById?id=`）对 X-Access-Token 做了用户归属校验、替换他人 id 即返回 401，但同控制器的分页列表接口 `/uniapp/wxUser/list` 未做同等的鉴权与数据过滤，把路径段从 `queryById` 改写为 `list` 并附加 `pageNo/pageSize` 即可未授权分页拉取全部用户敏感信息（姓名、身份证、手机号等，本例 7802 条）。

## 原理

框架（jeecg-boot 系）的 Shiro/JWT 过滤器通常按注解或路径模式对接口做认证，而"数据是否属于当前用户"的校验写在单条查询方法内部（queryById 里校验 id 归属），列表方法只做了登录态校验甚至完全放行——不同接口对同一资源的鉴权粒度不一致。因此攻击者虽然无法越权读单条，却可以直接调用同资源的列表接口批量读全部：绕过的不是认证而是授权粒度缺口。特征上，jeecg 框架可从 URL 关键字识别（`/jeecg`、`/sys`、`/system`、`/uniapp` 等）。

## 触发条件

- 存在按 id 查询的接口且响应含 PII 字段（idcard、realNameAuth 等）；
- 同一控制器/资源存在 list 类分页接口；
- 列表接口未复用单条接口的归属校验（常见于快速开发框架生成的 CRUD）。

## 利用步骤

1. 从小程序/前端流量中确定 `GET /uniapp/wxUser/queryById?id=<自己id>` 返回含敏感字段；
2. 用他人 id 或随机 id 重放该接口，返回 `{"success":false,"message":"账号有问题","code":401}`，确认存在归属校验；
3. 检查历史流量中的 list 类路径（如 `/sys/.../queryTreeList`），把 `queryById` 段直接替换为 `list`：`GET /uniapp/wxUser/list`，得到 200 与分页数据（total: 7802）；
4. 构造 `list?pageNo=1&pageSize=7802` 一次性拉取全部记录；
5. 若 JWT 密钥可爆破（工具无影等字典未命中时），还可进一步伪造 token 扩大危害，但列表接口未授权本身已足够批量泄露。

## PoC

`GET /uniapp/wxUser/list?pageNo=1&pageSize=7802 HTTP/1.1`（携带任意有效登录态或不带敏感头即可，具体以目标过滤器实现为准）。

## 变体与关联

- 同类粒度缺口：export/count/detail 等旁路接口、GraphQL 单字段 vs 聚合查询；
- 拿到列表中的上传文件路径字段后可拼接静态资源路由批量下载用户证件照（见文件路径拼接下载卡）；
- 与 openid 泄露+可枚举查询链卡的区别：那条链靠泄露 openid 逐条查询，本场景直接替换接口名批量获取。

## 检测与防御

- 对同一资源的所有接口（queryById/list/export）统一做数据归属校验（MyBatis 拦截器或统一数据权限层），而非仅在单条接口实现；
- 上线前对 list 类接口做未授权扫描；日志监控 `pageNo/pageSize` 超大分页请求；
- 响应最小化：列表接口不应返回 idcard 等敏感字段明文。
