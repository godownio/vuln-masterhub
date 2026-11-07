---
id: web-java-component-finereport-builtin-user-default-password
title: 帆软 FineReport 内置测试用户统一默认口令 123456 登录管理后台（CNVD-2024-37222）
type: scenario
domain: web
path: web/java/component
technique: finereport-builtin-user-default-password
aliases:
- CNVD-2024-37222
- 帆软弱口令
- FineReport 默认口令
- FineReport 内置测试用户
- 123456 弱口令
tags:
- java
- finereport
- default-credentials
- weak-password
- cnvd-2024-37222
- admin-panel
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 非运维平台部署的 FineReport 工程（内置测试用户未删除且口令未修改）
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:25:39+08:00'
  notes: 已对照原文与图01/02核对：CNVD-2024-37222，非运维平台部署工程；图02用户管理可见Alice/Anna/Billy/Cherry/demo/eoco/hanwen/Jack/Jenny/Lily/Lisa/Mike/sunlin/Tom/wangwei等内置用户且启用，原文称密码均为123456可登录后台，与卡一致；受影响的非版本区间字段保留。未本机复现登录。frontmatter 无 sources/source_url。
---

## 一句话结论

非运维平台部署的 FineReport 工程会保留一批内置测试用户（Alice、Billy、Cherry、demo、Jack、Mike、Tom 等），这些账号的统一初始密码为 `123456`；任意一个账号即可登录数据决策系统后台，获得该账号对应角色（部分为管理/开发/领导角色）的权限，并为后台接口类漏洞提供入口。

## 原理

- FineReport 的数据决策系统内置了演示/测试用户用于产品体验和权限示例；正常交付时应删除或重置，但非运维平台部署的工程经常原样保留。
- 这些内置账号共享同一个初始口令 `123456`，且用户名可从登录页、用户管理页或产品文档/默认列表中枚举。
- 登录成功后服务端只按账号角色授权；内置账号中存在“技术支持-部长”“开发-部长”“领导部-president”等较高权限角色，可直接访问用户管理、插件管理、数据连接、定时调度等功能。
- 弱口令本身不是代码缺陷，但它把“需要管理员权限才能触发”的后台漏洞（如 `/remote/design/channel` 反序列化、插件安装、数据连接配置）变成可实际利用的入口。

## 触发条件

- 目标为非运维平台部署的 FineReport 工程。
- 内置测试用户未被删除，或未被强制修改初始密码。
- 登录入口 `/webroot/decision/login` 对攻击者可达。
- 目标未对内置用户名做禁用、IP 限制或登录告警。

## 利用步骤

1. 访问登录页，确认产品为 FineReport 数据决策系统。
2. 使用内置用户名列表逐个尝试，口令统一为 `123456`：`Alice`、`Anna`、`Billy`、`Cherry`、`demo`、`eoco`、`hanwen`、`Jack`、`Jenny`、`Lily`、`Lisa`、`Mike`、`sunlin`、`Tom`、`wangwei`、`zhangsan`（不同版本可能略有差异）。
3. 登录成功后查看当前账号角色；若为普通角色，继续尝试列表中其他账号，优先 `Mike`、`Alice`、`Tom` 等管理/领导角色。
4. 使用后台权限扩大影响：用户管理、插件管理、数据连接、定时调度、远程设计等。
5. 若目标是 V11 且要利用 `/remote/design/channel`，用该账号走远程设计 token 流程获取 JWT，再带 `username`/`token` 头调用（见关联卡片）。

## PoC

无 HTTP PoC；原文为界面登录验证：在登录页输入任意内置用户名 + 密码 `123456`，即可进入后台，用户管理页可见上述账号均处于启用状态。

## 变体与关联

- 同一口令可能被运维复用到其它系统；拿到后台后可在“用户管理”中查看/重置更多账号。
- 与 [[web-java-deserialization-finereport-channel-gzip-safeinvocation]] 组合：V11 的 channel 反序列化需要后台/远程设计权限，弱口令正好提供凭据。
- 与插件安装、数据连接 JDBC、定时调度等后台功能组合可进一步到 RCE，但均需相应角色权限。
- 边界：如果工程由运维平台部署、内置用户已删除或已改密，此入口不成立。

## 检测与防御

- 删除 FineReport 内置测试用户，或首次上线时强制重置所有账号口令。
- 实施口令策略（长度、复杂度、定期更换），禁止 `123456` 一类弱口令；对管理/开发角色启用多因素认证。
- 限制 `/webroot/decision/login` 与后台管理界面的来源 IP；对内置用户名登录、短时间多账号尝试做告警与锁定。
- 审计用户列表：检查是否仍存在 Alice/Billy/Cherry/demo/Jack/Mike/Tom 等默认账号及启用状态。
- 检测：登录日志中出现内置用户名 + 同一口令、同一 IP 轮换多个用户名、非工作时间管理后台登录。
