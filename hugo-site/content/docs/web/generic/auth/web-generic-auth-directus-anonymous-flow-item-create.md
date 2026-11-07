---
id: web-generic-auth-directus-anonymous-flow-item-create
title: Directus Webhook Flow 匿名触发 item-create：permissions=$full 以系统身份写库
type: scenario
domain: web
path: web/generic/auth
technique: unauth-webhook-flow-system-item-create
tags:
- directus
- flow
- webhook
- unauthorized
- accountability
- item-create
- database-write
- nodejs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V67
  verified_at: '2026-11-05T11:54:42+08:00'
  notes: 已对照原文全文与12张内联截图核对：/flows/trigger/:pk 路由仅 checkIsLocked、runWebhookFlow 不校验调用者、executeOperation accountability 硬编码 null、创建 accountability=all 的 webhook Flow、匿名 POST 触发 item-create 返回 [1]、管理员查到 notes 集合记录，均与原文一致；'12.2.0（原文实测）'只是实测环境版本，已按核对规则清除 affected_versions。未验证点：未实际执行 PoC；卡内'触发 accountability 须允许匿名，否则匿名无法触发'为基于原文配置的合理推断；exec 逃逸失败按原文未单独立卡；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-directus-anonymous-flow-item-create/
draft: false
kb_aliases:
- Directus 匿名 Flow 写库
- /flows/trigger 未授权写操作
- Directus item-create 系统身份
- accountability null 写库
- Directus Webhook Flow 未授权
---

## 一句话结论

Directus 的 Webhook Flow 触发器 `/flows/trigger/<uuid>` 没有认证中间件，只要知道 Flow 的 UUID，任何人都能匿名触发；若 Flow 含 `item-create` 操作且 permissions 配成 `$full`，该操作会以系统身份（accountability 为 null）写入数据库，形成未授权写库。

## 原理

- Flow 是 Directus 的可视化自动化工作流，Webhook 触发器把 `GET/POST /flows/trigger/:pk` 注册为公开路由；源码中该路由只挂了 `checkIsLocked('flows')`（流程是否锁定），没有任何认证中间件。
- `runWebhookFlow(id, data, context)` 从内存表 `webhookFlowHandlers` 中按 id 取 handler，找到就执行，全程不检查调用者身份；唯一门槛是 Flow 的 UUID 是否已知。UUID 有 122 位随机熵，但会出现在活动日志、分享链接、前端状态等位置，泄露途径不少。
- `executeOperation` 调用 handler 时把 `accountability` 硬编码为 `null`。在 Directus 中 accountability 为 null 即系统身份，绕过所有权限校验。
- `item-create` 操作的 permissions 有三个取值：`trigger` 用触发者身份、`public` 用公开身份、`$full` 用系统身份。管理员配置自动化 Flow 时，为了让流程不受权限限制，选 `$full` 很常见；但配完后这个 Webhook 一触发，就是系统级写操作，界面上没有警告。
- 为什么管理员会配出这种 Flow：Webhook Flow 的典型用途是给外部系统回调入口（订单推送、第三方通知），外部系统没有 Directus 账号，触发 accountability 常设为 `$all`；“谁能触发”和“操作以什么身份执行”是两个独立配置，组合起来就是匿名可调、以系统权限写库的 API。
- 同一入口还可承载 `request`（系统身份 SSRF）和 `exec`（isolated-vm 内执行 JS）操作；本条聚焦 `item-create` 的未授权写库。

## 触发条件

- Directus 实例存在 status 为 active、trigger 为 webhook 的 Flow，且链路上包含 `item-create` 操作，permissions 为 `$full`（或等价系统身份）。
- 攻击者知道该 Flow 的 UUID。
- Flow 的触发 accountability 允许匿名（`$all` 或等价配置）；若设为 trigger/用户身份，匿名请求无法触发。
- Flow 已加载生效；新建 Flow 在原文环境中需要重启容器才生效，否则触发报 403 且日志提示找不到 webhook flow。

## 利用步骤

1. 收集 Flow UUID：活动日志、分享链接、前端状态、备份/错误响应等。
2. 确认触发方法：Webhook 路由 key 为 `${method}-${flowId}`，Flow 未配 method 时默认 GET；POST 触发可能 404/403，改 GET 或按配置的方法。
3. 不带任何 token，向 `/flows/trigger/<uuid>` 发送 JSON 触发数据。
4. 观察响应：`item-create` 成功时通常返回新记录 id（如 `[1]`）或 Flow 的 `$last` 结果。
5. 用管理员账号查询目标集合，确认匿名请求写入的记录。

## PoC

```bash
# 匿名触发 item-create Flow（无 Authorization 头）
curl -s -X POST 'http://target:8055/flows/trigger/<flow_uuid>' \
  -H 'Content-Type: application/json' -d '{"msg":"hello"}'
# [1]

# 管理员查看写入结果
curl -s 'http://target:8055/items/notes' -H "Authorization: Bearer $TOKEN"
# {"data":[{"id":1,"title":"pwned-by-anon"}]}
```

```text
# 最小 Flow 配置（管理员侧，用于复现条件）
# trigger: webhook, status: active, accountability: all
# operation: item-create, collection: notes, permissions: $full
```

## 变体与关联

- 变体：`item-update`/`item-delete` 等写操作同样以系统身份执行，可篡改或删除数据。
- 变体：若 Flow 写入 `directus_users`、角色/策略等敏感集合，可能进一步扩大为账号或权限操纵；需管理员实际配置了对应操作才成立。
- 变体：同一触发入口的 `request` 操作形成匿名 SSRF，见关联卡；`exec` 操作在 isolated-vm 中执行任意 JS，但原文实测 `process.mainModule` 逃逸链失败，未打通进程执行，故不单独立卡。
- 关联：[[web-generic-ssrf-directus-anonymous-webhook-flow-request]]（同一触发入口的 request SSRF）、[[web-generic-ssrf-directus-cve-2026-61835-zero-ip-bypass]]、[[web-generic-ssrf-directus-private-network-denylist-gap]]。
- 边界：Flow 未激活/被锁定、UUID 未知、accountability 不允许匿名、操作 permissions 为 trigger/public 时，本场景不成立；新建 Flow 未重启容器也可能暂时无法触发。

## 检测与防御

- 检测：审计对 `/flows/trigger/<uuid>` 的匿名请求，尤其是返回新记录 id 或 `$last` 操作结果的请求；检查所有 webhook Flow 的 accountability 与 item-create permissions 配置；监控系统身份（accountability null）产生的数据库写入。
- 修复：给 Webhook Flow 前置网关做签名校验或 IP 白名单；把 accountability 从 `$all` 改为需要认证的 trigger 身份；把 item-create 的 permissions 从 `$full` 改为 `trigger`/`public` 并显式授权。
- 加固：限制 Flow/Operations 的创建与修改权限；定期审计活动日志中的 Flow 创建与触发记录；不要把 Flow UUID 当作唯一防线；升级并关注 Directus 对 Flow 触发认证的后续改动。
