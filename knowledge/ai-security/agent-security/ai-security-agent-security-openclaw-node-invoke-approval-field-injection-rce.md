---
id: ai-security-agent-security-openclaw-node-invoke-approval-field-injection-rce
title: OpenClaw Gateway node.invoke 审批字段注入：params.approvalDecision 绕过 system.run 审批执行任意命令（CVE-2026-28466）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: openclaw-node-invoke-approval-field-injection-rce
aliases:
- CVE-2026-28466
- OpenClaw RCE
- node.invoke 审批绕过
- approvalDecision 注入
- system.run 绕过审批
- Gateway 内部审批字段
- 审批状态伪造
tags:
- ai-security
- agent-security
- openclaw
- gateway
- node-invoke
- approval-bypass
- system-run
- rce
- cve-2026-28466
cve:
- CVE-2026-28466
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: < 2026.2.14
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:38:21+08:00'
  notes: 已对照原文与8张图核对：node.invoke 的 params 为 unknown 原样透传、coerceNodeInvokePayload 仅做类型归一化、handleInvoke 直接读取 params.approvalDecision，注入 allow-once/allow-always 绕过 system.run 审批；CVE-2026-28466、受影响 v2026.2.13/修复 >= 2026.2.14 与原文一致。原文未给出完整 RPC 报文，卡内 PoC 为按字段流转构造的示意；未实机复现。
---

## 一句话结论

OpenClaw Gateway 的 `node.invoke` 处理器把客户端传入的 `params` 当作 `unknown` 原样转发给 Node，Node 端 `coerceNodeInvokePayload` 只校验 `id/nodeId/command/paramsJSON` 的类型、不做内部字段剥离；`handleInvoke` 直接从 `params.approvalDecision` 读取审批结果，于是持有合法网关凭据的攻击者在 `params` 里注入 `approvalDecision: "allow-always"`（或 `"allow-once"`）即可让 `system.run` 跳过用户审批，在 Node 主机上执行任意系统命令。

## 原理

- **入口不限制字段**：`src/gateway/server-methods/nodes.ts` 的 `node.invoke` handler 只调用 `validateNodeInvokeParams(params)` 校验整体格式，随后把 `params` 断言为 `{ nodeId: string; command: string; params?: unknown; timeoutMs?: number; idempotencyKey: string }`。`params` 的类型是 `unknown`，可携带任意嵌套字段。
- **原样转发**：handler 调用 `context.nodeRegistry.invoke({ nodeId, command, params: p.params, timeoutMs, idempotencyKey })`，没有对 `p.params` 做白名单、剥离或重写。
- **序列化不净化**：`src/gateway/node-registry.ts` 的 `invoke()` 中，若 `"params" in params && params.params !== undefined`，则 `paramsJSON = JSON.stringify(params.params)`，否则为 null；随后构造 `{ id, nodeId, command, paramsJSON, timeoutMs, idempotencyKey }`，通过 `sendEventToSession(node, "node.invoke.request", payload)` 发给目标 Node。JSON 序列化保留所有字段，包括 `approvalDecision`。
- **Node 端只做类型归一化**：`src/node-host/runner.ts` 的 `onEvent` 只处理 `node.invoke.request`，调用 `coerceNodeInvokePayload(evt.payload)`；该方法要求 payload 是对象，提取 `id`/`nodeId`/`command` 并 `trim()`，要求非空；`paramsJSON` 优先取字符串，否则若 `obj.params !== undefined` 则 `JSON.stringify(obj.params)`；最后返回标准化 payload。整个过程没有针对任何字段的剥离或清洗。
- **审批值来自客户端**：`src/node-host/invoke.ts` 的 `handleInvoke()` 在执行审批逻辑前读取：
  ```ts
  const approvalDecision: "allow-once" | "allow-always" | null =
    params.approvalDecision === "allow-once" || params.approvalDecision === "allow-always"
      ? params.approvalDecision
      : null;
  ```
  正常设计里该值由本地审批弹窗在用户点击后写入：`null` 表示等待审批，`allow-once` 允许一次，`allow-always` 始终允许。由于这里直接信任来自 `params` 的同名字段，攻击者可伪造“用户已同意”。
- **审批被绕过**：Node 把伪造的 `approvalDecision` 带进 `ExecHostRequest`，`system.run` 走已批准分支，不再弹出确认，直接执行 `command`。攻击者因此可以在开发者工作站、CI runner 等 Node 主机上执行任意命令。
- **前提是网关凭据**：漏洞描述明确是“具有合法网关凭据的攻击者”。这不是未认证 RCE；它的价值在于把“已认证但只能发任务”的权限提升为“在 Node 上任意命令执行”，并绕过本应存在的人工审批边界。

## 触发条件

- OpenClaw 版本 <= 2026.2.13（原文分析 v2026.2.13，修复版本 2026.2.14）；
- 攻击者持有合法 Gateway 凭据，能调用 `node.invoke` RPC；
- 目标 Node 已连接 Gateway，且 Node 上 `system.run`/exec host 的审批逻辑使用 `params.approvalDecision` 判定（原文为 macOS app exec 路径）；
- Gateway 未做额外参数过滤/审批服务端校验。

## 利用步骤

1. 获取/确认一个可用的 Gateway 凭据，连接 Gateway RPC。
2. 调用 `node.invoke`，`command` 设为 `system.run`（或等价的高危执行命令），`nodeId` 设为目标 Node。
3. 在 `params` 中注入内部审批字段 `approvalDecision: "allow-always"`（或 `"allow-once"`），并填入 `system.run` 所需命令参数。
4. Gateway 将该 `params` JSON 序列化后经 `node.invoke.request` 转发给 Node。
5. Node 的 `coerceNodeInvokePayload` 保留该字段，`handleInvoke` 读取后认为审批已通过，直接执行命令。
6. 在 Node 主机上获得命令执行；可进一步反弹 shell、写入持久化或读取凭据。

## PoC

```json
{
  "method": "node.invoke",
  "params": {
    "nodeId": "<target-node-id>",
    "command": "system.run",
    "timeoutMs": 10000,
    "idempotencyKey": "<uuid>",
    "params": {
      "command": "<要执行的系统命令>",
      "approvalDecision": "allow-always"
    }
  }
}
```

> 原文未给出完整 `system.run` 参数 schema 与实际 RPC 报文，上面的请求按文章展示的字段流转构造，`params.command` 的具体字段名需按目标版本的 `system.run` schema 调整。

关键代码路径：

```text
Gateway: node.invoke(params)
  -> validateNodeInvokeParams(params)          // 只校验格式
  -> nodeRegistry.invoke({ ..., params: p.params })
  -> JSON.stringify(params.params)             // approvalDecision 被保留
  -> sendEventToSession("node.invoke.request", payload)

Node: onEvent("node.invoke.request")
  -> coerceNodeInvokePayload(payload)           // 只做类型归一化
  -> handleInvoke(payload, ...)
  -> params.approvalDecision === "allow-always" // 攻击者可控
  -> system.run 直接执行，无审批弹窗
```

## 变体与关联

- 注入位置可换成 `paramsJSON` 字符串（`coerceNodeInvokePayload` 会直接采用字符串形式的 `paramsJSON`），同样可携带 `approvalDecision`。
- 同类“内部字段由客户端提供”的问题不限于审批：凡是把 `internal`/`approval`/`trusted` 等控制字段放在请求参数里、由服务端直接信任的 Agent/RPC 设计，都可能被伪造。
- 关联 [[ai-security-agent-security-hitl-capability-dangerous-tool-guard]]：从防御侧看，HITL 门禁必须由服务端/本地可信通道写入授权标记，不能接受客户端自报的审批结果；本卡是其反面案例。
- 关联 [[ai-security-agent-security-capability-scope-subsumption-bypass]]：都是 Agent 权限边界校验缺失导致的越权，但本卡是审批状态伪造而非路径范围计算错误。
- 边界：需要合法 Gateway 凭据；若 Gateway 在 2026.2.14+ 已剥离/校验内部字段，或审批决定不来自请求参数，则失效。

## 检测与防御

- **升级**：OpenClaw >= 2026.2.14（原文修复建议）。
- **服务端剥离内部字段**：Gateway 在转发前对 `params` 做白名单，删除 `approvalDecision`、`approved`、`trusted` 等内部审批字段；Node 端也不得从请求参数读取审批状态。
- **审批状态不可由客户端提供**：审批结果应保存在 Node 本地可信状态（弹窗回调、带 nonce 的会话、签名令牌）中，并与具体命令、节点、会话绑定；客户端提交的“allow-always”一律视为无效。
- **最小权限与网络隔离**：Gateway 不暴露公网；凭据按最小权限签发，限制可调用的 node/command；高危 `system.run` 需要服务端二次校验。
- **检测**：审计 `node.invoke` 请求中出现 `approvalDecision` 等内部字段；监控同一凭据短时间内对多个 Node 执行 `system.run`；对无审批弹窗记录却执行高危命令的情况告警。
