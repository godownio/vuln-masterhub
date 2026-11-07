---
id: cloud-k8s-k8s-apiserver-anonymous-access
title: K8s apiserver 匿名访问与 8080 不安全端口利用
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-apiserver-anonymous-access
tags:
- kubernetes
- apiserver
- unauthorized
- anonymous
- 6443
- 8080
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:42:39+08:00'
  notes: 已对照原文核对；6443/8080 探测、匿名 200/401/403 判定、system:anonymous 误绑定均与原文一致；未本地复现
url: /docs/cloud/k8s/cloud-k8s-k8s-apiserver-anonymous-access/
draft: false
kb_aliases:
- apiserver 未授权
- 6443 匿名访问
- 8080 insecure port
- system:anonymous
---

## 一句话结论

当 apiserver 的匿名用户 `system:anonymous` 被绑定到高权限角色，或旧集群仍开放 8080 HTTP 不安全端口时，外部攻击者无需任何凭证即可直接调用 Kubernetes API，读取资源甚至接管集群。

## 原理

- apiserver 默认监听 6443 HTTPS，正常情况下要求客户端证书或 Bearer Token 认证。
- 若管理员显式把 `system:anonymous` 或 `system:unauthenticated` 组绑定到高权限 Role/ClusterRole，匿名请求就会通过认证并以该角色授权。
- 旧版本 Kubernetes 的 8080 HTTP 端口默认无认证，直接暴露 API；即使只读，也能枚举命名空间、Pod、Service 等，为后续攻击提供情报。
- 匿名访问的判定看响应：200 表示匿名有权限且返回数据；401 表示需要认证；403 表示匿名被允许但权限不足，说明匿名用户存在，可继续尝试其他端点。
- 一旦匿名用户拥有写权限（如 create pods、get secrets、create clusterrolebindings），影响等同未授权接管集群。

## 触发条件

- apiserver 6443 从攻击者网络可达，且 `system:anonymous` 被绑定到有实际权限的角色。
- 或旧集群开放 8080 HTTP 端口且未限制来源。
- 或 apiserver 配置了 `--anonymous-auth=true`（默认）且 RBAC 误绑定。
- 目标 API 端点未被网络策略/防火墙隔离。

## 利用步骤

1. 探测 6443/8080，访问 `/api/v1/namespaces`、`/api`、`/version`。
2. 根据状态码判断：200 直接枚举；403 说明匿名存在但权限低，继续尝试 `/api/v1/pods`、`/api/v1/secrets`、`/apis/rbac.authorization.k8s.io/v1/clusterrolebindings`。
3. 若可读 Secret，按 Secret 窃取路径解码凭据；若可创建 Pod，尝试恶意 Pod 逃逸；若可创建 ClusterRoleBinding，直接绑定 cluster-admin。
4. 若 8080 开放，优先走 HTTP 端口，通常无需任何头。
5. 记录可访问的资源范围，评估是否能进一步提权。

```bash
# 6443 HTTPS 匿名探测
curl -k https://<apiserver-ip>:6443/api/v1/namespaces

# 8080 HTTP 不安全端口
curl http://<apiserver-ip>:8080/api/v1/namespaces

# 版本与 API 列表
curl -k https://<apiserver-ip>:6443/version
curl -k https://<apiserver-ip>:6443/api
```

## PoC

```bash
# 匿名列出命名空间（200 即存在匿名访问且有权限）
curl -sk -o /dev/null -w '%{http_code}\n' https://<apiserver-ip>:6443/api/v1/namespaces

# 匿名读取 Pod
curl -sk https://<apiserver-ip>:6443/api/v1/pods

# 匿名读取 Secret（若 RBAC 误绑定）
curl -sk https://<apiserver-ip>:6443/api/v1/secrets

# 8080 不安全端口
curl -s http://<apiserver-ip>:8080/api/v1/namespaces
```

## 变体与关联

- 403 不是终点：匿名用户可能存在但只被授予少量权限，逐个尝试资源与 verb（get/list/create）可能找到可用入口。
- 8080 端口在新版本已移除；老集群/托管环境仍可能残留，需单独探测。
- 匿名访问常与 Dashboard 未授权、kubelet 未授权同时出现，属于集群暴露面配置问题。
- 关联：`[[cloud-k8s-k8s-rbac-secret-read]]`、`[[cloud-k8s-k8s-rbac-clusterrolebinding-privesc]]`、`[[cloud-k8s-k8s-kubelet-unauth]]` 是匿名访问成功后的主要利用路径。

## 检测与防御

- 检测：apiserver 审计日志中 `system:anonymous` 的请求；外部 IP 对 6443/8080 的访问；匿名用户对 Secret/Pod/RBAC 资源的读写。
- 检测：`system:anonymous` 或 `system:unauthenticated` 出现在 RoleBinding/ClusterRoleBinding 的 subjects 中。
- 防御：不要给 `system:anonymous` 绑定任何有实际权限的角色；保持 `--anonymous-auth=false` 或仅允许健康检查端点。
- 防御：关闭 8080 不安全端口；6443 只对可信网络开放，使用防火墙/安全组/NetworkPolicy 限制来源。
- 加固：启用 API 审计并告警匿名访问；定期审计 RBAC 绑定；托管集群检查控制面端点是否公开。
