---
id: web-java-deser-hessian-nacos-raft-abstractprocessor-entry
title: Nacos raft 请求触发 Hessian 反序列化：AbstractProcessor#handleRequest→JRaftServer#applyOperation→InstanceMetadataProcessor#onApply
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: nacos-raft-hessian-deserialization-entry
aliases:
- Nacos Hessian 反序列化
- Nacos raft 反序列化入口
- InstanceMetadataProcessor onApply
- JRaftServer applyOperation
- naming_instance_metadata
- Nacos 2.2.2 反序列化
tags:
- java
- hessian
- deserialization
- nacos
- raft
- sofa-jraft
- entry-point
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V454
  verified_at: '2026-11-10T02:21:02+08:00'
  notes: 已对照原文核对：图01 AbstractProcessor#handleRequest 的 findTupleByGroup/isLeader/execute、图03 multiRaftGroup（key=naming_instance_metadata，state=STATE_LEADER）、图04 applyOperation 的 Task 与 requestTypeFieldBytes{56,0}（ReadRequest 置1否则置2）/node.apply、图06 NacosStateMachine onApply 的 WriteRequest→processor.onApply 分派、图07/08 InstanceMetadataProcessor#onApply 首行 serializer.deserialize(request.getData().toByteArray(), processType) 及 FSMCallerImpl 调用栈，均支撑卡内链路；state_error、三节点默认三次尝试、替换全新 data 目录重启恢复与原文一致。原文未给出外部 raft 请求客户端与鉴权细节，卡内 confidence:medium 与‘无完整网络 PoC’标注合理。与既有 XXL-Job/Dubbo/HessianServlet 等入口卡产品不同，dedup 建卡前判 new。未在本机搭 Nacos 集群复跑。原文 2.2.2 仅为调试环境，非受影响版本区间，affected_versions 已 --clear。
---

## 一句话结论

Nacos 2.x 集群的 raft 请求在 leader 节点上经 `AbstractProcessor#handleRequest` → `findTupleByGroup` → `execute` → `JRaftServer#applyOperation` 封装成 `Task` 提交状态机，最终进入 `NacosStateMachine.onApply`；当消息是 `WriteRequest` 时交给 `InstanceMetadataProcessor#onApply`，后者直接 `serializer.deserialize(request.getData().toByteArray(), processType)`，于是 raft 请求里可控的 data 字节会进入 Hessian 反序列化——把恶意 Hessian 流（如 JDK-only 的 PKCS9Attributes/UIDefaults 链）作为 WriteRequest 数据发到 leader 的 raft 端口即可触发 gadget。

## 原理

- **入口链路**：`com.alibaba.nacos.core.distributed.raft.processor.AbstractProcessor#handleRequest(server, group, rpcCtx, message)` 先用 `findTupleByGroup(group)` 取该 group 的 `RaftGroupTuple`；只有 `tuple.getNode().isLeader()` 为真才 `execute(server, rpcCtx, message, tuple)`，否则返回 “Could not find leader”。调试可见 Nacos 的 multiRaftGroup 有 `naming_service_metadata`、`naming_instance_metadata` 等 group，示例节点状态为 `STATE_LEADER`。
- **提交到 raft**：`JRaftServer#applyOperation` 创建 `com.alipay.sofa.jraft.entity.Task`，在 data 前拼两个字节（`byte[]{56, 0}`，第二字节按消息类型改为 1/2），把原消息字节附在后面，`node.apply(task)`；sofa-jraft 完成日志复制/多数派提交后回调状态机的 `onApply`。
- **状态机分派**：`NacosStateMachine.onApply` 判断 `message instanceof WriteRequest` 时调用 `this.processor.onApply((WriteRequest) message)`，`ReadRequest` 则走 `onRequest`。
- **真正反序列化点**：`InstanceMetadataProcessor#onApply(WriteRequest request)` 第一行就是 `(MetadataOperation) this.serializer.deserialize(request.getData().toByteArray(), this.processType)`——data 字节被直接交给 Hessian 反序列化器，没有再校验类型/内容。
- **为什么能打通**：Hessian 反序列化器会把流中的类按 Map/Bean 还原并触发 `map.put`、`toString`、`equals` 等语义（见同目录入口/触发卡），而 raft 请求里的 data 完全由攻击者控制；只要请求能被 leader 接受并提交，就能在状态机线程中执行 gadget。
- **限制与代价**：必须命中 leader 且 group 存在；一次成功（或触发异常）的 POC 之后节点会进入 `state_error`，三节点集群默认最多尝试三次；恢复方式是替换为全新 data 目录并重启服务。文章未展示完整的外部请求构造/鉴权细节，raft 端口与集群 token 配置决定远程可达性。

## 触发条件

- 目标为 Nacos 2.x 集群（文章示例 2.2.2），raft 端口/集群通信对攻击者可达，且请求能被路由到对应 group 的 leader。
- group 名已知（如 `naming_instance_metadata`），消息类型可构造为 `WriteRequest`。
- Nacos/sofa-jraft 版本的反序列化路径与文章一致（入口类名/字段可能随版本变化）。
- 未启用会阻断该流的集群鉴权/网络隔离，或攻击者已能访问集群内网。

## 利用步骤

1. 先准备 Hessian gadget：可出网用 `PKCS9Attributes + UIDefaults/SwingLazyValue`（InitialContext.lookup）；不出网用 DumpBytecode 写 class + keytool 加载（见关联卡）。按 gadget 要求构造字节并在流首加 `0x43`（`'C'`）触发 `expect` 中的 `toString`。
2. 构造 raft `WriteRequest`：group 填 `naming_instance_metadata`（或 `naming_service_metadata`），data 为上面的 Hessian 流；`JRaftServer#applyOperation` 会在 data 前补 `[56, 0x02]`（非 ReadRequest）后提交。
3. 将请求发送到目标 leader 的 raft 服务端；在 `AbstractProcessor#handleRequest`/`InstanceMetadataProcessor#onApply` 下断可确认进入 `serializer.deserialize`。
4. 观察副作用：命令执行/回连（出网链）或临时目录出现 class 文件后加载（不出网链）。
5. 节点 `state_error` 后按文章方法替换 `data` 目录为全新数据并重启，才能再次测试；三节点集群留意尝试次数。
6. 验证 gadget 本体可先在本地 `Hessian2Input.readObject` 复现，再走 Nacos 入口。

## PoC

无完整可复制的网络 PoC（文章以调试/断点方式展示链路，未给出 raft 请求客户端与鉴权细节）。入口判定的最小依据：

```text
AbstractProcessor#handleRequest(group="naming_instance_metadata", message=WriteRequest)
  -> findTupleByGroup -> node.isLeader()
  -> execute -> JRaftServer#applyOperation
  -> Task.data = byte[]{56, 2} + request.getData()
  -> node.apply(task)
  -> NacosStateMachine.onApply(message instanceof WriteRequest)
  -> InstanceMetadataProcessor.onApply(request)
  -> serializer.deserialize(request.getData().toByteArray(), processType)
```

说明：Hessian gadget 的构造见关联的 JDK-only 与不出网链卡；本卡只记录 Nacos 入口与请求结构。未在本机搭集群复跑。

## 变体与关联

- [[web-java-deser-hessian-jdk-only-proxylazyvalue-chain]]：可出网的 PKCS9Attributes/UIDefaults/SwingLazyValue→InitialContext 链，与 Nacos 入口组合。
- [[web-java-deser-hessian-dumpbytecode-keytool-write-class-load-provider]]：不出网的 DumpBytecode 写 class + keytool 加载链。
- [[web-java-deser-hessian-deserialization-entry-map-put]]、[[web-java-deser-hessian2-protocol-error-tostring-trigger]]：Hessian 反序列化的通用触发语义（map.put / expect→toString）。
- [[web-java-deser-hessian-dubbo-provider-argument-deserialization-rce]]、[[web-java-deser-hessian-xxl-job-admin-api-entry]]、[[web-java-deser-hessian-hessianservlet-argument-header-entry]]：其他产品级 Hessian 入口，可对比暴露面与鉴权。
- 变体：group 选择 `naming_service_metadata`/其他 processor；消息类型 ReadRequest 走 `onRequest`（不一定是反序列化 sink）；不同 Nacos/sofa-jraft 版本类名与前置字节可能变化。
- 边界：非 leader 返回失败；集群鉴权/网络隔离阻断；版本升级改变入口；一次 POC 后节点 state_error 需恢复。

## 检测与防御

- 检测：对 raft 端口（默认 7848 等）的异常外部访问与超大/非预期 WriteRequest；Nacos 日志中 `handleRequest` 异常、`state_error`、状态机 onApply 反序列化报错；`naming_instance_metadata` 组出现非正常 data。
- 检测：Hessian 流特征（首字节 `0x43`、`com.caucho.hessian` 类名、PKCS9Attributes/UIDefaults/ProxyLazyValue 等类名）在集群通信中出现。
- 防御：不要将 raft 端口暴露到不可信网络；启用 Nacos 集群鉴权/Token 与网络 ACL；升级 Nacos 并关注官方安全公告；在反序列化层使用类允许列表（拒绝 PKCS9Attributes/UIDefaults/ProxyLazyValue 等）；限制集群节点出网与临时目录写权限。
- 响应：隔离受影响节点，保存 raft 日志与 data 目录作为证据，检查命令执行与横向移动，重建集群数据。
