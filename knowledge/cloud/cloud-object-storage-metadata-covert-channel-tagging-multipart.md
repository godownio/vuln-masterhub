---
id: cloud-object-storage-metadata-covert-channel-tagging-multipart
title: 对象存储可变元数据跨身份隐蔽信道：Object Tagging 与未完成 Multipart ListParts 分片长度编码
type: scenario
domain: cloud
path: cloud
technique: object-storage-metadata-covert-channel
aliases:
- MinIO Tagging 信道
- S3 对象标签跨身份传递
- ListParts 分片长度编码
- 未完成 Multipart 隐蔽信道
- 对象伴生状态信道
- 禁用 Tagging 后的对象元数据旁路
tags:
- cloud
- object-storage
- minio
- s3
- object-tagging
- multipart-upload
- listparts
- covert-channel
- iam
- tenant-isolation
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:50:00+08:00'
  notes: 已对照原文与全部 51 张图核对：MinIO 路由/Get/PutObjectTagging handler 源码行号、Tagging 403 AccessDenied、POST ?uploads 返回 UploadId、九片 Size=108/105/115/116... 编码 list_mail、ListParts 200、HEAD ETag 不变均与正文及截图一致；两套凭据非真实租户、已知 UploadId 的前提已如实标注；未复跑
---

## 一句话结论

对象存储的伴生可变状态（对象标签、未完成 Multipart 上传的分片元数据）可被同一对象上的另一个身份读取，从而在两个网络互不可达的客户端之间承载数据；即使 `PutObjectTagging`/`GetObjectTagging` 被拒绝，只要另一身份持有 `ListMultipartUploadParts` 权限并已知 `UploadId`，仍可通过分片 `Size` 编码读取信息，而正式对象正文与 `ETag` 保持不变。

## 原理

- S3/MinIO 用 `bucket + objectKey` 定位对象。普通下载读取对象正文；`?tagging` 请求进入独立的标签处理器，GET/PUT/DELETE 标签分别受 `GetObjectTagging`、`PutObjectTagging` 等权限控制。标签附着在对象上，修改标签不改变对象正文。
- MinIO 源码中，`cmd/api-router.go` 的路由把带 `Queries("tagging","")` 的 GET/PUT/DELETE 请求交给独立的 Tagging Handler；`cmd/object-handlers.go` 的 GET Handler 在 `authenticateRequest(..., GetObjectTaggingAction)` 后读取标签，PUT Handler 写入 `PutObjectTags`；`cmd/object-api-interface.go` 把 `PutObjectTags`、`GetObjectTags`、`DeleteObjectTags` 声明为独立对象操作。因此“能下载对象”与“能读写标签”是两套权限。
- Multipart 上传是第三种可变状态：`POST ?uploads` 创建未完成上传并返回 `UploadId`；`UploadPart` 写入分片；`ListParts` 在检查 `ListMultipartUploadPartsAction` 后返回 `PartNumber`、`Size`、`ETag` 等元数据。分片正文可以是无意义填充，而 `Size` 由上传者选择，按 ASCII 数值设置每个分片长度即可编码字符串；接收端按 `PartNumber` 顺序把 `Size` 转回字符。
- 两条路径都不需要 `CompleteMultipartUpload`，也不修改正式对象；`HEAD` 记录的 `ETag` 可用来证明正式制品未被覆盖。关键条件不是“绕过权限”，而是权限被分别授予：标签被拒绝不代表分片枚举被拒绝，`UploadId` 与标签 value 一样只是定位一条状态记录。

## 触发条件

- 两个身份都能访问同一对象存储端点与同一 `bucket + objectKey`；客户端之间可以没有直连网络。
- 标签路径：一侧具备 `PutObjectTagging`，另一侧具备 `GetObjectTagging`（或同一共享凭据同时具备两者）。
- 分片路径：A 具备 `CreateMultipartUpload`/`UploadPart`；B 具备 `ListMultipartUploadParts`（`ListParts`），并且知道 A 创建的 `UploadId`（通常需要额外信道传递或由测试人员提供，正常部署中 `UploadId` 是随机值）。
- 只读下载身份不应具备上述写标签、创建上传、列举分片的权限；若具备，即形成状态信道。

## 利用步骤

1. 对目标对象执行 `HEAD`，记录 `ETag` 作为正式对象基线。
2. 测试标签：A 发送 `PUT ?tagging` 写入无害值（如 `probe=should-deny`），B 发送 `GET ?tagging`；403 `AccessDenied` 表示标签路径受限，200 表示可用。
3. 若标签可用：A 写入键值（如 `chatgpt_test_ts=1789105063`），B 读取同一对象标签；对象正文不变。
4. 若标签被禁：A 对同一对象键发送 `POST ?uploads`，取得 `UploadId`；随后按待编码字符串的 ASCII 值逐个 `UploadPart`，例如 `list_mail` 对应 `108,105,115,116,95,109,97,105,108`，正文用 `X` 填充。
5. B 用自己的凭据携带 A 提供的 `UploadId` 调用 `GET ?uploadId=...`（`ListParts`），读取返回的 `PartNumber`/`Size`，按顺序把 `Size` 转成 ASCII。
6. 再次 `HEAD` 正式对象，确认 `ETag` 与基线一致；若一致，说明本轮未覆盖正式制品，信道只存在于未完成上传记录中。

## PoC

标签写入与读取（MinIO/S3 兼容接口，凭据省略）：

```http
PUT /pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz?tagging HTTP/1.1
Host: minio.internal
Content-Type: application/xml

<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <TagSet><Tag><Key>channel_canary</Key><Value>1789105063</Value></Tag></TagSet>
</Tagging>
```

```http
GET /pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz?tagging HTTP/1.1
Host: minio.internal
```

对照环境（MinIO）结果：标签写/读均返回 `403 AccessDenied`；正式对象 `HEAD` 返回 `200` 并记录 `ETag`。

未完成 Multipart 分片长度编码：

```http
POST /pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz?uploads HTTP/1.1
Host: minio.internal

PUT /pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz?partNumber=1&uploadId=<UploadId> HTTP/1.1
Host: minio.internal
Content-Length: 108

XXXXXXXXXXXXXXXX...（108 字节填充）

GET /pypi-cache/packages/requests/2.32.3/requests-2.32.3.tar.gz?uploadId=<UploadId> HTTP/1.1
Host: minio.internal
```

编码表：

```text
list_mail -> 108, 105, 115, 116, 95, 109, 97, 105, 108
```

`ListParts` 响应中可见 `PartNumber` 与 `Size`，例如前四项 `108/105/115/116`，按同样规则处理九个分片后还原 `list_mail`。

本地对照的边界：

- 两套凭据（`pypi-attacker` / `pypi-victim`）不等于两个真实租户；本轮验证的是“已知 `UploadId` 且策略允许 `ListParts`”时另一身份可读，不是 B 能独立发现 `UploadId`。
- 九个分片仅约百字节，远小于常规 Multipart 非末片 5 MiB 下限；本轮未调用 `CompleteMultipartUpload`，不能称为正常文件上传流程，也不代表生产信道吞吐量。
- `ETag` 前后一致只说明正式对象未被替换；未完成上传记录是否存在要单独看 `ListParts`。
- `403` 只表示 Tagging 被拒绝，不能推导所有对象元数据都不可访问。

## 变体与关联

- 标签可用时可直接把短状态放在标签值中；标签数量与长度受服务限制，长内容需多标签或多对象分片。
- 分片数量上限（S3 为 10000）允许一条上传承载较长消息；除 `Size` 外，`LastModified`、`ETag`、分片顺序等元数据也可被观察，但本文只验证了 `Size` 编码，不宜把其他字段写成已证实信道。
- 其他伴生状态：对象用户元数据、ACL、保留策略、版本信息等未被本文验证；审计时应一并检查其权限是否被误授给只读身份。
- 关联：制品仓库 Item Properties 跨租户信道（`ai-security-agent-security-sandbox-shared-artifactory-property-channel`）；Jupyter Contents 共享文件信道；`cloud-object-storage-bucket-acl-misconfig`（匿名读写）。
- 注意：本文实验是特定授权配置下的状态传递，不是 MinIO 默认配置的跨租户越权漏洞。

## 检测与防御

- 最小权限：只负责下载缓存的运行时仅授予 `GetObject`/`HeadObject`；显式拒绝 `PutObjectTagging`、`GetObjectTagging`、`CreateMultipartUpload`、`UploadPart`、`ListMultipartUploadParts`、`ListBucketMultipartUploads`、`CompleteMultipartUpload`、`AbortMultipartUpload`。
- 状态归属：`UploadOwner = UploadId -> tenant_id + session_id + bucket + objectKey`；`ListParts` 除权限检查外还要核验认证主体是否为上传发起者，不能仅凭知道 `UploadId` 就允许读取。
- 前缀与桶隔离：按租户、主体、桶、前缀授予 Multipart 与 Tagging 权限；共享依赖缓存前缀只读。
- 检测：标签读写 403 的同时出现成功的 `ListParts`；同一对象上大量微小分片；分片 `Size` 呈现 ASCII 可打印范围；创建后长期不 `Complete`/`Abort` 的上传；非发起者调用 `ListParts`；对象标签在共享缓存路径上的异常写入。
- 响应：清理未完成上传、撤销越权策略、轮换共享凭据、审计对象标签与分片元数据访问日志。
- 局限：原文未给出受影响版本（这是权限配置/隔离模型问题）；实验只验证状态可传递与可读取，没有验证真实租户间越权、禁止 `ListParts` 后仍可读取、或 `UploadId` 的独立发现方式。
