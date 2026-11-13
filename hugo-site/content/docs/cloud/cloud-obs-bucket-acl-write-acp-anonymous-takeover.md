---
id: cloud-obs-bucket-acl-write-acp-anonymous-takeover
title: 华为云 OBS 桶 ACL 对 Everyone 授予 WRITE_ACP：匿名 PUT /?acl 改成 FULL_CONTROL 后接管读权限
type: scenario
domain: cloud
path: cloud
technique: obs-bucket-acl-write-acp-anonymous-takeover
tags:
- cloud
- object-storage
- obs
- huawei-cloud
- acl
- write-acp
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:09:15+08:00'
  notes: 对照原文 img37-45：ACL 权限表（37-39）说明 WRITE_ACP 语义；img40 桶ACLs 匿名用户 ACL访问权限含读取|写入，img41 GET /?acl 显示 Everyone READ_ACP+WRITE_ACP，img42 匿名 PUT /?acl 提交 Everyone FULL_CONTROL 返回 200 OK，img43/44 复查 ACL 已为 FULL_CONTROL，img45 匿名列对象成功，完整接管链与卡片一致。已把 Content-Type 描述修正为原文抓包 text/html（application/xml 亦为 OBS ACL API 可接受格式），不再表述为两种均抓包。原文未标版本，affected_versions 为空正确。与 AWS S3 WRITE_ACP 卡（cloud-s3-write-acp-acl-takeover，不同厂商/API）非同一条链，dedup 报告 new，保留。
url: /docs/cloud/cloud-obs-bucket-acl-write-acp-anonymous-takeover/
draft: false
kb_aliases:
- OBS ACL 可写
- Everyone WRITE_ACP
- 匿名改写桶 ACL
- PUT ?acl 提权
- 华为云桶接管
---

## 一句话结论

当华为云 OBS 桶的 ACL 把 `READ_ACP` 和 `WRITE_ACP` 授予 `Everyone`（匿名用户）时，攻击者虽然未必能直接读对象，但可以匿名 `PUT /?acl` 提交新的 AccessControlPolicy，把 `Everyone` 的权限改成 `FULL_CONTROL`（成功返回 200），随后匿名列举桶对象并下载；本质是“写 ACL 权限”在 ACL 模型里等价于“可把自己提升为完全控制”。

## 原理

- **OBS ACL 权限位**：桶访问权限有读取（列对象）、对象读、写入；ACL 访问权限有读取（读 ACL）和写入（写 ACL）。`WRITE_ACP` 只表示能改 ACL，不含读数据权限。
- **ACL 改写即提权**：ACL 的修改者可以在新 ACL 里给同一被授权者（此处 Everyone）授予 `FULL_CONTROL`；OBS 接受匿名 ACL 写请求后，Everyone 立即拥有完全控制，等价于把“只能改 ACL”升级为“可读可写可再授权”。
- **实测链路**：`GET /?acl` 返回 `<Grant><Grantee><Canned>Everyone</Canned></Grantee><Permission>READ_ACP/WRITE_ACP</Permission></Grant>`；匿名 `PUT /?acl` 提交包含 `Everyone → FULL_CONTROL` 的 AccessControlPolicy，返回 `HTTP/1.1 200 OK`；再次 `GET /?acl` 确认 Everyone 已是 `FULL_CONTROL`；随后 `GET /` 返回 `ListBucketResult`，可下载对象。
- **为什么成立**：ACL 把“授权能力”和“资源访问能力”绑定在同一张表里，写 ACL 的权限天然可以写入对自身的完全授权；这是 ACL 模型的设计缺陷，而非单个 API 的问题。
- **边界**：若桶启用“阻止公共访问”或改为桶策略集中治理、不授予 Everyone `WRITE_ACP`，链路失效；对象 ACL 的 WRITE_ACP 只能接管对应对象，桶 ACL 的 WRITE_ACP 影响整桶。

## 触发条件

- 目标 OBS 桶 ACL 中 `Everyone`/匿名用户被授予 `WRITE_ACP`（常因“公共读写”或错误共享配置）。
- 桶未启用会拦截匿名 ACL 修改的“阻止公共访问”/组织策略。
- 攻击者可匿名访问桶域名并发送 `PUT /?acl`。

## 利用步骤

1. `GET https://<bucket>.obs.<region>.myhuaweicloud.com/?acl`，确认 Everyone 的 `WRITE_ACP`（通常同时有 `READ_ACP`）。
2. 构造 AccessControlPolicy：Owner 保持原桶主，`AccessControlList` 中加入 `Grantee=Canned Everyone, Permission=FULL_CONTROL`。
3. 匿名发送 `PUT https://<bucket>.obs.<region>.myhuaweicloud.com/?acl`，Content-Type 原文抓包为 `text/html`（OBS 的 ACL API 也接受 `application/xml`），观察 200。
4. 再次 `GET /?acl` 确认 Everyone 变为 `FULL_CONTROL`。
5. `GET /` 列举对象并下载敏感数据；记录 ACL 变更前后的 XML 作为证据。

## PoC

```http
GET /?acl HTTP/1.1
Host: al1ex.com.obs.cn-north-4.myhuaweicloud.com
```

```xml
<AccessControlPolicy>
  <Owner><ID>31f4edc737d94fd88a4a17e6e137278a</ID></Owner>
  <AccessControlList>
    <Grant><Grantee><Canned>Everyone</Canned></Grantee><Permission>READ_ACP</Permission></Grant>
    <Grant><Grantee><Canned>Everyone</Canned></Grantee><Permission>WRITE_ACP</Permission></Grant>
  </AccessControlList>
</AccessControlPolicy>
```

```http
PUT /?acl HTTP/1.1
Host: al1ex.com.obs.cn-north-4.myhuaweicloud.com
Content-Type: text/html

<AccessControlPolicy>
  <Owner><ID>31f4edc737d94fd88a4a17e6e137278a</ID></Owner>
  <AccessControlList>
    <Grant><Grantee><ID>31f4edc737d94fd88a4a17e6e137278a</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>
    <Grant><Grantee><Canned>Everyone</Canned></Grantee><Permission>FULL_CONTROL</Permission></Grant>
  </AccessControlList>
</AccessControlPolicy>
```

```text
# 预期：PUT 返回 200；GET /?acl 中 Everyone 变为 FULL_CONTROL；GET / 可列对象。
```

## 变体与关联

- 变体：仅 `READ_ACP` 只能读 ACL 结构，不能提权；必须 `WRITE_ACP`。
- 变体：对象 ACL 的 `WRITE_ACP` 可对单个对象做同样接管（`PUT /<object>?acl`）。
- 关联：[[cloud-s3-write-acp-acl-takeover]]（AWS S3 的 WRITE_ACP→FULL_CONTROL 同型手法）、[[cloud-object-storage-bucket-acl-misconfig]]（公共读写/ListObject）、[[cloud-obs-bucket-policy-acl-conflict-anonymous-list]]（策略/ACL 冲突导致列举）。
- 边界：BucketOwnerEnforced/阻止公共访问启用后 ACL 被禁用，本手法失效。

## 检测与防御

- 检测：桶/对象 ACL 中出现 `Everyone`/匿名 `WRITE_ACP` 或 `FULL_CONTROL`；匿名 `PUT ?acl` 请求；ACL 变更后紧接的 ListBucket/GetObject。
- 防御：禁止对匿名用户授予 `WRITE_ACP`；优先使用桶策略/IAM 而非 ACL；开启阻止公共访问与访问日志；对 ACL 变更告警并定期审计。
