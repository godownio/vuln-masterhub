---
id: cloud-cloud-iam-nacos-config-aliyun-ak-sk-oss-takeover
title: Nacos 配置详情泄露阿里云 OSS AK/SK：控制台/oss-browser 接管存储桶
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: nacos-config-aliyun-ak-sk-oss-takeover
tags:
- cloud
- aliyun
- oss
- accesskey
- nacos
- credential-leak
- config-center
- bucket
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V288
  verified_at: '2026-11-08T05:27:27+08:00'
  notes: 已对照全文与43图核对：图38 Nacos配置详情oss块含endpoint https://...:443、access-key LTAI...、secret-key ucoc...、bucket-name ar-...；图39匿名访问返回AccessDenied XML HostId=oss-cn-hangzhou.aliyuncs.com；图40 AccessKey登录页；图42 OSS Browser v1.17.0 AK登录；图43列出多个Bucket。已将'OSS Browser列出桶内日志文件'修正为'列出多个Bucket（原文另附桶内日志对象截图）'（日志截图实际来自MinIO Browser）。dedup仅与前端JS/未授权接口泄露AK-SK卡related（泄露源不同）；dup-scan与配置中心默认口令卡pair判related，并列保留（通用下游密钥 vs Nacos具体AK/SK→OSS接管）。图中密钥已打码，confidence=medium。未连接真实云。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-nacos-config-aliyun-ak-sk-oss-takeover/
draft: false
kb_aliases:
- Nacos 配置泄露 AK/SK
- 阿里云 OSS AK/SK 泄露
- LTAI AccessKey 泄露
- oss-browser 接管
- 配置中心明文凭据
- OSS 存储桶接管
---

## 一句话结论

Nacos 配置详情把阿里云 OSS 的 `endpoint`、`access-key`、`secret-key`、`bucket-name` 以明文保存；一旦攻击者能读取该配置（默认口令、未授权、配置导出或其它入口），即可用泄露的 `LTAI...` AccessKey 登录阿里云控制台或用 oss-browser/ossutil 连接，列举并下载桶内日志、备份与业务数据，接管对象存储。

## 原理

- 配置中心集中存放各环境的数据库、对象存储、消息队列等连接信息，应用启动时从这里拉取明文配置；因此 Nacos 配置详情天然是“凭据库”，一条配置就可能包含完整云账号凭据。
- OSS 的 AccessKeyId/Secret 是长期身份凭据。客户端每次调用 OSS API 都用它做签名，拿到 AK/SK 等于拥有对应 RAM 用户/主账号的权限，攻击者可从公网直接访问对象存储，无需进入目标内网。
- 阿里云 AccessKeyId 通常以 `LTAI` 开头，长度约 16–24 个字符；AccessKeySecret 约 30 位字母数字。腾讯云 SecretId 常以 `AKID` 开头，SecretKey 约 40 位。这些特征可用于在配置文本中快速定位凭据。
- 文章案例在 Nacos 配置内容中看到 `oss: endpoint: https://<...>:443`、`access-key: LTAI...`、`secret-key: ucoc...`、`bucket-name: ar-...`；随后用 AccessKey 登录云控制台，并用 OSS Browser（v1.17.0）填入 Endpoint、AccessKeyId、AccessKeySecret 后成功连接，列出多个 Bucket（原文另附桶内日志对象截图）。
- 匿名访问 OSS 桶时返回 `AccessDenied` XML 并带 `HostId`（如 `oss-cn-hangzhou.aliyuncs.com`）只能说明桶存在且拒绝匿名请求，不代表可利用；真正的接管来自泄露的 AK/SK 登录成功并能列举对象。
- 危害程度取决于该 AK/SK 所属 RAM 用户的权限：若拥有 OSS 列举/读取权限，可批量下载日志、备份、导出报表；若权限更宽（ECS 管理等），还可能进一步控制云主机。长期 AK/SK 不会自动过期，泄露后可持续访问。

## 触发条件

- Nacos 控制台/OpenAPI 可从攻击者网络访问（常见 8848 端口或经反代路径 `/nacos`），且存在默认口令、未授权访问、配置导出或其它可读取配置的缺陷。
- 配置详情中明文存放阿里云/腾讯云/其它对象存储的 AK/SK、Endpoint、Bucket 名称。
- 密钥仍有效，未绑定源 IP 白名单、MFA 或过期限制；所属账号至少具备列举/读取桶的权限。
- 对象存储 Endpoint 可从攻击者网络访问。

## 利用步骤

1. 定位 Nacos 入口（`/nacos`、8848 端口），在授权范围内尝试默认口令、已知未授权/鉴权绕过或配置导出入口；不要对非授权目标尝试。
2. 进入配置列表，逐一查看 `dataId`/`group` 的配置详情，搜索 `access-key`、`secret-key`、`accessKeyId`、`secretAccessKey`、`oss`、`endpoint`、`bucket`。
3. 根据 AccessKeyId 前缀判断云厂商：`LTAI` 为阿里云，`AKID` 为腾讯云；记录 Endpoint、Bucket、AK、SK。
4. 验证密钥：用阿里云控制台的 AccessKey 登录入口，或用 oss-browser/ossutil/oss2 配置 Endpoint、AK/SK 后调用 `list_buckets`。
5. 列举 Bucket 与对象，抽样下载日志/备份/导出文件确认数据敏感性；控制下载量，避免大规模拖取。
6. 若密钥权限包含 ECS 等其它服务，可进一步评估；仅记录证据并在授权范围内停止。

## PoC

```yaml
# Nacos 配置详情中的敏感片段（示意，值已脱敏）
oss:
  endpoint: https://oss-cn-hangzhou.aliyuncs.com:443
  access-key: LTAI****************
  secret-key: ******************************
  bucket-name: ar-********
  cacheControl: no-cache
```

```bash
# 使用 ossutil 验证并列举（授权环境）
ossutil config -e oss-cn-hangzhou.aliyuncs.com -i <AccessKeyId> -k <AccessKeySecret>
ossutil ls oss://
ossutil ls oss://<bucket-name>/ --limited-num 100
```

```text
# OSS Browser 图形化连接
Endpoint: https://oss-cn-hangzhou.aliyuncs.com
AccessKeyId: LTAI****************
AccessKeySecret: ******************************
```

## 变体与关联

- **前端 JS 泄露 AK/SK**：泄露源为打包 bundle 而非配置中心；已有 [[cloud-cloud-iam-frontend-js-alibaba-ak-sk-cloud-takeover]] 覆盖该场景。
- **未授权配置接口泄露 AK/SK**：泄露源为业务配置接口；已有 [[cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof]] 覆盖，并给出 oss2 枚举与 PII 取证方法。
- **Nacos 配置泄露 MinIO 凭据**：同类配置中心问题，但目标为 MinIO；参见 [[pentest-lateral-movement-nacos-ua-bypass-config-minio-credentials]]。
- **配置中心默认口令**：进入 Nacos 的前置入口之一；参见 [[pentest-lateral-movement-config-center-default-credential-downstream-key-leak]]。
- **临时凭证**：若泄露的是 STS 临时 AK/SK/SecurityToken，需检查过期时间与角色权限，利用窗口更短。

## 检测与防御

- 配置中心中的密钥使用 KMS/加密配置（如 Nacos 的加密插件、Jasypt）存储，避免明文 AK/SK；前端与日志中禁止输出。
- 为业务分配最小权限 RAM 用户：仅允许特定 Bucket/前缀的必需操作，禁止 `ListBuckets`、`*` 资源与 ECS 管理权限。
- 开启 AK/SK 轮换与泄露检测；禁用长期 AK 登录控制台，要求 MFA；绑定源 IP 白名单与网络边界。
- Nacos 加固：修改默认口令、关闭公网暴露、启用鉴权与 TLS、限制控制台访问来源、审计配置读取行为。
- 监控：云审计日志中的异常 `ListBuckets`/`ListObjects`/`GetObject`；同一 AK 从异常 IP 或非业务时段访问；Nacos 配置详情的高频遍历。
