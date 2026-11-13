---
id: cloud-obs-bucket-existence-enumeration-differential
title: 华为云 OBS 桶枚举：NoSuchBucket / AccessDenied / ListBucketResult 三态差分定位存在桶
type: scenario
domain: cloud
path: cloud
technique: obs-bucket-existence-enumeration-differential
aliases:
- OBS 桶枚举
- 华为云桶爆破
- NoSuchBucket 差分
- AccessDenied 判断桶存在
- bucket brute force obs
tags:
- cloud
- object-storage
- obs
- huawei-cloud
- enumeration
- recon
- bucket
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:08:53+08:00'
  notes: 对照原文与50张本地截图：img07 al2ex.com 桶根返回 Error/NoSuchBucket，img08 al1ex.com 桶根返回 ListBucketResult（含 Key 列表），img09 al1ex.com 返回 AccessDenied，三态差分与卡片一致；img01-06 为权限模型/URL构成/内网访问背景。卡片将状态码写为通常404/403（截图未显示状态码，均属合理默认），PoC 与原文 URL 结构一致。原文未标服务版本，affected_versions 为空正确。与 cloud-object-storage-bucket-acl-misconfig（命中后的公共读利用）、dangling-cname 卡（接管）不同链，dedup 报告 new，保留。
---

## 一句话结论

华为云 OBS 对桶根路径的匿名请求有三种可区分响应：桶不存在返回 `NoSuchBucket`，桶存在但匿名无列举权限返回 `AccessDenied`，桶存在且允许匿名列对象返回 `ListBucketResult` 对象列表；对候选桶名批量请求 `https://<bucket>.obs.<region>.myhuaweicloud.com/`，按响应码/错误码即可枚举出存在的桶，并顺带发现可匿名列对象的桶。

## 原理

- **URL 构成**：`Protocol://[BucketName.]Endpoint[:Port][/Object][?Param]`，公网访问形如 `http://al1ex.com.obs.cn-north-4.myhuaweicloud.com/myfolder/al1ex.html`；BucketName 在整个 OBS 中全局唯一，Endpoint 为区域域名（如 `obs.cn-north-4.myhuaweicloud.com`）。子域名式访问把桶名放在 DNS 前缀，直接 GET 桶根 `/` 就是列举请求。
- **三态差分**：
  - 桶不存在：XML `<Error><Code>NoSuchBucket</Code>...`（通常 404）；
  - 桶存在、匿名无 `ListBucket`：`<Code>AccessDenied</Code>`（403）；
  - 桶存在且有列举权限：`<ListBucketResult>` 返回 Key 列表（200）。
- **为什么能枚举**：响应体错误码把“存在/不存在”与“有无权限”分开暴露，攻击者不需要任何凭据即可区分；桶名常来自公司名/产品名/域名前缀/拼音，字典爆破命中率高。
- **边界**：部分区域/SDK 端点可能对不存在桶返回通用错误或重定向；开启“阻止公共访问”不改变 `NoSuchBucket` 与 `AccessDenied` 的差异；命中后仍需判断可读对象范围与是否有敏感数据。

## 触发条件

- 目标使用华为云 OBS，桶可通过公网域名访问（`*.obs.<region>.myhuaweicloud.com`）。
- 攻击者可对候选桶名发起未认证请求（无 WAF 速率限制或可绕过）。
- 桶名有可猜测规律（企业名、域名、产品名、环境后缀）。

## 利用步骤

1. 收集候选桶名：公司/产品/域名/拼音 + 常见后缀（`-prod`、`-test`、`-static`、`-assets`、`-backup` 等）。
2. 对每个候选请求 `GET https://<bucket>.obs.<region>.myhuaweicloud.com/`，记录 HTTP 状态与 XML 中的 `Code`。
3. 按三态分类：`NoSuchBucket`=不存在；`AccessDenied`=存在；`ListBucketResult`=存在且可列对象。
4. 对可列对象的桶解析 `<Key>` 批量下载，优先找备份、日志、配置、source map、用户数据。
5. 对仅 `AccessDenied` 的桶继续测试对象 ACL、防盗链、策略条件等（见关联卡）。

## PoC

```http
GET / HTTP/1.1
Host: al1ex.com.obs.cn-north-4.myhuaweicloud.com
```

```text
# 不存在：404 / <Code>NoSuchBucket</Code>
# 存在但不可列：403 / <Code>AccessDenied</Code>
# 存在且可列：200 / <ListBucketResult><Contents><Key>...
```

```python
import requests
for name in candidates:
    url = f"https://{name}.obs.cn-north-4.myhuaweicloud.com/"
    r = requests.get(url, timeout=5)
    tag = "LIST" if "<ListBucketResult" in r.text else ("EXISTS" if "AccessDenied" in r.text else ("NO" if "NoSuchBucket" in r.text else "?"))
    print(name, r.status_code, tag)
```

## 变体与关联

- 变体：内网场景通过 VPC 内网 DNS 解析 OBS 域名访问，枚举逻辑相同但需先进入内网。
- 变体：其他厂商同型差分（AWS S3 `NoSuchBucket`/`AccessDenied`、阿里云 OSS `NoSuchBucket`/`AccessDenied`），错误码字段略有差异。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]（命中后公共读/读写利用）、[[cloud-obs-bucket-policy-acl-conflict-anonymous-list]]（存在但不可列时检查策略/ACL 冲突）、[[cloud-cloud-iam-s3-anonymous-enum-export-xml-privilege-escalation]]（S3 匿名枚举的同类手法）。
- 边界：枚举结果受 endpoint/区域影响；桶名全局唯一但仅在同一分区内保证解析到目标区域。

## 检测与防御

- 检测：OBS 访问日志/网关日志中出现大量 `NoSuchBucket` 请求、同一来源对多个 `*.obs.*.myhuaweicloud.com` 子域的探测、403/404 交替的枚举特征。
- 防御：桶名使用不可预测随机串（但不能替代权限控制）；开启访问日志与异常告警；对匿名请求限速；敏感桶不暴露公网域名。
