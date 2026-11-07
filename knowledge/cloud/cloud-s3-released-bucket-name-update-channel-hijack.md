---
id: cloud-s3-released-bucket-name-update-channel-hijack
title: S3 存储桶名称释放后劫持软件更新源与供应链
type: scenario
domain: cloud
path: cloud
technique: s3-released-bucket-name-update-channel-hijack
aliases:
- S3 桶名接管
- 失效 S3 更新源劫持
- bucket name squatting
- 云存储供应链劫持
- dangling S3 bucket takeover
tags:
- cloud
- aws
- s3
- supply-chain
- update-channel
- bucket-takeover
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:15:01+08:00'
  notes: 已通读全文并逐张核对61张图：图43 Quake domain:"s3.amazonaws.com" and body:"ListBucketResult" 命中17,371条；图45-49 公开桶创建/上传/对象URL与AccessDenied/带签名可读；图51-55 更新源被删桶释放后同名桶接管并下发 beacon 的示意，卡内原理、触发条件、curl/aws s3api 步骤与之一致。原文引用 watchTowr 案例但未给具体厂商 PoC，confidence medium 合理；无版本/CVE。frontmatter 无 sources/source_url；PoC 未在本机执行。
---

## 一句话结论

软件或设备把更新源硬编码为 `https://<name>.s3.<region>.amazonaws.com/...`，当 `<name>` 桶被删除后名称会被释放；攻击者在同区域注册同名桶并上传恶意更新文件，即可劫持所有仍在请求旧地址的客户端，形成供应链级攻击。

## 原理

- S3 桶名在 AWS 分区内全局唯一，但桶删除后名称会释放（除保留/特殊限制外），任何人都可重新创建同名桶。
- 大量软件、IoT 设备、VPN 客户端、杀毒软件、移动/桌面应用把更新检查地址直接写成 S3 桶端点，而不是自有域名；桶不存在时请求返回 `NoSuchBucket`，但客户端会持续重试。
- 攻击者注册同名桶后，原 URL 的解析结果就指向攻击者内容；由于客户端信任原域名（仍是 `*.amazonaws.com`），下载并执行更新时不会校验发布者，从而被植入后门。
- 与 CNAME 悬空接管的区别：这里不需要目标 DNS 记录仍存在，客户端直接请求桶端点；攻击面是“桶名引用”而不是“自定义域名”。
- 原文引用 watchTowr 的真实研究：通过分析大量对已删除桶的请求，定位到政府、军队、安全公司、交通、移动平台、银行等机构的更新源，可劫持 JS 更新、iOS/macOS 应用更新、SSLVPN 客户端、AV 引擎/签名库、CloudFormation 模板与 VM 镜像等。
- 该攻击可以规模化：AWS 单账号默认支持大量桶，攻击者可注册大量失效桶名并长期收集请求，按命中率筛选高价值目标。

## 触发条件

- 目标客户端/脚本请求的 S3 桶名已不存在（`NoSuchBucket`），且该名称可被重新注册。
- 更新内容没有代码签名/哈希校验，或校验公钥可被替换/绕过。
- 客户端会执行下载的可执行文件、脚本、配置或镜像。
- 攻击者知道失效桶名（来自日志、旧配置、公开代码、错误请求等）。

## 利用步骤

1. 收集目标软件/设备引用的 S3 地址与桶名（安装包、配置文件、前端 JS、日志、流量）。
2. 请求该地址，确认返回 `NoSuchBucket` 而非 `AccessDenied`。
3. 在相同区域创建同名桶；若名称被占用/保留则失败。
4. 按客户端期望的路径与文件名上传恶意更新（EXE/BAT/SH/JS/配置/镜像），必要时复现原目录结构。
5. 等待客户端按计划检查更新并下载执行；先用无害验证文件确认命中，再评估影响。
6. 记录证据并报告，协助恢复原桶或修改更新地址。

## PoC

检查桶是否存在：

```bash
curl -i https://<name>.s3.us-east-1.amazonaws.com/
# 返回 NoSuchBucket 表示名称已释放，是接管候选
```

创建同名桶并上传验证文件（示意，需攻击者自有账号与授权）：

```bash
aws s3api create-bucket --bucket <name> --region us-east-1
echo "takeover-proof" > verify.txt
aws s3 cp verify.txt s3://<name>/verify.txt
curl https://<name>.s3.us-east-1.amazonaws.com/verify.txt
```

原文未给出针对具体厂商的利用 PoC，仅引用 watchTowr 的真实案例；实际投放恶意更新需严格授权。

## 变体与关联

- 变体：劫持前端 JS 更新源注入恶意脚本；劫持移动/桌面应用更新下发后门版本；劫持 VPN/AV 更新致盲安全设备；替换 IaC 模板/VM 镜像。
- 变体：CNAME 指向已删除桶的自定义域名接管（机制不同，见关联卡）。
- 关联：[[cloud-object-storage-dangling-cname-bucket-takeover]]（DNS CNAME 悬空导致的自定义域名接管）。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]（桶 ACL 公开导致的数据泄露）。
- 边界：桶名被保留、客户端有强代码签名校验、更新地址已迁移、或客户端不再请求旧地址时，接管不成立。

## 检测与防御

- 检测：监控对不存在桶的持续请求（CloudTrail/S3 访问日志中的 `NoSuchBucket`）；发现同名桶被新账号创建；更新下载内容哈希/签名异常。
- 防御：删除桶前保留名称或使用不可预测名称；更新地址使用自有域名并校验所有权；对更新包做代码签名与哈希校验，客户端固定公钥。
- 加固：定期扫描代码/配置/镜像中的 S3 端点引用，清理失效地址；对关键更新通道做证书固定与透明日志监控；监控第三方对新注册桶名的使用。
