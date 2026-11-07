---
id: cloud-cloud-iam-frontend-js-alibaba-ak-sk-cloud-takeover
title: 前端 JS 泄露阿里云长期 AK/SK：OSS 桶枚举、ECS 导入与云资产接管
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: frontend-js-alibaba-ak-sk-cloud-takeover
aliases:
- 阿里云 AK/SK 泄露
- LTAI SecretId
- 前端 JS 云密钥
- 转子 JS 扫描
- OSSKey 泄露
- 行云管家导入云主机
tags:
- cloud
- alibaba-cloud
- aliyun
- ak-sk
- oss
- ecs
- credential-leak
- frontend-js
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V207
  verified_at: '2026-11-07T01:59:44+08:00'
  notes: 已对照原文与全部61图核对：转子 JS 扫描输出阿里 OSSKey 泄露报告（图28-29）、JS 中 SecretKey/Bucket 片段（图60）、行云管家导入公有云主机（图61）与原文一致；LTAI/AKID 特征与原文相同。卡片为可操作场景而非情报资讯；与 cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof 系不同泄露源（前端 JS vs 未授权配置接口），不构成同一链。未验证点：原文未给出 AK/SK 原文与 ossutil/oss2 具体命令，PoC 为结构化复现；CF 提权仅一句带过；未在真实环境执行；未标注组件版本。
---

## 一句话结论

企业站点前端 JS（打包 bundle、接口文件、注释）常为“直传 OSS/调用云 API”而硬编码长期阿里云 AccessKeyId/Secret；用 JS 扫描工具（如转子）或正则从 JS 中提取 `LTAI...`/`SecretKey` 后，可用 OSS 工具/oss2 枚举并下载桶内文件，或把 AK/SK 导入行云管家等云管平台接管 ECS/OSS 等资产；若密钥权限过大（如 OSS 全桶读写、ECS 管理），可造成几十 GB 内部文件泄露和云主机控制。

## 原理

- **为什么前端会有 AK/SK**：为了让浏览器直接上传 OSS、调用云 API 或做签名，开发者有时把长期 AK/SK 写进前端 JS；这些文件对所有访问者可见，等于公开凭据。
- **阿里云 AK 特征**：AccessKeyId 常以 `LTAI` 开头，长度约 16–24；AccessKeySecret 约 30 位字母数字。正则可作为初筛：`LTAI[A-Za-z0-9]{12,20}`；腾讯云 SecretId 常以 `AKID` 开头：`AKID[A-Za-z0-9]{13,20}`。
- **权限验证**：拿到 AK/SK 后，用 OSS SDK/ossutil 调 `list_buckets`/`list_objects` 验证；若能列出桶并读取对象，说明密钥有效且至少拥有 OSS 读权限。若密钥绑定 RAM 用户且授予 ECS/OSS 管理策略，还可通过云管平台/API 管理 ECS 实例。
- **云管平台的作用**：行云管家等工具支持输入 AK/SK 导入公有云主机，批量纳管 ECS；OSS 浏览器/ossutil 可直接浏览桶；CF 面板类工具可在拿到主机权限后进一步提权。
- **为什么危害大**：长期 AK/SK 不像 STS 临时凭证会自动过期；一旦泄露，攻击者可持续访问云资源，且前端 JS 可能被缓存/存档，密钥长期有效。若 RAM 权限过宽（如 `AliyunOSSFullAccess`、`AliyunECSFullAccess`），可从“读文件”升级到“控制云主机”。

## 触发条件

- 目标前端 JS 可公开访问，且其中硬编码了有效 AK/SK（或通过注释、source map、接口文件泄露）。
- 密钥为长期凭证，未绑定 IP 白名单/MFA，RAM 权限包含 OSS 读写或 ECS 管理。
- 攻击者能访问阿里云 OSS/ECS 公网端点（或通过代理）。
- 目标未对异常 OSS/ECS API 调用做监控/告警。

## 利用步骤

1. 收集 JS：爬取目标站点、下载 bundle/接口文件，或用转子等工具对 URL 做 JS 扫描（`--scan=3` 提高深度）。
2. 提取凭据：在 JS/HTML/注释中正则搜索 `LTAI[A-Za-z0-9]{12,20}`、`SecretKey`、`accessKeyId`、`secretAccessKey`；记录 AccessKeyId/Secret。
3. 验证 OSS：用 ossutil/oss2 调 `list_buckets`；成功后 `list_objects` 枚举桶内对象，抽样下载确认权限与数据敏感性。
4. 接管云主机：把 AK/SK 导入行云管家/云厂商控制台/CLI，列出 ECS 实例；若权限允许，可重启/登录/重置密码/创建实例。
5. 扩大影响：检查 RAM 策略、OSS 桶 ACL、ECS 安全组与元数据；寻找更高权限角色/凭据；下载敏感文件作为影响证明。
6. 清理与报告：记录使用的 AK/SK、API 调用与下载清单；不要修改/删除目标数据。

## PoC

```bash
# 1) 从 JS 中粗筛阿里云 AK
curl -s https://target/app.js | grep -oE 'LTAI[A-Za-z0-9]{12,20}'

# 2) 用 ossutil 验证并枚举（示例）
ossutil config -e oss-cn-hangzhou.aliyuncs.com -i <AccessKeyId> -k <AccessKeySecret>
ossutil ls
ossutil ls oss://<bucket>/
ossutil cp oss://<bucket>/path/file.txt ./file.txt
```

```python
# 3) 用 oss2 验证 list_buckets / list_objects
import oss2
auth = oss2.Auth("<AccessKeyId>", "<AccessKeySecret>")
service = oss2.Service(auth, "https://oss-cn-hangzhou.aliyuncs.com")
for b in oss2.BucketIterator(service):
    print(b.name)
    bucket = oss2.Bucket(auth, "https://oss-cn-hangzhou.aliyuncs.com", b.name)
    for obj in oss2.ObjectIterator(bucket):
        print(" ", obj.key)
```

说明：PoC 为原文云接管流程的结构化复现，未在真实环境执行；原文用转子扫描 JS 发现 `SecretId`/`SecretKey`，用行云管家导入云主机、OSS 工具浏览桶，声称接管几十 GB 文件并取得 root 权限。具体权限取决于 RAM 策略，需在授权范围内验证。

## 变体与关联

- 变体（泄露位置）：前端 bundle、source map、接口文档、注释、GitHub、小程序包、配置接口；本文通过 JS 扫描发现。
- 变体（云厂商）：阿里云 `LTAI`、腾讯云 `AKID`、AWS `AKIA`、华为云等；验证工具不同但思路一致。
- 变体（利用）：OSS 桶读写/遍历、ECS 导入/重置密码、RAM 策略提权、容器镜像/函数计算、CF 面板提权。
- 关联：[[cloud-cloud-iam-oss-ak-sk-leak-bucket-pii-proof]]（配置接口泄露 OSS AK/SK 并用 list_objects 证明 PII 泄露）；[[pentest-recon-frontend-obfuscated-js-hardcoded-credentials]]（前端 JS 硬编码凭据）；[[cloud-cloud-iam-aws-access-key-leak-search-engine-takeover]]（AWS AK 泄露）；[[cloud-cloud-iam-tencent-temp-credential-cvm-password-reset]]（腾讯云临时凭证）。
- 边界：密钥已禁用/轮换、绑定 IP 白名单/仅 STS、RAM 权限仅最小只读、或前端只暴露无权限的公共上传签名时，接管范围受限。

## 检测与防御

- 检测：前端 JS 中出现 `LTAI`/`SecretKey`/`AccessKey` 等字符串；OSS/ECS API 出现异常 `list_buckets`、批量 `list_objects`、异地 IP 调用；云审计中出现非业务时间/非业务 IP 的 AK 使用。
- 防御：不要把长期 AK/SK 放进前端；改用 STS 临时凭证 + 最小权限 RAM 策略 + 桶/对象级授权；启用 IP 白名单、MFA、AK 轮换与泄露扫描；对 OSS/ECS 调用做审计告警；前端构建时做 secret 扫描（如 gitleaks/trufflehog）。
