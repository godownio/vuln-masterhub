---
id: cloud-obs-bucket-policy-acl-conflict-anonymous-list
title: 华为云 OBS 桶策略与桶 ACL 冲突：ListBucket 关闭但 ACL 允许匿名仍可列对象
type: scenario
domain: cloud
path: cloud
technique: obs-bucket-policy-acl-conflict
aliases:
- OBS 策略冲突
- 桶策略与桶 ACL
- ListBucket 关闭仍可列
- 匿名 ACL 列举对象
- 华为云 OBS 越权列举
tags:
- cloud
- object-storage
- obs
- huawei-cloud
- bucket-policy
- acl
- access-control
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:09:12+08:00'
  notes: 对照原文与 img19-36：四种组合均实测——策略含ListBucket+ACL禁匿名可列（19-21）、策略含ListBucket+ACL许匿名可列（22-24）、策略无ListBucket+ACL许匿名仍可列（25-27，核心场景）、策略无ListBucket+ACL禁匿名不可列（28-30）；匿名访问两情形为策略含匿名+ACL禁可直接下载对象（31-33）、策略不含匿名+ACL禁返回AccessDenied（34-36）。卡片的 Allow 并集/显式 Deny 优先与原文权限矩阵（img02/03）一致。原文未标版本，affected_versions 为空正确。与通用公共读卡（cloud-object-storage-bucket-acl-misconfig）为不同根因（策略/ACL 冲突语义），dedup 报告 new，保留。
---

## 一句话结论

华为云 OBS 的有效权限是 IAM 策略、桶策略与 ACL 的 Allow 并集（显式 Deny 优先，未授权默认 Deny）：运维人员以为在桶策略里去掉 `ListBucket` 就能禁止匿名列举，但只要桶 ACL 仍给匿名用户授予桶读权限，匿名请求依旧能返回 `ListBucketResult`；同理，桶策略里 Allow 了匿名对象读时，即使 ACL 没有授权，对象也可直接下载。只有桶策略与 ACL 同时不授权（或显式 Deny）才真正拦截。

## 原理

- **权限模型**：OBS 权限由 IAM 权限、桶策略、对象 ACL、桶 ACL 共同决定；`Effect` 分 Allow/Deny，默认 Deny，显式 Deny 始终优先于 Allow；多条 Allow 叠加。
- **Allow 并集**：对某个动作（如 `ListBucket`），只要任一策略/ACL 给出 Allow 且没有任何显式 Deny，结果就是 Allow。因此“桶策略里没有 ListBucket”只代表桶策略这一路不授予，不代表 ACL 那一路不授予。
- **本文四个实测组合（列对象）**：
  1. 桶策略含 ListBucket + ACL 未给匿名权限 → 可列（策略 Allow 生效）；
  2. 桶策略含 ListBucket + ACL 给匿名桶读 → 可列；
  3. 桶策略不含 ListBucket + ACL 给匿名桶读 → 可列（ACL Allow 生效，最容易被忽略）；
  4. 桶策略不含 ListBucket + ACL 未给匿名权限 → 不可列（AccessDenied）。
- **匿名对象访问**：桶策略含匿名用户（Principal 为 Everyone）时，即使 ACL 未授权，对象也可直接下载；桶策略不含匿名用户且 ACL 未授权时返回 AccessDenied。说明桶策略 Allow 同样绕过 ACL 的空缺。
- **为什么容易误判**：控制台上桶策略与桶 ACL 分开配置，运维只改其中一处；加上“显式 Deny 优先”的直觉，容易以为 ACL 不授权就是拒绝，实际是默认 Deny 被策略 Allow 覆盖。
- **边界**：若任一策略显式 Deny（如 Block Public Access 或 Deny 语句），Allow 并集不再生效；不同厂商的优先级细节略有差异。

## 触发条件

- 目标 OBS 桶对匿名用户开放了任一 Allow（桶策略或 ACL）。
- 桶策略中 `ListBucket` 已移除但桶 ACL 仍保留匿名桶读权限（本文核心场景）。
- 对象可被匿名读取（策略含匿名 Principal 或 ACL 授权）。
- 攻击者能匿名访问桶域名。

## 利用步骤

1. 匿名请求桶根 `GET https://<bucket>.obs.<region>.myhuaweicloud.com/`，若返回 `ListBucketResult` 说明可列。
2. 若被拒，分别检查桶策略与桶 ACL：策略里是否有 `ListBucket`、`GetObject` 等 Allow 语句；ACL 里匿名用户/Everyone 是否有桶读、对象读权限。
3. 对“策略无 ListBucket 但 ACL 匿名授权”的桶，直接列举对象并下载敏感 Key。
4. 对“策略有匿名 Allow 但 ACL 无授权”的桶，直接请求对象 URL，验证是否可下载。
5. 组合测试四种策略/ACL 组合，确认是哪一路 Allow 生效，并评估影响面。

## PoC

```http
GET / HTTP/1.1
Host: al1ex.com.obs.cn-north-4.myhuaweicloud.com
```

```xml
<!-- 200 OK：策略或 ACL 任一路授予 ListBucket -->
<ListBucketResult xmlns="http://obs.myhwclouds.com/doc/2015-06-30/">
  <Name>al1ex.com</Name>
  <Contents><Key>al1ex.html</Key>...</Contents>
</ListBucketResult>
```

```text
# 策略：公共读写模板包含 ListBucket（或已移除）
# ACL：公共访问权限 - 匿名用户 - 桶访问权限 = 读取权限
# 关键结论：只移除桶策略的 ListBucket 不够，ACL 的匿名授权仍会放行；
# 需同时清除桶策略与桶 ACL 的匿名 Allow（或加显式 Deny）。
```

## 变体与关联

- 变体：对象 ACL 同样可单独给匿名读权限，策略未授权时对象仍可下载。
- 变体：显式 Deny 语句或“阻止公共访问”可覆盖 Allow 并集，是正确修复方式。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]（公共读/读写与 ListObject）、[[cloud-obs-bucket-acl-write-acp-anonymous-takeover]]（ACL 可写进一步接管）、[[cloud-obs-bucket-existence-enumeration-differential]]（发现桶）。
- 边界：不同云厂商的 ACL 与策略优先级实现不同，AWS S3 中 ACL 与桶策略也为并集语义，但 Deny 细节需按厂商文档确认。

## 检测与防御

- 检测：桶 ACL 中匿名用户/Everyone 存在任何桶读或对象读授权；桶策略中存在 Principal 为 `*`/Everyone 的 Allow 语句；匿名 ListBucket 成功日志。
- 防御：以“最小权限 + 显式 Deny”审计：同时检查 IAM、桶策略、桶 ACL、对象 ACL 四层；删除匿名 Allow；开启“阻止公共访问”与访问日志；配置变更后回归四种组合测试。
- 加固：默认私有桶；静态资源通过 CDN + 签名 URL 暴露；把 ListBucket 与 GetObject 权限分开治理。
