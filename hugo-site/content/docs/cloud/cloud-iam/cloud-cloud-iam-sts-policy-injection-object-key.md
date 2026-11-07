---
id: cloud-cloud-iam-sts-policy-injection-object-key
title: STS Policy 注入：可控 Object Key 进入 AssumeRole 会话 Policy 导致临时凭据越权
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: sts-policy-injection-object-key
tags:
- cloud
- sts
- iam
- policy-injection
- json-injection
- assume-role
- oss
- cos
- object-storage
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V29
  verified_at: '2026-11-05T03:23:00+08:00'
  notes: 已通读全文并逐张查看50张图。核对：阿里云 aliyunVulnerablePolicy 的 fmt.Sprintf 把 fullPathFid 拼进 Resource；注入 x"],"Action":["oss:ListObjects"],"Resource":["acs:oss:*:*:* 后 STS 返回的 policy 含重复 Action/Resource（图26 lab 日志）；图14/15 基线仅单对象 PutObject，图23/24 注入后 OSS Browser 可列桶，图39-44 真实业务 SDK 可列/删/覆盖，图42 列出他人 key；腾讯云 qcs 模板新增 Statement、重复键被拒、图35-38 注入后 STS 与上传成功；ListObjects 需 Bucket 级 Resource 的边界与原文第八节一致。未验证点：PoC 未在本机执行；原文未给软件版本区间（应用侧代码模式），未设 versions。frontmatter 无 sources/source_url，来源 xz.aliyun.com/news/92599。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-sts-policy-injection-object-key/
draft: false
kb_aliases:
- STS Policy 注入
- Policy 注入越权
- AssumeRole 会话策略注入
- fullPathFid 注入
- fileKey 注入
- Object Key 注入
- 阿里云 STS 注入
- 腾讯云 COS STS 注入
- 临时凭据越权
---

## 一句话结论

后端把用户可控的文件名 / Object Key 用字符串拼接进 `AssumeRole` 的会话 Policy JSON 的 `Resource` 字段时，攻击者可用 `"`、`]`、`}` 闭合原字符串并注入 `Action` / `Resource`（阿里云走重复键覆盖，腾讯云走新增 Statement），使本应只允许写单个对象的 15 分钟 STS 临时凭据扩大到桶级列举、覆盖他人文件甚至角色权限上限。

## 原理

- **STS 的权限模型**：业务后端用长期身份或 RAM/CAM 角色调用 `AssumeRole`，签发短期临时凭证（AccessKeyId/Secret/SecurityToken）。最终权限是 `角色权限 ∩ 会话 Policy`；会话 Policy 只能在角色上限内做减法，不能突破角色本身。
- **输入进入 Policy 语法**：常见实现是把前端提交的文件名/目录拼进 Policy 模板，例如阿里云 `"Resource":["acs:oss:*:*:%s/%s"]`（bucket, fid），或腾讯云 `"resource":["qcs::cos:%s:uid/%s:%s/%s"]`（region, appID, bucket, fid）。这里的 `fid` 本应只是数据，却参与了 JSON 源码生成。
- **注入改变授权语义**：攻击者传入 `x"],"Action":["oss:ListObjects"],"Resource":["acs:oss:*:*:*`，闭合原 `Resource` 字符串与数组，再追加新的 `Action`/`Resource` 键。阿里云 STS 在本次验证中接受重复键并采用后者，于是同一条 Statement 的权限变成“任意动作、任意资源”（仍受角色上限约束）。腾讯云拒绝重复键，因此改为闭合第一条 Statement 并新增一条 `{"effect":"allow","action":["*"],"resource":["*"]}`。
- **为什么是控制流入侵**：与 SQL 注入同构——解释器从 SQL parser 换成 JSON parser + 云端授权；边界字符从单引号换成双引号、方括号、花括号。开发者眼里 `fid` 是字符串值，JSON 解析器看到的却是新的授权语句。
- **影响落点**：拿到放大后的 STS 后，可直接调用对象存储 SDK 进行 `ListObjects`（列桶）、`PutObject`（覆盖他人对象）、`DeleteObject`（清空桶）；若角色本身还挂了其他服务权限，`Action:"*"` + `Resource:"*"` 的请求集合会进一步逼近角色上限。
- **边界**：`ListObjects` 是 Bucket 级操作，需要 Bucket 级 `Resource`（如 `acs:oss:*:*:BUCKET`）且角色允许该 Action；仅把对象 `Resource` 写成 `BUCKET/*` 并不自动获得列桶权限。`Action:*`/`Resource:*` 也不会超越角色/CAM 上限与显式 Deny。

## 触发条件

- 业务提供“前端直传对象存储”接口：后端先签发 STS，再把临时凭证返回浏览器。
- 后端构造会话 Policy 时使用字符串拼接，且 `Resource` 中至少有一个片段来自用户可控值（文件名、Object Key、目录、日期前缀、扩展名等）。
- 接口未在服务端基于认证上下文重新生成 Object Key，也未校验用户提交的 Key 是否属于该用户/该前缀。
- RAM/CAM 角色的权限上限大于单对象：常见为整个 Bucket 读写，否则注入也只能在角色上限内生效。
- 攻击者能正常调用该接口获取一份 STS（通常只需登录业务系统）。

## 利用步骤

1. 找到签发 STS 的接口（如 `/api/v1/sts?fullPathFid=...`），确认文件名或 Object Key 参数可控，并观察返回的 `policy` 字段（部分实现会回显拼接后的 Policy）。
2. 先用正常值确认基线权限：STS 应只能对单个对象 PutObject/GetObject，ListObjects 返回 403。
3. 按目标云的模板构造闭合 payload：
   - 阿里云：`x"],"Action":["oss:ListObjects"],"Resource":["acs:oss:*:*:*`（利用重复键后者覆盖）。
   - 腾讯云：`uploads/alice/x.txt"]},{"effect":"allow","action":["*"],"resource":["*`（关闭第一条 Statement 并新增）。
4. 申请 STS，检查返回的 `policy` / `statementCount` 是否出现注入后的 Action/Resource。
5. 用返回的临时凭证调用对象存储 SDK：列桶、读取/覆盖他人对象、删除对象；以实际返回码确认权限扩大。
6. 影响评估以角色上限为界；若角色仅有 OSS/COS 权限，则影响集中在对象存储，若角色还挂了计算、密钥等权限，继续测试对应服务。

## PoC

阿里云模板与注入：

```go
// 脆弱写法：fid 直接拼接进 Policy JSON
fmt.Sprintf(`{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:GetObject","oss:PutObject"],"Resource":["acs:oss:*:*:%s/%s"]}]}`, bucket, fid)
```

```text
fid = x"],"Action":["oss:ListObjects"],"Resource":["acs:oss:*:*:*
```

拼接结果（Statement 数量仍为 1，重复键后者生效）：

```json
{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:GetObject","oss:PutObject"],"Resource":["acs:oss:*:*:BUCKET/x"],"Action":["oss:ListObjects"],"Resource":["acs:oss:*:*:*"]}]}
```

腾讯云模板与注入：

```go
fmt.Sprintf(`{"version":"2.0","statement":[{"effect":"allow","action":["cos:GetObject","cos:PutObject"],"resource":["qcs::cos:%s:uid/%s:%s/%s"]}]}`, region, appID, bucket, fid)
```

```text
fid = uploads/alice/x.txt"]},{"effect":"allow","action":["*"],"resource":["*
```

拼接结果为两条 Statement，第二条为 `action:["*"]`、`resource:["*"]`。

拿到 STS 后验证：

```python
# 以返回的临时三元组初始化客户端后
client.list_objects(bucket_name, max_keys=100)          # 列桶
client.put_object_from_file(bucket, victim_key, path)   # 覆盖他人对象
client.delete_object(bucket, victim_key)                # 删除对象
```

说明：以上为结构化复现，未在本会话执行；payload 的闭合后缀需按目标模板实际尾部调整。

## 变体与关联

- 变体（注入字段）：不只 `Resource`，文件名也可能进入 `Condition`、`Resource` 前缀、目录拼接；凡是用户值进入 Policy 源码的地方都可尝试。
- 变体（目标云）：字段大小写、Resource 格式、重复键处理不同。阿里云 `Version/Statement/Action/Resource` 且接受重复键；腾讯云 `version/statement/action/resource` 且拒绝重复键，需新增 Statement。AWS/GCP/Azure 的会话策略模型需单独验证，不能直接套用 payload。
- 变体（利用面）：列桶后可批量覆盖/删除；若同时控制完整 Object Key，可覆盖头像、报表、附件等已存在对象；未开版本控制时原对象不可恢复。
- 关联：[[cloud-cloud-iam-sts-policy-injection-filter-bypass-unicode]]（修复方改用字符串黑名单后，用双写/Unicode 转义二次绕过）。
- 边界：服务端基于认证上下文生成 Object Key、对 Key 做归属校验、角色上限本身仅限单对象、或会话 Policy 用结构化 JSON 序列化构造时，本链不成立。

## 检测与防御

- 检测：审计 `AssumeRole` 调用点的 Policy 构造，搜索 `fmt.Sprintf`/字符串模板拼接 Policy、`Resource` 中出现用户可控变量；重点关注文件名、目录、扩展名、Object Key 参数。
- 检测：STS 请求的 Policy 中出现多个 `Action`/`Resource` 键、`Statement` 数量异常、`Action:["*"]`、`Resource:["*"]`，或请求文件名包含 `"]`、`},{`、`\\u`、`*` 等 JSON 结构字符。
- 检测：同一账号短时间内 STS 权限从单对象扩大到桶级；对象存储侧出现跨用户前缀的 List/Put/Delete；大量对象被覆盖或删除。
- 防御（根因）：不要用字符串拼接生成 Policy。用 JSON 序列化/结构化策略构造器，把用户值作为字符串值交给序列化器转义；对象 Key 由服务端基于认证上下文生成，前端只提交业务无关的随机 ID。
- 防御（权限）：角色权限上限收敛到最小 Bucket/前缀；会话 Policy 只授予单对象 PutObject，不授予 List/Delete；开启 `x-oss-forbid-overwrite: true` 或版本控制，降低覆盖影响。
- 防御（校验）：对用户提交的 Key 做服务端规范化与归属校验（前缀、用户 ID、允许字符），拒绝包含 JSON 结构字符的异常值；STS 接口加审计与频控。
